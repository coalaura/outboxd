package deliver

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/coalaura/outboxd/internal/queue"
)

func (d *Deliverer) send(ctx context.Context, envelope *queue.Envelope, candidate mxCandidate, body int, indexes []int) (bool, error) {
	trace := d.newDebugTrace()

	host := candidate.host

	messageSize := envelope.MessageSize(indexes[0])
	eightBit := envelope.MessageEightBit(indexes[0])

	client, err := d.connect(ctx, candidate, !envelope.SMTPUTF8 && !eightBit)

	trace.mark("connect")

	if err != nil {
		return false, err
	}

	defer client.Close()

	if envelope.SMTPUTF8 {
		supported, _ := client.Extension("SMTPUTF8")
		if !supported {
			_ = client.Quit()

			return false, errSMTPUTF8Unsupported
		}
	}

	if eightBit {
		supported, _ := client.Extension("8BITMIME")
		if !supported {
			_ = client.Quit()

			return false, err8BITMIMEUnsupported
		}
	}

	err = client.Mail(envelope.Sender, MailOpts{
		Size:     messageSize,
		UTF8:     envelope.SMTPUTF8,
		EightBit: eightBit,
	})

	trace.mark("mail")

	if err != nil {
		if errors.Is(err, errSMTPUTF8Unsupported) || errors.Is(err, err8BITMIMEUnsupported) {
			_ = client.Quit()

			return false, err
		}

		if permanent(err) {
			d.rejectSMTP(envelope, indexes, err)

			return true, nil
		}

		return false, err
	}

	accepted := make([]int, 0, len(indexes))
	temporary := make([]string, 0, len(indexes))
	pendingIndexes := make([]int, 0, len(indexes))
	pendingAddresses := make([]string, 0, len(indexes))

	for _, index := range indexes {
		recipient := &envelope.Recipients[index]
		if recipient.Status != queue.StatusPending {
			continue
		}

		pendingIndexes = append(pendingIndexes, index)
		pendingAddresses = append(pendingAddresses, recipient.Address)
	}

	results := make([]error, 0, len(pendingIndexes))

	var batchErr error

	pipelining, _ := client.Extension("PIPELINING")
	if pipelining && len(pendingIndexes) > 1 {
		results, batchErr = client.RcptBatch(pendingAddresses)
	} else {
		for _, address := range pendingAddresses {
			results = append(results, client.Rcpt(address))
		}
	}

	for resultIndex, result := range results {
		index := pendingIndexes[resultIndex]
		recipient := &envelope.Recipients[index]

		if result == nil {
			accepted = append(accepted, index)

			continue
		}

		if permanent(result) {
			d.rejectSMTP(envelope, []int{index}, result)

			continue
		}

		recipient.Detail = describe(result)

		temporary = append(temporary, fmt.Sprintf("%s: %s", recipient.Address, recipient.Detail))
	}

	trace.mark("rcpt")

	if batchErr != nil {
		return false, batchErr
	}

	if len(accepted) == 0 {
		_ = client.Quit()

		if len(temporary) > 0 {
			return false, fmt.Errorf("temporary RCPT failures: %s", strings.Join(temporary, "; "))
		}

		return true, nil
	}

	openReader := d.reader
	if openReader == nil {
		openReader = func(id string, body int) (io.ReadCloser, error) {
			return d.queue.ReaderVariant(id, body)
		}
	}

	reader, err := openReader(envelope.ID, body)

	trace.mark("body_open")

	if err != nil {
		return false, err
	}

	defer reader.Close()

	dw, err := client.Data()

	trace.mark("data")

	if err != nil {
		if permanent(err) {
			d.rejectSMTP(envelope, accepted, err)

			return true, nil
		}

		return false, err
	}

	written, err := io.Copy(dw, io.LimitReader(reader, messageSize+1))

	trace.mark("body_write")

	if err != nil {
		// Closing DotWriter emits the DATA terminator. Abort the transport instead.
		_ = client.Close()

		return false, err
	}

	if written != messageSize {
		// Closing DotWriter emits the DATA terminator, so body integrity failures
		// must abort the transport directly.
		_ = client.Close()

		if written < messageSize {
			return false, fmt.Errorf("%w: got %d, want %d", errBodyTooShort, written, messageSize)
		}

		return false, fmt.Errorf("%w: got at least %d, want %d", errBodyTooLong, written, messageSize)
	}

	err = dw.Close()

	trace.mark("data_reply")

	if err != nil {
		if permanent(err) {
			d.rejectSMTP(envelope, accepted, err)

			return true, nil
		}

		return false, err
	}

	reply := dw.Reply()

	for _, index := range accepted {
		recipient := &envelope.Recipients[index]
		recipient.Status = queue.StatusSent
		recipient.Detail = normalizeDiagnostic(fmt.Sprintf("%s: %s", host, reply))
	}

	_ = client.Quit()

	trace.mark("quit")

	d.debugf("delivery %s SMTP transaction with %s completed: recipients=%d bytes=%d %s\n", envelope.ID, host, len(indexes), written, trace)

	if len(temporary) > 0 {
		return false, fmt.Errorf("temporary RCPT failures: %s", strings.Join(temporary, "; "))
	}

	return true, nil
}
