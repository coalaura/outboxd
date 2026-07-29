package queue

import (
	"container/heap"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/coalaura/outboxd/internal/disk"
)

// Status is the delivery state of a single recipient.
type Status string

const (
	StatusPending Status = "pending"
	StatusSent    Status = "sent"
	StatusFailed  Status = "failed"
)

// Recipient is one envelope recipient and its delivery outcome.
type Recipient struct {
	Address string `json:"address"`
	Domain  string `json:"domain"`
	Status  Status `json:"status"`
	Detail  string `json:"detail,omitempty"`
}

// Envelope is the queued metadata for one accepted message.
type Envelope struct {
	ID          string      `json:"id"`
	Username    string      `json:"username"`
	Sender      string      `json:"sender"`
	Recipients  []Recipient `json:"recipients"`
	Size        int64       `json:"size"`
	Created     time.Time   `json:"created"`
	Attempts    int         `json:"attempts"`
	NextAttempt time.Time   `json:"next_attempt"`
	LastError   string      `json:"last_error,omitempty"`

	index int
}

// Queue is a durable, crash-safe spool of messages awaiting delivery.
type Queue struct {
	directory string
	dead      string

	mu      sync.Mutex
	pending schedule
	notify  chan struct{}
}

// Pending reports how many recipients still need a delivery attempt.
func (e *Envelope) Pending() int {
	var count int

	for i := range e.Recipients {
		if e.Recipients[i].Status == StatusPending {
			count++
		}
	}

	return count
}

// Len returns the number of messages waiting for delivery.
func (q *Queue) Len() int {
	q.mu.Lock()
	defer q.mu.Unlock()

	return q.pending.Len()
}

// Add durably stores a message and schedules it for immediate delivery.
func (q *Queue) Add(envelope *Envelope, data []byte) error {
	envelope.Size = int64(len(data))

	err := disk.Write(q.message(envelope.ID), data, 0600)
	if err != nil {
		return err
	}

	err = q.store(envelope)
	if err != nil {
		os.Remove(q.message(envelope.ID))

		return err
	}

	q.schedule(envelope)

	return nil
}

// Next blocks until a message is due for delivery or ctx is cancelled.
func (q *Queue) Next(ctx context.Context) (*Envelope, error) {
	timer := time.NewTimer(time.Hour)
	defer timer.Stop()

	for {
		q.mu.Lock()

		wait := time.Hour

		if q.pending.Len() > 0 {
			envelope := q.pending[0]

			delay := time.Until(envelope.NextAttempt)
			if delay <= 0 {
				heap.Pop(&q.pending)

				q.mu.Unlock()

				return envelope, nil
			}

			wait = delay
		}

		q.mu.Unlock()

		timer.Stop()
		timer.Reset(wait)

		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-q.notify:
		case <-timer.C:
		}
	}
}

// Retry persists the updated envelope and reschedules it.
func (q *Queue) Retry(envelope *Envelope) error {
	err := q.store(envelope)
	if err != nil {
		return err
	}

	q.schedule(envelope)

	return nil
}

// Finish removes a fully delivered message from the spool.
func (q *Queue) Finish(envelope *Envelope) error {
	return errors.Join(
		os.Remove(q.metadata(envelope.ID)),
		os.Remove(q.message(envelope.ID)),
		disk.Sync(q.directory),
	)
}

// Bury moves an undeliverable message into the dead-letter directory.
func (q *Queue) Bury(envelope *Envelope) error {
	err := q.store(envelope)
	if err != nil {
		return err
	}

	return errors.Join(
		os.Rename(q.metadata(envelope.ID), filepath.Join(q.dead, envelope.ID+".json")),
		os.Rename(q.message(envelope.ID), filepath.Join(q.dead, envelope.ID+".eml")),
		disk.Sync(q.directory),
		disk.Sync(q.dead),
	)
}

// Reader opens the stored message for streaming to a destination.
func (q *Queue) Reader(id string) (*os.File, error) {
	return os.OpenFile(q.message(id), os.O_RDONLY, 0)
}

func (q *Queue) schedule(envelope *Envelope) {
	q.mu.Lock()
	heap.Push(&q.pending, envelope)
	q.mu.Unlock()

	select {
	case q.notify <- struct{}{}:
	default:
	}
}

func (q *Queue) store(envelope *Envelope) error {
	body, err := json.Marshal(envelope)
	if err != nil {
		return err
	}

	return disk.Write(q.metadata(envelope.ID), body, 0600)
}

func (q *Queue) read(path string) (*Envelope, error) {
	body, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	envelope := new(Envelope)

	err = json.Unmarshal(body, envelope)
	if err != nil {
		return nil, err
	}

	return envelope, nil
}

func (q *Queue) message(id string) string {
	return filepath.Join(q.directory, id+".eml")
}

func (q *Queue) metadata(id string) string {
	return filepath.Join(q.directory, id+".json")
}

// Open loads an existing spool directory, creating it when needed.
func Open(directory string) (*Queue, error) {
	q := &Queue{
		directory: directory,
		dead:      filepath.Join(directory, "dead"),
		notify:    make(chan struct{}, 1),
	}

	err := disk.Mkdir(q.directory)
	if err != nil {
		return nil, err
	}

	err = disk.Mkdir(q.dead)
	if err != nil {
		return nil, err
	}

	entries, err := os.ReadDir(q.directory)
	if err != nil {
		return nil, err
	}

	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}

		envelope, err := q.read(filepath.Join(q.directory, entry.Name()))
		if err != nil {
			continue
		}

		_, err = os.Stat(q.message(envelope.ID))
		if err != nil {
			os.Remove(q.metadata(envelope.ID))

			continue
		}

		heap.Push(&q.pending, envelope)
	}

	return q, nil
}
