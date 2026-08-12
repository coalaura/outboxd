package deliver

import "errors"

var (
	errBodyTooShort = errors.New("queued body shorter than envelope size")
	errBodyTooLong  = errors.New("queued body longer than envelope size")

	errNullMX              = errors.New("domain does not accept mail (null MX)")
	errNoSuchDomain        = errors.New("recipient domain does not exist")
	errSMTPUTF8Unsupported = errors.New("destination does not support SMTPUTF8")
	err8BITMIMEUnsupported = errors.New("destination does not support 8BITMIME")
	errTLSRequired         = errors.New("TLS required but STARTTLS not available")
	errTLSFailed           = errors.New("STARTTLS failed; refusing plaintext downgrade")
	errNoUsableIP          = errors.New("no usable destination address")
	errPrivateDestination  = errors.New("destination address is not publicly routable")
	errAttemptTimeout      = errors.New("delivery attempt timeout exceeded")
	errLifetime            = errors.New("maximum queue lifetime exceeded")
)
