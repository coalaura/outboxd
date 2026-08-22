package deliver

import (
	"sync"

	"github.com/coalaura/outboxd/internal/queue"
)

type admissionKind uint8

const (
	admissionUser admissionKind = iota
	admissionDomain
)

type admissionWait struct {
	envelope *queue.Envelope
	kind     admissionKind
	key      string
}

type admissionParking struct {
	mu      sync.Mutex
	waiting []admissionWait
}

func (d *Deliverer) parkAdmission(envelope *queue.Envelope, kind admissionKind, key string) {
	if kind == admissionDomain {
		envelope.PreferredDomain = key
	}

	d.parked.mu.Lock()
	d.parked.waiting = append(d.parked.waiting, admissionWait{
		envelope: envelope,
		kind:     kind,
		key:      key,
	})
	d.parked.mu.Unlock()

	// Close the race where capacity was released immediately before parking.
	d.wakeAdmission(kind, key)
}

func (d *Deliverer) wakeAdmission(kind admissionKind, key string) {
	limiter := d.users
	if kind == admissionDomain {
		limiter = d.domains
	}

	if !limiter.available(key) {
		return
	}

	var envelope *queue.Envelope

	d.parked.mu.Lock()

	for i := range d.parked.waiting {
		waiting := d.parked.waiting[i]
		if waiting.kind != kind || waiting.key != key {
			continue
		}

		envelope = waiting.envelope
		copy(d.parked.waiting[i:], d.parked.waiting[i+1:])
		d.parked.waiting = d.parked.waiting[:len(d.parked.waiting)-1]

		break
	}

	d.parked.mu.Unlock()

	if envelope != nil {
		d.queue.Requeue(envelope)
	}
}

func (d *Deliverer) requeueParked() {
	d.parked.mu.Lock()
	waiting := d.parked.waiting
	d.parked.waiting = nil
	d.parked.mu.Unlock()

	for _, parked := range waiting {
		d.queue.Requeue(parked.envelope)
	}
}
