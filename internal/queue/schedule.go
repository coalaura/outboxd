package queue

import (
	"container/heap"
	"time"
)

type envelopeHeap []*Envelope

type userQueue struct {
	name     string
	messages envelopeHeap
	index    int
	due      bool
}

type userHeap []*userQueue

// schedule keeps one NextAttempt heap per owner. Due owners rotate through due,
// so a busy owner contributes at most one message per scheduling quantum.
type schedule struct {
	users  map[string]*userQueue
	future userHeap
	due    []*userQueue
	count  int
}

func (h envelopeHeap) Len() int {
	return len(h)
}

func (h envelopeHeap) Less(i, j int) bool {
	if h[i].NextAttempt.Equal(h[j].NextAttempt) {
		return h[i].ID < h[j].ID
	}

	return h[i].NextAttempt.Before(h[j].NextAttempt)
}

func (h envelopeHeap) Swap(i, j int) {
	h[i], h[j] = h[j], h[i]

	h[i].index = i
	h[j].index = j
}

func (h *envelopeHeap) Push(value any) {
	envelope := value.(*Envelope)

	envelope.index = len(*h)

	*h = append(*h, envelope)
}

func (h *envelopeHeap) Pop() any {
	old := *h

	last := len(old) - 1

	envelope := old[last]

	old[last] = nil

	envelope.index = -1

	*h = old[:last]

	return envelope
}

func (h userHeap) Len() int {
	return len(h)
}

func (h userHeap) Less(i, j int) bool {
	a, b := h[i].messages[0], h[j].messages[0]

	if a.NextAttempt.Equal(b.NextAttempt) {
		return h[i].name < h[j].name
	}

	return a.NextAttempt.Before(b.NextAttempt)
}

func (h userHeap) Swap(i, j int) {
	h[i], h[j] = h[j], h[i]

	h[i].index = i
	h[j].index = j
}

func (h *userHeap) Push(value any) {
	user := value.(*userQueue)

	user.index = len(*h)

	*h = append(*h, user)
}

func (h *userHeap) Pop() any {
	old := *h

	last := len(old) - 1

	user := old[last]

	old[last] = nil

	user.index = -1

	*h = old[:last]

	return user
}

func (s *schedule) Len() int {
	return s.count
}

func (s *schedule) init() {
	if s.users == nil {
		s.users = make(map[string]*userQueue)
	}
}

func (s *schedule) Push(envelope *Envelope) {
	s.init()

	user := s.users[envelope.Username]
	if user == nil {
		user = &userQueue{name: envelope.Username, index: -1}

		s.users[user.name] = user
	}

	oldFirst := user.messages.Len() == 0

	heap.Push(&user.messages, envelope)

	s.count++

	if user.due {
		return
	}

	if oldFirst {
		heap.Push(&s.future, user)
	} else if envelope.index == 0 {
		heap.Fix(&s.future, user.index)
	}
}

func (s *schedule) NextAttempt() (time.Time, bool) {
	if len(s.due) > 0 {
		return s.due[0].messages[0].NextAttempt, true
	}

	if len(s.future) == 0 {
		return time.Time{}, false
	}

	return s.future[0].messages[0].NextAttempt, true
}

func (s *schedule) PopDue(now time.Time) *Envelope {
	for len(s.future) > 0 && !s.future[0].messages[0].NextAttempt.After(now) {
		user := heap.Pop(&s.future).(*userQueue)

		user.due = true

		s.due = append(s.due, user)
	}

	if len(s.due) == 0 {
		return nil
	}

	user := s.due[0]

	s.due = s.due[1:]

	envelope := heap.Pop(&user.messages).(*Envelope)

	s.count--

	if user.messages.Len() == 0 {
		delete(s.users, user.name)

		user.due = false
	} else if !user.messages[0].NextAttempt.After(now) {
		s.due = append(s.due, user)
	} else {
		user.due = false

		heap.Push(&s.future, user)
	}

	return envelope
}

func (s *schedule) Remove(envelope *Envelope) bool {
	user := s.users[envelope.Username]

	if user == nil || envelope.index < 0 || envelope.index >= user.messages.Len() || user.messages[envelope.index] != envelope {
		return false
	}

	wasFirst := envelope.index == 0

	heap.Remove(&user.messages, envelope.index)

	s.count--

	if user.messages.Len() == 0 {
		delete(s.users, user.name)

		if user.due {
			for i, queued := range s.due {
				if queued == user {
					s.due = append(s.due[:i], s.due[i+1:]...)

					break
				}
			}
		} else if user.index >= 0 {
			heap.Remove(&s.future, user.index)
		}

		return true
	}

	if wasFirst && user.due && user.messages[0].NextAttempt.After(time.Now()) {
		for i, queued := range s.due {
			if queued == user {
				s.due = append(s.due[:i], s.due[i+1:]...)

				break
			}
		}

		user.due = false

		heap.Push(&s.future, user)

		return true
	}

	if wasFirst && !user.due {
		heap.Fix(&s.future, user.index)
	}

	return true
}
