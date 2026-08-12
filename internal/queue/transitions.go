package queue

import "slices"

func (q *Queue) beginTransition(id string) error {
	return q.beginTransitions(id)
}

func (q *Queue) beginTransitions(ids ...string) error {
	q.mu.Lock()
	defer q.mu.Unlock()

	for _, id := range ids {
		_, exists := q.transitioning[id]
		if exists {
			return ErrQueueBusy
		}
	}

	for _, id := range ids {
		q.transitioning[id] = struct{}{}
	}

	return nil
}

func (q *Queue) endTransition(id string) {
	q.endTransitions(id)
}

func (q *Queue) endTransitions(ids ...string) {
	q.mu.Lock()

	var added bool

	for _, id := range ids {
		delete(q.transitioning, id)

		if slices.ContainsFunc(q.requeues[id], q.scheduleLocked) {
			added = true
		}

		delete(q.requeues, id)
	}

	q.mu.Unlock()

	if added {
		q.signal()
	}
}
