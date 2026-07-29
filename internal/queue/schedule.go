package queue

type schedule []*Envelope

func (s schedule) Len() int {
	return len(s)
}

func (s schedule) Less(i, j int) bool {
	return s[i].NextAttempt.Before(s[j].NextAttempt)
}

func (s schedule) Swap(i, j int) {
	s[i], s[j] = s[j], s[i]
	s[i].index = i
	s[j].index = j
}

func (s *schedule) Push(value any) {
	envelope := value.(*Envelope)
	envelope.index = len(*s)

	*s = append(*s, envelope)
}

func (s *schedule) Pop() any {
	old := *s
	last := len(old) - 1

	envelope := old[last]
	old[last] = nil

	*s = old[:last]

	return envelope
}
