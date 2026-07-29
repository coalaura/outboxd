package smtpd

import (
	"github.com/emersion/go-sasl"
)

// PLAIN over TLS is equivalent and preferred.
const mechLogin = "LOGIN"

const (
	loginStateInit = iota
	loginStateUsername
	loginStatePassword
	loginStateDone
)

var (
	loginUsername = []byte("Username:")
	loginPassword = []byte("Password:")
)

type loginServer struct {
	authenticate func(username, password string) error

	username string
	state    int
}

func newLoginServer(authenticate func(username, password string) error) sasl.Server {
	return &loginServer{authenticate: authenticate}
}

func (s *loginServer) Next(response []byte) (challenge []byte, done bool, err error) {
	if s.state == loginStateInit {
		s.state = loginStateUsername

		if len(response) == 0 {
			return loginUsername, false, nil
		}
	}

	switch s.state {
	case loginStateUsername:
		if len(response) == 0 {
			s.state = loginStateDone

			return nil, true, sasl.ErrUnexpectedClientResponse
		}

		s.username = string(response)
		s.state = loginStatePassword

		return loginPassword, false, nil
	case loginStatePassword:
		s.state = loginStateDone

		return nil, true, s.authenticate(s.username, string(response))
	}

	return nil, true, sasl.ErrUnexpectedClientResponse
}
