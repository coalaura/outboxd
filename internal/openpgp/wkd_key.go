package openpgp

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"slices"

	pgp "github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
)

const (
	wkdMaxPackets          = 256
	wkdSignaturePacket     = 2
	wkdPublicKeyPacket     = 6
	wkdUserIDPacket        = 13
	wkdPublicSubkeyPacket  = 14
	wkdUserAttributePacket = 17
	wkdEmbeddedSignature   = 32
)

func parseWKDRecipient(keyData []byte, recipient string) (*pgp.Entity, error) {
	if len(keyData) == 0 || len(keyData) > wkdMaxKeyBytes {
		return nil, errors.New("invalid WKD key size")
	}

	// ReadKeyRing tolerates some malformed entities. Inspect every packet first
	// so private, compressed or trailing invalid material cannot be hidden.
	body := bytes.NewReader(keyData)
	reader := packet.NewOpaqueReader(body)

	primaryKeys := 0

	for count := 0; body.Len() > 0; count++ {
		value, err := reader.Next()
		if err != nil {
			return nil, fmt.Errorf("read WKD packet: %w", err)
		}

		if count >= wkdMaxPackets {
			return nil, errors.New("WKD key exceeds packet limit")
		}

		switch value.Tag {
		case wkdPublicKeyPacket:
			primaryKeys++
		case wkdSignaturePacket:
			err = validateWKDSignature(value.Contents, false)
			if err != nil {
				return nil, err
			}
		case wkdPublicSubkeyPacket, wkdUserIDPacket, wkdUserAttributePacket:
		default:
			return nil, errors.New("WKD response contains a non-public-key packet")
		}

		_, err = value.Parse()
		if err != nil {
			return nil, fmt.Errorf("parse WKD packet: %w", err)
		}
	}

	if primaryKeys != 1 {
		return nil, errors.New("WKD response must contain exactly one public entity")
	}

	entity, addresses, err := parseRecipientEntity(keyData)
	if err != nil {
		return nil, err
	}

	if !slices.Contains(addresses, recipient) {
		return nil, errors.New("WKD key has no active self-signed identity for the exact recipient")
	}

	return entity, nil
}

func validateWKDSignature(body []byte, embedded bool) error {
	// The dependency allocates v6 signature subpacket buffers from untrusted
	// uint32 lengths before reading them, and recursively parses embedded
	// signatures. Bound both before invoking its semantic packet parser.
	if len(body) < 4 || body[0] < 4 || body[0] > 6 {
		return errors.New("invalid WKD signature header")
	}

	lengthBytes := 2

	if body[0] == 6 {
		lengthBytes = 4
	}

	body = body[4:]

	for range 2 {
		if len(body) < lengthBytes {
			return errors.New("truncated WKD signature length")
		}

		length := uint64(binary.BigEndian.Uint16(body))

		if lengthBytes == 4 {
			length = uint64(binary.BigEndian.Uint32(body))
		}

		body = body[lengthBytes:]
		if length > uint64(len(body)) {
			return errors.New("WKD signature subpackets exceed packet size")
		}

		subpackets, err := packet.OpaqueSubpackets(body[:int(length)])
		if err != nil {
			return fmt.Errorf("read WKD signature subpackets: %w", err)
		}

		for _, subpacket := range subpackets {
			if subpacket.SubType&0x7f != wkdEmbeddedSignature {
				continue
			}

			if embedded {
				return errors.New("WKD signature nesting exceeds limit")
			}

			err = validateWKDSignature(subpacket.Contents, true)
			if err != nil {
				return err
			}
		}

		body = body[int(length):]
	}

	return nil
}
