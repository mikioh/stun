// Copyright 2015 Mikio Hara. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package stun

import (
	"crypto/rand"
	"errors"
	"io"
)

var (
	errMessageTooShort   = errors.New("message too short")
	errAttributeTooShort = errors.New("attribute too short")
	errBufferTooShort    = errors.New("buffer too short")
	errInvalidMessage    = errors.New("invalid message")
	errInvalidAttribute  = errors.New("invalid attribute")
)

const HeaderLen = 20 // STUN message header length

// A Class represents a STUN message class.
type Class int

const (
	ClassRequest Class = iota
	ClassIndication
	ClassSuccessResponse
	ClassErrorResponse
)

var classes = map[Class]string{
	ClassRequest:         "request",
	ClassIndication:      "indication",
	ClassSuccessResponse: "success response",
	ClassErrorResponse:   "error response",
}

func (c Class) String() string {
	s, ok := classes[c]
	if !ok {
		return "<nil>"
	}
	return s
}

// A Method represents a STUN message method.
type Method int

func (m Method) String() string {
	s, ok := methods[m]
	if !ok {
		return "<nil>"
	}
	return s
}

// A Type reprensents a STUN message type.
type Type int

// Class returns a message class of the type.
func (t Type) Class() Class {
	return Class(t&0x0100>>7 | t&0x10>>4)
}

// Method returns a message type of the type.
func (t Type) Method() Method {
	return Method(t&0x3e00>>2 | t&0xe0>>1 | t&0x0f)
}

// MessageType returns a message type consisting of c and m.
func MessageType(c Class, m Method) Type {
	return Type(m&0x0f80<<2) | Type(c&0x02<<7) | Type(m&0x70<<1) | Type(c&0x01<<4) | Type(m&0x0f)
}

// MagicCookie is the fixed cookie value defined in RFC 5389.
var MagicCookie = []byte{0x21, 0x12, 0xa4, 0x42}

// A Message represents a STUN message.
type Message struct {
	// Type specifies the message type.
	Type Type

	// Cookie specifies the 32-bit magic cookie.
	// If Cookie is nil, Marshal method sets an appropriate value.
	Cookie []byte

	// TID specifies the 96-bit transaction identifier.
	// If TID is nil, Marshal method sets an appropriate value.
	TID []byte

	// Attrs specifies the list of attributes.
	Attrs []Attribute
}

// Marshal returns the binary encoding of the STUN message m.
func (m *Message) Marshal() ([]byte, error) {
	l := 0
	for _, attr := range m.Attrs {
		l += roundup(4 + attr.Len())
	}
	b := make([]byte, HeaderLen+l)
	b[0], b[1] = byte(m.Type>>8), byte(m.Type)
	b[2], b[3] = byte(l>>8), byte(l)
	if len(m.Cookie) < 4 {
		copy(b[4:8], MagicCookie)
	} else {
		copy(b[4:8], m.Cookie)
	}
	if len(m.TID) < 12 {
		if _, err := io.ReadFull(rand.Reader, b[8:20]); err != nil {
			return nil, err
		}
	} else {
		copy(b[8:20], m.TID)
	}
	if err := marshalAttributes(b, m); err != nil {
		return nil, err
	}
	return b, nil
}

// ParseMessage parses b as a STUN message.
func ParseMessage(b []byte) (*Message, error) {
	if len(b) < HeaderLen {
		return nil, errMessageTooShort
	}
	l := int(b[2])<<8 | int(b[3])
	if len(b) < HeaderLen+roundup(l) {
		return nil, errMessageTooShort
	}
	m := Message{
		Type:   Type(b[0])<<8 | Type(b[1]),
		Cookie: make([]byte, 4),
		TID:    make([]byte, 12),
	}
	copy(m.Cookie, b[4:8])
	copy(m.TID, b[8:HeaderLen])
	var err error
	m.Attrs, err = parseAttributes(m.TID, b[HeaderLen:])
	if err != nil {
		return nil, err
	}
	return &m, nil
}
