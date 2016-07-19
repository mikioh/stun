// Copyright 2015 Mikio Hara. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package stun

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"hash/crc32"
	"io"
)

var (
	errMessageTooShort          = errors.New("message too short")
	errAttributeTooShort        = errors.New("attribute too short")
	errBufferTooShort           = errors.New("buffer too short")
	errInvalidMessage           = errors.New("invalid message")
	errInvalidHeader            = errors.New("invalid header")
	errInvalidAttribute         = errors.New("invalid attribute")
	errHMACFingerprintMismatch  = errors.New("HMAC fingerprint mismatch")
	errCRC32FingerprintMismatch = errors.New("CRC-32 fingerprint mismatch")
)

// A MessageError represents a STUN message error.
type MessageError struct {
	// Type is the STUN message type.
	Type Type

	// Err is the error that occurred.
	Err error
}

func (me *MessageError) Error() string {
	if me == nil {
		return "<nil>"
	}
	return fmt.Sprintf("%s: %s", me.Type.String(), me.Err.Error())
}

const (
	controlHeaderLen     = 20
	channelDataHeaderLen = 4
)

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
		return fmt.Sprintf("%#x", byte(c&0x3))
	}
	return s
}

// A Method represents a STUN message method.
type Method int

func (m Method) String() string {
	s, ok := methods[m]
	if !ok {
		return fmt.Sprintf("%#03x", uint16(m))
	}
	return s
}

// A Type reprensents a STUN message type or channel number.
type Type int

// Class returns the message class of type.
func (t Type) Class() Class {
	if 0x0000 <= t && t <= 0x3fff {
		return Class(t&0x0100>>7 | t&0x10>>4)
	}
	return Class(t)
}

// Method returns the message method of type.
func (t Type) Method() Method {
	if 0x0000 <= t && t <= 0x3fff {
		return Method(t&0x3e00>>2 | t&0xe0>>1 | t&0x0f)
	}
	return Method(t)
}

func (t Type) String() string {
	if 0x0000 <= t && t <= 0x3fff {
		return fmt.Sprintf("%s for %s", t.Class().String(), t.Method().String())
	}
	return fmt.Sprintf("%#04x", uint16(t))
}

// MessageType returns a message type consisting of c and m.
func MessageType(c Class, m Method) Type {
	return Type(m&0x0f80<<2) | Type(c&0x02<<7) | Type(m&0x70<<1) | Type(c&0x01<<4) | Type(m&0x0f)
}

// MagicCookie is the fixed cookie value defined in RFC 5389.
var MagicCookie = []byte{0x21, 0x12, 0xa4, 0x42}

// A Message represents a STUN message.
type Message interface {
	// Len returns the length of STUN message including the
	// message header and padding bytes.
	Len() int

	// Marshal writes the binary encoding of STUN message to b.
	// It returns the number of bytes marshaled.
	// H must be the HMAC-SHA1 when in use of STUN
	// MESSAGE-INTEGRITY attribute.
	Marshal(b []byte, h hash.Hash) (int, error)
}

// A Control represents a STUN control message.
type Control struct {
	// Type specifies the message type.
	Type Type

	// Cookie specifies the 32-bit magic cookie.
	// If Cookie is nil, Marshal method of Message interface sets
	// an appropriate value.
	Cookie []byte

	// TID specifies the 96-bit transaction identifier.
	// If TID is nil, Marshal method of Message interface sets an
	// appropriate value.
	TID []byte

	// Attrs specifies the list of STUN attributes.
	Attrs []Attribute
}

// Len implements the Len method of Message interface.
func (m *Control) Len() int {
	l := controlHeaderLen
	for _, attr := range m.Attrs {
		l += roundup(4 + attr.Len())
	}
	return l
}

// Marshal implements the Marshal method of Message interface.
func (m *Control) Marshal(b []byte, h hash.Hash) (int, error) {
	l := 0
	for _, attr := range m.Attrs {
		l += roundup(4 + attr.Len())
	}
	ll := controlHeaderLen + l
	if len(b) < ll {
		return 0, &MessageError{Type: m.Type, Err: errBufferTooShort}
	}
	binary.BigEndian.PutUint16(b[:2], uint16(m.Type))
	binary.BigEndian.PutUint16(b[2:4], uint16(l))
	if len(m.Cookie) < 4 {
		copy(b[4:8], MagicCookie)
	} else {
		copy(b[4:8], m.Cookie)
	}
	if len(m.TID) < 12 {
		if _, err := io.ReadFull(rand.Reader, b[8:20]); err != nil {
			return 0, &MessageError{Type: m.Type, Err: err}
		}
	} else {
		copy(b[8:20], m.TID)
	}
	fps, err := marshalAttrs(b[:ll], m)
	if err != nil {
		return 0, &MessageError{Type: m.Type, Err: err}
	}
	if err := marshalIntegrity(b[:ll], h, fps); err != nil {
		return 0, &MessageError{Type: m.Type, Err: err}
	}
	return ll, nil
}

// A ChannelData represents a STUN channel data message.
type ChannelData struct {
	// Number specifies the channel number.
	Number Type

	// Data specifies the channel data.
	// It just refers to the underlying buffer when the returned
	// value from ParseMessage.
	Data []byte
}

// Len implements the Len method of Message interface.
func (m *ChannelData) Len() int {
	return channelDataHeaderLen + roundup(len(m.Data))
}

// Marshal implements the Marshal method of Message interface.
func (m *ChannelData) Marshal(b []byte, _ hash.Hash) (int, error) {
	l := len(m.Data)
	ll := channelDataHeaderLen + roundup(l)
	if len(b) < ll {
		return 0, &MessageError{Type: m.Number, Err: errBufferTooShort}
	}
	binary.BigEndian.PutUint16(b[:2], uint16(m.Number))
	binary.BigEndian.PutUint16(b[2:4], uint16(l))
	copy(b[channelDataHeaderLen:], m.Data)
	return ll, nil
}

// ParseHeader parses b as a STUN message header.
// It returns the message type or channel number, and the message
// length including the message header but not including padding
// bytes.
func ParseHeader(b []byte) (Type, int, error) {
	if len(b) < channelDataHeaderLen {
		return 0, 0, &MessageError{Err: errMessageTooShort}
	}
	t := Type(binary.BigEndian.Uint16(b[:2]))
	l := int(binary.BigEndian.Uint16(b[2:4]))
	if 0x4000 <= t && t <= 0x7fff {
		return t, channelDataHeaderLen + l, nil
	}
	return t, controlHeaderLen + l, nil
}

// ParseMessage parses b as a STUN message.
// It returns the number of bytes parsed and message.
// H must be the HMAC-SHA1 when in use of STUN MESSAGE-INTEGRITY
// attribute.
// It assumes that b contains padding bytes even if a channel data
// message and sent over UDP.
func ParseMessage(b []byte, h hash.Hash) (int, Message, error) {
	if len(b) < channelDataHeaderLen {
		return 0, nil, &MessageError{Err: errMessageTooShort}
	}
	t := Type(binary.BigEndian.Uint16(b[:2]))
	l := int(binary.BigEndian.Uint16(b[2:4]))
	if 0x4000 <= t && t <= 0x7fff {
		ll := channelDataHeaderLen + roundup(l)
		if len(b) < ll {
			return 0, nil, &MessageError{Type: t, Err: errMessageTooShort}
		}
		return ll, &ChannelData{Number: t, Data: b[channelDataHeaderLen : channelDataHeaderLen+l]}, nil
	}
	if b[0]&0xc0 != 0 {
		return 0, nil, &MessageError{Type: t, Err: errInvalidHeader}
	}
	ll := controlHeaderLen + l
	if len(b) < ll {
		return 0, nil, &MessageError{Type: t, Err: errBufferTooShort}
	}
	cookieTID := make([]byte, 16)
	copy(cookieTID[:4], b[4:8])
	copy(cookieTID[4:16], b[8:controlHeaderLen])
	m := Control{Type: t, Cookie: cookieTID[:4], TID: cookieTID[4:16]}
	var (
		err error
		fps []fingerprint
	)
	m.Attrs, fps, err = parseAttrs(b[controlHeaderLen:ll], m.TID)
	if err != nil {
		return 0, nil, &MessageError{Type: t, Err: err}
	}
	if err := validateIntegrity(b[:ll], h, fps); err != nil {
		return 0, nil, &MessageError{Type: t, Err: err}
	}
	return ll, &m, nil
}

func marshalIntegrity(b []byte, h hash.Hash, fps []fingerprint) error {
	for i, fp := range fps {
		if i < 2 && h != nil && fp.attr != nil {
			var tmp [2]byte
			copy(tmp[:], b[2:4])
			l := fp.off - controlHeaderLen + roundup(4+fp.attr.Len())
			binary.BigEndian.PutUint16(b[2:4], uint16(l))
			h.Reset()
			h.Write(b[:fp.off])
			copy(b[fp.off+4:], h.Sum(nil))
			copy(b[2:4], tmp[:])
		}
		if i == 2 && fp.attr != nil {
			if fp.attr.(Fingerprint) == 0 {
				fp.attr = Fingerprint(crc32.ChecksumIEEE(b[:fp.off]) ^ crc32XOR)
			}
			if err := marshalUintAttr(b[fp.off:], attrFINGERPRINT, fp.attr, nil); err != nil {
				return &AttributeError{Type: attrFINGERPRINT, Err: err}
			}
		}
	}
	return nil
}

func validateIntegrity(b []byte, h hash.Hash, fps []fingerprint) error {
	for i, fp := range fps {
		if i < 2 && h != nil && fp.attr != nil {
			var tmp [2]byte
			copy(tmp[:], b[2:4])
			l := fp.off + roundup(4+fp.attr.Len())
			binary.BigEndian.PutUint16(b[2:4], uint16(l))
			h.Reset()
			h.Write(b[:controlHeaderLen+fp.off])
			mac := h.Sum(nil)
			copy(b[2:4], tmp[:])
			if i == 0 && !bytes.Equal(mac, fp.attr.(MessageIntegrity)) {
				return &AttributeError{Type: attrMESSAGE_INTEGRITY, Err: errHMACFingerprintMismatch}
			}
			if i == 1 && !bytes.Equal(mac, fp.attr.(MessageIntegritySHA256)) {
				return &AttributeError{Type: attrMESSAGE_INTEGRITY_SHA256, Err: errHMACFingerprintMismatch}
			}
		}
		if i == 2 && fp.attr != nil {
			if crc := Fingerprint(crc32.ChecksumIEEE(b[:controlHeaderLen+fp.off]) ^ crc32XOR); crc != fp.attr.(Fingerprint) {
				return &AttributeError{Type: attrFINGERPRINT, Err: errCRC32FingerprintMismatch}
			}
		}
	}
	return nil
}
