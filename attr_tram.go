// Copyright 2015 Mikio Hara. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package stun

import (
	"crypto/sha256"
	"encoding/binary"
)

// A Userhash represents a STUN USERHASH attribute.
type Userhash []byte

// Len implements the Len method of Attribute interface.
func (h Userhash) Len() int {
	return len(h)
}

// A MessageIntegritySHA256 represents a STUN MESSAGE-INTEGRITY-SHA256
// attribute.
// If MessageIntegrity is nil, Marshal method of Message interface
// sets an approrpiate value.
type MessageIntegritySHA256 []byte

// Len implements the Len method of Attribute interface.
func (_ MessageIntegritySHA256) Len() int {
	return sha256.Size
}

// A PasswordAlgorithms represents a STUN PASSWORD-ALGORITHMS
// attribute.
type PasswordAlgorithms []PasswordAlgorithm

// Len implements the Len method of Attribute interface.
func (pas PasswordAlgorithms) Len() int {
	var l int
	for _, pa := range pas {
		l += roundup(pa.Len())
	}
	return l
}

func marshalPasswordAlgosAttr(b []byte, t int, attr Attribute, _ []byte) error {
	l := attr.Len()
	if len(b) < l {
		return errBufferTooShort
	}
	marshalAttrTypeLen(b, t, l)
	b = b[4:]
	for _, pa := range attr.(PasswordAlgorithms) {
		binary.BigEndian.PutUint16(b[:2], uint16(pa.Number))
		binary.BigEndian.PutUint16(b[2:4], uint16(len(pa.Params)))
		copy(b[4:], pa.Params)
		b = b[roundup(pa.Len()):]
	}
	return nil
}

func parsePasswordAlgosAttr(b []byte, min, max int, _ []byte, _, l int) (Attribute, error) {
	if min > l || l > max || len(b) < l {
		return nil, errAttributeTooShort
	}
	var pas PasswordAlgorithms
	for len(b) >= 4 {
		pa := PasswordAlgorithm{Number: int(binary.BigEndian.Uint16(b[:2]))}
		ll := int(binary.BigEndian.Uint16(b[2:4]))
		pa.Params = make([]byte, ll)
		copy(pa.Params, b[4:])
		pas = append(pas, pa)
		rl := roundup(4 + ll)
		if rl > len(b) {
			return nil, errInvalidAttribute
		}
		b = b[rl:]
	}
	return pas, nil
}

// A PasswordAlgorithm represents a STUN PASSWORD-ALGORITHM attribute.
type PasswordAlgorithm struct {
	Number int    // algorithm number; 0x0001 for MD5, 0x0002 for SHA256
	Params []byte // algorithm parameters
}

// Len implements the Len method of Attribute interface.
func (pa *PasswordAlgorithm) Len() int {
	if pa == nil {
		return 0
	}
	return 4 + len(pa.Params)
}

func marshalPasswordAlgoAttr(b []byte, t int, attr Attribute, _ []byte) error {
	l := attr.Len()
	if len(b) < l {
		return errBufferTooShort
	}
	marshalAttrTypeLen(b, t, l)
	if pa, ok := attr.(*PasswordAlgorithm); ok && pa != nil {
		binary.BigEndian.PutUint16(b[4:6], uint16(pa.Number))
		binary.BigEndian.PutUint16(b[6:8], uint16(len(pa.Params)))
		copy(b[8:], pa.Params)
	}
	return nil
}

func parsePasswordAlgoAttr(b []byte, min, max int, _ []byte, _, l int) (Attribute, error) {
	if min > l || l > max || len(b) < l {
		return nil, errAttributeTooShort
	}
	pa := PasswordAlgorithm{Number: int(binary.BigEndian.Uint16(b[:2]))}
	pa.Params = make([]byte, int(binary.BigEndian.Uint16(b[2:4])))
	copy(pa.Params, b[4:])
	return &pa, nil
}

// An AlternateDomain represents a STUN ALTERNATE-DOMAIN attribute.
type AlternateDomain string

// Len implements the Len method of Attribute interface.
func (ad AlternateDomain) Len() int {
	return len(ad)
}

// An Origin represents a STUN ORIGIN attribute.
type Origin string

// Len implements the Len method of Attribute interface.
func (o Origin) Len() int {
	return len(o)
}
