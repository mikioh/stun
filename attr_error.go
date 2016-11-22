// Copyright 2015 Mikio Hara. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package stun

import (
	"encoding/binary"
	"errors"
)

// An Error represents a STUN ERROR-CODE attribute.
type Error struct {
	Code   int    // code consists of class and number
	Reason string // reason
}

// Len implements the Len method of Attribute interface.
func (e *Error) Len() int {
	if e == nil {
		return 0
	}
	return 4 + len(e.Reason)
}

// Class returns the error class.
func (e *Error) Class() int {
	if e == nil {
		return 0
	}
	return int(e.Code / 100 & 0x07)
}

// Number returns the error number.
func (e *Error) Number() int {
	if e == nil {
		return 0
	}
	return int(e.Code % 100)
}

func marshalErrorAttr(b []byte, t int, attr Attribute, _ []byte) error {
	if len(b) < 4+attr.Len() {
		return errors.New("short buffer")
	}
	marshalAttrTypeLen(b, t, attr.Len())
	b[6], b[7] = byte(attr.(*Error).Class()), byte(attr.(*Error).Number())
	copy(b[8:], attr.(*Error).Reason)
	return nil
}

func parseErrorAttr(b []byte, min, max int, _ []byte, _, l int) (Attribute, error) {
	if min > l || l > max || len(b) < l {
		return nil, errors.New("short attribute")
	}
	e := Error{Code: int(b[2]&0x07)*100 + int(b[3])}
	e.Reason = string(b[4:l])
	return &e, nil
}

// An UnknownAttrs represents a STUN UNKNOWN-ATTRIBUTES attribute.
type UnknownAttrs []int

// Len implements the Len method of Attribute interface.
func (ua UnknownAttrs) Len() int {
	if len(ua) == 0 {
		return 0
	}
	return 2 * len(ua)
}

func marshalUnknownAttrs(b []byte, t int, attr Attribute, _ []byte) error {
	if len(b) < 4+attr.Len() {
		return errors.New("short buffer")
	}
	marshalAttrTypeLen(b, t, attr.Len())
	b = b[4:]
	for _, t := range attr.(UnknownAttrs) {
		if len(b) < 2 {
			return errors.New("short buffer")
		}
		binary.BigEndian.PutUint16(b[:2], uint16(t))
		b = b[2:]
	}
	return nil
}

func parseUnknownAttrs(b []byte, min, max int, _ []byte, _, l int) (Attribute, error) {
	if min > l || l > max || len(b) < l {
		return nil, errors.New("short attribute")
	}
	ua := make(UnknownAttrs, 0, l/2)
	for len(b) > 1 {
		ua = append(ua, int(binary.BigEndian.Uint16(b[:2])))
		b = b[2:]
	}
	return ua, nil
}
