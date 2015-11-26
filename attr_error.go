// Copyright 2015 Mikio Hara. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package stun

import "encoding/binary"

// An ErrorCode represents a STUN ERROR-CODE attribute.
type ErrorCode struct {
	Code   int    // code consist of class and number
	Reason string // reason
}

// Len implements the Len method of Attribute interface.
func (ec *ErrorCode) Len() int {
	if ec == nil {
		return 0
	}
	return 4 + len(ec.Reason)
}

// Class returns the error class.
func (ec *ErrorCode) Class() int {
	if ec == nil {
		return 0
	}
	return int(ec.Code / 100 & 0x07)
}

// Number returns the error number.
func (ec *ErrorCode) Number() int {
	if ec == nil {
		return 0
	}
	return int(ec.Code % 100)
}

func marshalErrorCodeAttr(b []byte, t int, attr Attribute, _ []byte) error {
	if len(b) < 4+attr.Len() {
		return errBufferTooShort
	}
	marshalAttrTypeLen(b, t, attr.Len())
	b[6], b[7] = byte(attr.(*ErrorCode).Class()), byte(attr.(*ErrorCode).Number())
	copy(b[8:], attr.(*ErrorCode).Reason)
	return nil
}

func parseErrorCodeAttr(b []byte, min, max int, _ []byte, _, l int) (Attribute, error) {
	if min > l || l > max || len(b) < l {
		return nil, errAttributeTooShort
	}
	ec := ErrorCode{Code: int(b[2]&0x07)*100 + int(b[3])}
	ec.Reason = string(b[4:l])
	return &ec, nil
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
		return errBufferTooShort
	}
	marshalAttrTypeLen(b, t, attr.Len())
	b = b[4:]
	for _, t := range attr.(UnknownAttrs) {
		if len(b) < 2 {
			return errBufferTooShort
		}
		binary.BigEndian.PutUint16(b[:2], uint16(t))
		b = b[2:]
	}
	return nil
}

func parseUnknownAttrs(b []byte, min, max int, _ []byte, _, l int) (Attribute, error) {
	if min > l || l > max || len(b) < l {
		return nil, errAttributeTooShort
	}
	ua := make(UnknownAttrs, 0, l/2)
	for len(b) > 1 {
		ua = append(ua, int(binary.BigEndian.Uint16(b[:2])))
		b = b[2:]
	}
	return ua, nil
}
