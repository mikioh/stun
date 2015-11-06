// Copyright 2015 Mikio Hara. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package stun

// An ErrorCode represents a STUN ERROR-CODE attribute.
type ErrorCode struct {
	Code   int    // code
	Reason string // reason
}

// Len implements the Len method of Attribute interface.
func (ec *ErrorCode) Len() int {
	if ec == nil {
		return 0
	}
	return 4 + len(ec.Reason)
}

// Marshal implements the Marshal method of Attribute interface.
func (ec *ErrorCode) Marshal(tid []byte) ([]byte, error) {
	b := make([]byte, roundup(8+len(ec.Reason)))
	if err := marshalErrorCodeAttr(b, attrERROR_CODE, ec, tid); err != nil {
		return nil, err
	}
	return b, nil
}

func marshalErrorCodeAttr(b []byte, t int, attr Attribute, tid []byte) error {
	if len(b) < 8+len(attr.(*ErrorCode).Reason) {
		return errBufferTooShort
	}
	marshalAttrTypeLen(b, t, 4+len(attr.(*ErrorCode).Reason))
	b[6], b[7] = byte(attr.(*ErrorCode).Code/100&0x07), byte(attr.(*ErrorCode).Code%100)
	copy(b[8:], attr.(*ErrorCode).Reason)
	return nil
}

func parseErrorCodeAttr(t, l int, tid, b []byte) (Attribute, error) {
	if len(b) < 4 {
		return nil, errAttributeTooShort
	}
	ec := ErrorCode{Code: int(b[2]&0x07)*100 + int(b[3])}
	ec.Reason = string(b[4:l])
	return &ec, nil
}
