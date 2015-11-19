// Copyright 2015 Mikio Hara. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package stun

// A ECNCheck represents a STUN ECN-CHECK attribute.
type ECNCheck struct {
	ECF int  // ECN echo value field
	V   bool // whether ECF is valid
}

// Len implements the Len method of Attribute interface.
func (ec *ECNCheck) Len() int {
	if ec == nil {
		return 0
	}
	return 4
}

func marshalECNCheckAttr(b []byte, t int, attr Attribute, _ []byte) error {
	if len(b) < 4+4 {
		return errBufferTooShort
	}
	marshalAttrTypeLen(b, t, 4)
	b[7] = byte(attr.(*ECNCheck).ECF & 0x03 << 1)
	if attr.(*ECNCheck).V {
		b[7] |= 0x01
	}
	return nil
}

func parseECNCheckAttr(b []byte, min, max int, _ []byte, _, l int) (Attribute, error) {
	if min > l || l > max || len(b) < l {
		return nil, errAttributeTooShort
	}
	ec := ECNCheck{ECF: int(b[3]) >> 1 & 0x03}
	if b[3]&0x01 != 0 {
		ec.V = true
	}
	return &ec, nil
}
