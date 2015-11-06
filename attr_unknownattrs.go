// Copyright 2015 Mikio Hara. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package stun

// An UnknownAttrs represents a STUN UNKNOWN-ATTRIBUTES attribute.
type UnknownAttrs struct {
	Types []int // types
}

// Len implements the Len method of Attribute interface.
func (ua *UnknownAttrs) Len() int {
	if ua == nil {
		return 0
	}
	return 2 * len(ua.Types)
}

// Marshal implements the Marshal method of Attribute interface.
func (ua *UnknownAttrs) Marshal(tid []byte) ([]byte, error) {
	b := make([]byte, roundup(4+2*len(ua.Types)))
	if err := marshalUnknownAttrs(b, attrUNKNOWN_ATTRIBUTES, ua, tid); err != nil {
		return nil, err
	}
	return b, nil
}

func marshalUnknownAttrs(b []byte, t int, attr Attribute, tid []byte) error {
	if len(b) < 4+2*len(attr.(*UnknownAttrs).Types) {
		return errBufferTooShort
	}
	marshalAttrTypeLen(b, t, 2*len(attr.(*UnknownAttrs).Types))
	b = b[4:]
	for _, t := range attr.(*UnknownAttrs).Types {
		if len(b) < 2 {
			return errBufferTooShort
		}
		b[0], b[1] = byte(t>>8), byte(t)
		b = b[2:]
	}
	return nil
}

func parseUnknownAttrs(t, l int, tid, b []byte) (Attribute, error) {
	ua := UnknownAttrs{Types: make([]int, 0, l/2)}
	for len(b) > 1 {
		ua.Types = append(ua.Types, int(b[0])<<8|int(b[1]))
		b = b[2:]
	}
	return &ua, nil
}
