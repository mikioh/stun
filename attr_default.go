// Copyright 2015 Mikio Hara. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package stun

// A DefaultAttribute reprensents the default STUN attribute.
type DefaultAttribute struct {
	Type int    // type
	Data []byte // value
}

// Len implements the Len method of Attribute interface.
func (da *DefaultAttribute) Len() int {
	if da == nil {
		return 0
	}
	return len(da.Data)
}

// Marshal implements the Marshal method of Attribute interface.
func (da *DefaultAttribute) Marshal(tid []byte) ([]byte, error) {
	b := make([]byte, roundup(4+len(da.Data)))
	if err := marshalDefaultAttr(b, da.Type, da, tid); err != nil {
		return nil, err
	}
	return b, nil
}

func marshalDefaultAttr(b []byte, t int, attr Attribute, tid []byte) error {
	if len(b) < 4 {
		return errBufferTooShort
	}
	marshalAttrTypeLen(b, t, len(attr.(*DefaultAttribute).Data))
	copy(b[4:], attr.(*DefaultAttribute).Data)
	return nil
}

func parseDefaultAttr(t, l int, tid, b []byte) (Attribute, error) {
	da := DefaultAttribute{Type: t, Data: make([]byte, l)}
	copy(da.Data, b)
	return &da, nil
}
