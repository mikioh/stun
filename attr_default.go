// Copyright 2015 Mikio Hara. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package stun

import "errors"

// A DefaultAttr reprensents the default STUN attribute.
// DefaultAttr is used for marshaling and parsing STUN attributes not
// supported in the package.
type DefaultAttr struct {
	// Type specifies the attribute type.
	Type int

	// Data specifes the attribute value.
	Data []byte
}

// Len implements the Len method of Attribute interface.
func (da *DefaultAttr) Len() int {
	if da == nil {
		return 0
	}
	return len(da.Data)
}

func marshalDefaultAttr(b []byte, t int, attr Attribute, _ []byte) error {
	if len(b) < 4+attr.Len() {
		return errors.New("short buffer")
	}
	marshalAttrTypeLen(b, t, attr.Len())
	copy(b[4:], attr.(*DefaultAttr).Data)
	return nil
}

func parseDefaultAttr(b []byte, _, _ int, _ []byte, t, l int) (Attribute, error) {
	da := DefaultAttr{Type: t, Data: make([]byte, l)}
	copy(da.Data, b)
	return &da, nil
}
