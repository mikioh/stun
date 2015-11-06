// Copyright 2015 Mikio Hara. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package stun

import "hash/crc32"

// An Attribute represents a STUN attribute.
type Attribute interface {
	// Len returns the length of STUN attribute value not
	// including the 4-byte attribute type and length fields, and
	// attribute padding bytes.
	Len() int

	// Marshal returns the binary encoding of STUN attribute.
	Marshal(tid []byte) ([]byte, error)
}

func marshalAttrTypeLen(b []byte, t, l int) {
	b[0], b[1] = byte(t>>8), byte(t)
	b[2], b[3] = byte(l>>8), byte(l)
}

func attrType(attr Attribute) int {
	switch attr := attr.(type) {
	case *MappedAddr:
		return attrMAPPED_ADDRESS
	case *ErrorCode:
		return attrERROR_CODE
	case *UnknownAttrs:
		return attrUNKNOWN_ATTRIBUTES
	case *XORMappedAddr:
		return attrXOR_MAPPED_ADDRESS
	case *AlternateServer:
		return attrALTERNATE_SERVER
	case *Fingerprint:
		return attrFINGERPRINT
	case *DefaultAttribute:
		return attr.Type
	default:
		return -1
	}
}

var marshalFns = map[int]func([]byte, int, Attribute, []byte) error{
	attrMAPPED_ADDRESS:     marshalAddrAttr,
	attrERROR_CODE:         marshalErrorCodeAttr,
	attrUNKNOWN_ATTRIBUTES: marshalUnknownAttrs,
	attrXOR_MAPPED_ADDRESS: marshalAddrAttr,
	attrALTERNATE_SERVER:   marshalAddrAttr,
	//attrFINGERPRINT:        marshalFingerprintAttr,
}

func marshalAttributes(b []byte, m *Message) error {
	wire := b
	b = b[HeaderLen:]
	var fp *Fingerprint
	for _, attr := range m.Attrs {
		t := attrType(attr)
		if t == attrFINGERPRINT {
			fp = attr.(*Fingerprint)
			continue
		}
		fn, ok := marshalFns[t]
		if !ok {
			continue
		}
		if err := fn(b, t, attr, m.TID); err != nil {
			return err
		}
		b = b[roundup(4+attr.Len()):]
	}
	if fp == nil {
		return nil
	}
	var attr Fingerprint
	if fp.Checksum != 0 {
		attr.Checksum = fp.Checksum
	} else {
		attr.Checksum = crc32.ChecksumIEEE(wire[:len(wire)-8]) ^ crc32XOR
	}
	if err := marshalFingerprintAttr(b, attrFINGERPRINT, &attr, m.TID); err != nil {
		return err
	}
	return nil
}

func parseAttrTypeLen(b []byte) (t, l int, err error) {
	if len(b) < 4 {
		return -1, -1, errAttributeTooShort
	}
	t = int(b[0])<<8 | int(b[1])
	if 0 >= t || t >= 0xffff {
		return -1, -1, errInvalidAttribute
	}
	l = int(b[2])<<8 | int(b[3])
	if len(b) < 4+l {
		return -1, -1, errAttributeTooShort
	}
	return t, l, nil
}

var parseFns = map[int]func(int, int, []byte, []byte) (Attribute, error){
	attrMAPPED_ADDRESS:     parseAddrAttr,
	attrERROR_CODE:         parseErrorCodeAttr,
	attrUNKNOWN_ATTRIBUTES: parseUnknownAttrs,
	attrXOR_MAPPED_ADDRESS: parseAddrAttr,
	attrALTERNATE_SERVER:   parseAddrAttr,
	attrFINGERPRINT:        parseFingerprintAttr,
}

func parseAttributes(tid, b []byte) ([]Attribute, error) {
	var attrs []Attribute
	for len(b) > 0 {
		t, l, err := parseAttrTypeLen(b)
		if err != nil {
			return nil, err
		}
		var attr Attribute
		if fn, ok := parseFns[t]; !ok {
			attr, err = parseDefaultAttr(t, l, tid, b[4:4+l])
		} else {
			attr, err = fn(t, l, tid, b[4:4+l])
		}
		if err != nil {
			return nil, err
		}
		if attr != nil {
			attrs = append(attrs, attr)
		}
		b = b[roundup(4+l):]
	}
	return attrs, nil
}
