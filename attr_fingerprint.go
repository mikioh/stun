// Copyright 2015 Mikio Hara. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package stun

import "hash/crc32"

const crc32XOR = 0x5354554e // see RFC 5389

// A Fingerprint represents a STUN FINGERPRINT attribute.
// It must be the last attribute in the message.
type Fingerprint struct {
	// Checksum specifies the ITU V.42 CRC-32 checksum for the
	// message.
	// If Checksum is zero, Marshal method sets an appropriate
	// value.
	Checksum uint32
}

// Len implements the Len method of Attribute interface.
func (fp *Fingerprint) Len() int {
	if fp == nil {
		return 0
	}
	return 4
}

// Marshal implements the Marshal method of Attribute interface.
// Msg must be the STUN message including STUN message header but
// excluding the STUN FINGERPRINT attribute.
func (fp *Fingerprint) Marshal(msg []byte) ([]byte, error) {
	fp.Checksum = crc32.ChecksumIEEE(msg) ^ crc32XOR
	b := make([]byte, roundup(8))
	if err := marshalFingerprintAttr(b, attrFINGERPRINT, fp, nil); err != nil {
		return nil, err
	}
	return b, nil
}

func marshalFingerprintAttr(b []byte, t int, attr Attribute, tid []byte) error {
	if len(b) < 8 {
		return errBufferTooShort
	}
	marshalAttrTypeLen(b, t, 4)
	b[4], b[5], b[6], b[7] = byte(attr.(*Fingerprint).Checksum>>24), byte(attr.(*Fingerprint).Checksum>>16), byte(attr.(*Fingerprint).Checksum>>8), byte(attr.(*Fingerprint).Checksum)
	return nil
}

func parseFingerprintAttr(t, l int, tid, b []byte) (Attribute, error) {
	if len(b) < 4 {
		return nil, errAttributeTooShort
	}
	return &Fingerprint{Checksum: uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])}, nil
}
