// Copyright 2015 Mikio Hara. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package stun

import "crypto/sha1"

// A MessageIntegrity represents a STUN MESSAGE-INTEGRITY attribute.
// If MessageIntegrity is nil, Marshal method of Message interface
// sets an approrpiate value.
type MessageIntegrity []byte

// Len implements the Len method of Attribute interface.
func (_ MessageIntegrity) Len() int {
	return sha1.Size
}

const crc32XOR = 0x5354554e // see RFC 5389

// A Fingerprint represents a STUN FINGERPRINT attribute.
// It must be the last attribute in the message.
// If Fingerprint is zero, Marshal method of Message interface sets an
// appropriate value.
type Fingerprint uint

// Len implements the Len method of Attribute interface.
func (_ Fingerprint) Len() int {
	return 4
}
