// Copyright 2015 Mikio Hara. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package stun

// A Username represents a STUN USERNAME attribute.
type Username string

// Len implements the Len method of Attribute interface.
func (u Username) Len() int {
	return len(u)
}

// A Realm represents a STUN REALM attribute.
type Realm string

// Len implements the Len method of Attribute interface.
func (r Realm) Len() int {
	return len(r)
}

// A Nonce represents a STUN NONCE attribute.
type Nonce string

// Len implements the Len method of Attribute interface.
func (n Nonce) Len() int {
	return len(n)
}

// A Software represents a STUN SOFTWARE attribute.
type Software string

// Len implements the Len method of Attribute interface.
func (sw Software) Len() int {
	return len(sw)
}
