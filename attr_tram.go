// Copyright 2015 Mikio Hara. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package stun

// An Origin represents a STUN ORIGIN attribute.
type Origin string

// Len implements the Len method of Attribute interface.
func (o Origin) Len() int {
	return len(o)
}
