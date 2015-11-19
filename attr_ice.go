// Copyright 2015 Mikio Hara. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package stun

// A Priority represents a STUN PRIORITY attribute.
type Priority uint

// Len implements the Len method of Attribute interface.
func (_ Priority) Len() int {
	return 4
}

// A UseCandidate reprensents a STUN USE-CANDIDATE attribute.
type UseCandidate struct{}

// Len implements the Len method of Attribute interface.
func (_ *UseCandidate) Len() int {
	return 0
}

func marshalUseCandidateAttr(b []byte, t int, _ Attribute, _ []byte) error {
	if len(b) < 4 {
		return errBufferTooShort
	}
	marshalAttrTypeLen(b, t, 0)
	return nil
}

func parseUseCandidateAttr(_ []byte, _, _ int, _ []byte, _, _ int) (Attribute, error) {
	return &UseCandidate{}, nil
}

// A ICEControlled represents a STUN ICE-CONTROLLED attribute.
type ICEControlled uint64

// Len implements the Len method of Attribute interface.
func (_ ICEControlled) Len() int {
	return 8
}

// A ICEControlling represents a STUN ICE-CONTROLLING attribute.
type ICEControlling uint64

// Len implements the Len method of Attribute interface.
func (_ ICEControlling) Len() int {
	return 8
}
