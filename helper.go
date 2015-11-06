// Copyright 2015 Mikio Hara. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package stun

import (
	"crypto/rand"
	"io"
)

const align = 4

func roundup(n int) int {
	return (n + align - 1) & ^(align - 1)
}

// TransactionID returns a 96-bit random identifier.
func TransactionID() ([]byte, error) {
	b := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return nil, err
	}
	return b, nil
}
