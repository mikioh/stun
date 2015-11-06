// Copyright 2015 Mikio Hara. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package stun_test

import (
	"net"
	"testing"

	"github.com/mikioh/stun"
)

func BenchmarkMarshalMessage(b *testing.B) {
	tid, err := stun.TransactionID()
	if err != nil {
		b.Fatal(err)
	}
	m := stun.Message{
		Type: stun.MessageType(stun.ClassSuccessResponse, stun.MethodBinding),
		TID:  tid,
		Attrs: []stun.Attribute{
			&stun.XORMappedAddr{
				Port: 12345,
				IP:   net.IPv4(192, 168, 0, 1),
			},
		},
	}

	for i := 0; i < b.N; i++ {
		if _, err := m.Marshal(); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkParseMessage(b *testing.B) {
	wire := []byte{
		0x01, 0x01, 0x00, 0xc,
		0x21, 0x12, 0xa4, 0x42,
		0x83, 0xc7, 0xc2, 0xbc,
		0x8a, 0xc4, 0xb6, 0x9d,
		0x7f, 0x2b, 0x5e, 0xde,
		0x00, 0x20, 0x00, 0x08,
		0x00, 0x01, 0xe6, 0x68,
		0xe1, 0xba, 0xa4, 0x43,
	}

	for i := 0; i < b.N; i++ {
		if _, err := stun.ParseMessage(wire); err != nil {
			b.Fatal(err)
		}
	}
}
