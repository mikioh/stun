// Copyright 2015 Mikio Hara. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package stun_test

import (
	"net"
	"reflect"
	"testing"

	"github.com/mikioh/stun"
)

var typeClassMethodTests = []struct {
	in stun.Type
	c  stun.Class
	m  stun.Method
}{
	{0x0001, stun.ClassRequest, stun.MethodBinding},
	{0x0011, stun.ClassIndication, stun.MethodBinding},
	{0x0101, stun.ClassSuccessResponse, stun.MethodBinding},
	{0x0111, stun.ClassErrorResponse, stun.MethodBinding},

	{0x3eef, stun.ClassRequest, 0xfff},
	{0x3eff, stun.ClassIndication, 0xfff},
	{0x3fef, stun.ClassSuccessResponse, 0xfff},
	{0x3fff, stun.ClassErrorResponse, 0xfff},
}

func TestTypeClassMethod(t *testing.T) {
	for i, tt := range typeClassMethodTests {
		c := tt.in.Class()
		if c != tt.c {
			t.Errorf("#%d: got %v; want %v", i, c, tt.c)
		}
		m := tt.in.Method()
		if m != tt.m {
			t.Errorf("#%d: got %v; want %#x", i, m, uint16(tt.m))
		}
		out := stun.MessageType(c, m)
		if out != tt.in {
			t.Errorf("#%d: got %#x; want %#x", i, uint16(out), uint16(tt.in))
		}
	}
}

var marshalAndParseMessageTests = []struct {
	wire []byte
	m    *stun.Message
}{
	// XOR-MAPPED-ADDRESS
	{
		wire: []byte{
			0x00, 0x01, 0x00, 0x08,
			0x21, 0x12, 0xa4, 0x42,
			0x37, 0xc8, 0xa9, 0x9f,
			0x35, 0x5b, 0xa9, 0x70,
			0x00, 0x68, 0xbd, 0x79,
			0x80, 0x28, 0x00, 0x04,
			0x9c, 0x58, 0x84, 0xf4,
		},
		m: &stun.Message{
			Type:   stun.MessageType(stun.ClassRequest, stun.MethodBinding),
			Cookie: stun.MagicCookie,
			TID:    []byte{0x37, 0xc8, 0xa9, 0x9f, 0x35, 0x5b, 0xa9, 0x70, 0x00, 0x68, 0xbd, 0x79},
			Attrs: []stun.Attribute{
				&stun.Fingerprint{
					Checksum: 0x9c5884f4,
				},
			},
		},
	},
	{
		wire: []byte{
			0x01, 0x01, 0x00, 0xc,
			0x21, 0x12, 0xa4, 0x42,
			0x83, 0xc7, 0xc2, 0xbc,
			0x8a, 0xc4, 0xb6, 0x9d,
			0x7f, 0x2b, 0x5e, 0xde,
			0x00, 0x20, 0x00, 0x08,
			0x00, 0x01, 0xe6, 0x68,
			0xe1, 0xba, 0xa4, 0x43,
		},
		m: &stun.Message{
			Type:   stun.MessageType(stun.ClassSuccessResponse, stun.MethodBinding),
			Cookie: stun.MagicCookie,
			TID:    []byte{0x83, 0xc7, 0xc2, 0xbc, 0x8a, 0xc4, 0xb6, 0x9d, 0x7f, 0x2b, 0x5e, 0xde},
			Attrs: []stun.Attribute{
				&stun.XORMappedAddr{
					Family: 1,
					Port:   51066,
					IP:     net.IPv4(192, 168, 0, 1),
				},
			},
		},
	},
}

func TestMarshalAndParseMessage(t *testing.T) {
	for i, tt := range marshalAndParseMessageTests {
		b, err := tt.m.Marshal()
		if err != nil {
			t.Errorf("#%d: %v", i, err)
			continue
		}
		if !reflect.DeepEqual(b, tt.wire) {
			t.Errorf("#%d: got %#v; want %#v", i, b, tt.wire)
			continue
		}
		m, err := stun.ParseMessage(tt.wire)
		if err != nil {
			t.Errorf("#%d: %v", i, err)
			continue
		}
		if !reflect.DeepEqual(m, tt.m) {
			t.Errorf("#%d: got %#v; want %#v", i, m, tt.m)
			continue
		}
	}
}
