// Copyright 2015 Mikio Hara. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package stun_test

import (
	"crypto/rand"
	"fmt"
	"io"
	"io/ioutil"
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
			t.Errorf("#%d: got %v; want %v", i, m, tt.m)
		}
		out := stun.MessageType(c, m)
		if out != tt.in {
			t.Errorf("#%d: got %v; want %v", i, out, tt.in)
		}
	}
}

func TestParseFuzzHeader(t *testing.T) {
	defer func() {
		if p := recover(); p != nil {
			t.Fatalf("panicked: %v", p)
		}
	}()

	for i := 0; i < 1500; i++ {
		b := make([]byte, i)
		if _, err := io.ReadFull(rand.Reader, b); err != nil {
			t.Fatal(err)
		}
		if _, _, err := stun.ParseHeader(b); err != nil {
			fmt.Fprintf(ioutil.Discard, "%v", err)
		}
	}
}

func TestParseRandomFuzzMessage(t *testing.T) {
	defer func() {
		if p := recover(); p != nil {
			t.Fatalf("panicked: %v", p)
		}
	}()

	for i := 0; i < 1500; i++ {
		b := make([]byte, i)
		if _, err := io.ReadFull(rand.Reader, b); err != nil {
			t.Fatal(err)
		}
		if _, _, err := stun.ParseMessage(b, nil); err != nil {
			fmt.Fprintf(ioutil.Discard, "%v", err)
		}
	}
}

var parseGoFuzzMessageTests = [][]byte{
	[]byte("00\x00\x100000000000000000\x800\x00\x04000000000000"),
}

func TestParseGoFuzzMessage(t *testing.T) {
	defer func() {
		if p := recover(); p != nil {
			t.Fatalf("panicked: %v", p)
		}
	}()

	for _, tt := range parseGoFuzzMessageTests {
		if _, _, err := stun.ParseMessage(tt, nil); err != nil {
			fmt.Fprintf(ioutil.Discard, "%v", err)
		}
	}
}

var channelDataTests = []rfc5769Test{
	{
		raw: &stun.ChannelData{
			Number: 0x4000,
			Data:   []byte("\xb7\xe7\xa7\x01\xbc\x34\xd6\x86\xfa\x87\xff"),
		},
		wire: "\x40\x00\x00\x0b\xb7\xe7\xa7\x01\xbc\x34\xd6\x86\xfa\x87\xff\x00",
	},
	{
		raw: &stun.ChannelData{
			Number: 0x7fff,
			Data:   []byte("\xff"), // TURN over UDP is not required 4-byte alignment
		},
		wire: "\x7f\xff\x00\x01\xff",
	},
}

func TestMarshalAndParseMessage(t *testing.T) {
	var wire []byte
	tests := append(rfc5769Tests, channelDataTests...)
	for i, tt := range tests {
		b := make([]byte, tt.raw.Len())
		n, err := tt.raw.Marshal(b, tt.hash)
		if err != nil {
			t.Fatalf("#%d: %v", i, err)
		}
		if n%4 != 0 {
			t.Fatalf("#%d: not multiple of 4 bytes: %d", i, n)
		}
		wire = append(wire, b...)
	}
	for i, tt := range tests {
		if _, _, err := stun.ParseHeader(wire); err != nil {
			t.Fatalf("#%d: %v", i, err)
		}
		n, m, err := stun.ParseMessage(wire, tt.hash)
		if err != nil {
			t.Fatalf("#%d: %v", i, err)
		}
		switch m := m.(type) {
		case *stun.Control:
			if n%4 != 0 {
				t.Fatalf("#%d: not multiple of 4 bytes: %d", i, n)
			}
			if n != len(tt.wire) {
				t.Fatalf("#%d: got %d; want %d", i, n, len(tt.wire))
			}
		case *stun.ChannelData:
			if len(tt.wire)%4 == 0 {
				if n%4 != 0 {
					t.Fatalf("#%d: not multiple of 4 bytes: %d", i, n)
				}
				if n != len(tt.wire) {
					t.Fatalf("#%d: got %d; want %d", i, n, len(tt.wire))
				}
			}
			if len(m.Data) != len(tt.raw.(*stun.ChannelData).Data) {
				t.Fatalf("#%d: got %d; want %d", i, len(m.Data), len(tt.raw.(*stun.ChannelData).Data))
			}
		default:
			t.Fatalf("#%d: unknown type: %T", i, m)
		}
		wire = wire[n:]
	}
}
