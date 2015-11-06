// Copyright 2015 Mikio Hara. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package stun

import (
	"net"
	"reflect"
	"testing"
)

var marshalAndParseAttributeTests = []struct {
	obj  []byte
	tid  []byte
	attr Attribute
}{
	// MAPPED-ADDRESS
	{
		obj: []byte{
			byte(attrMAPPED_ADDRESS >> 8), byte(attrMAPPED_ADDRESS), 0, 4 + net.IPv4len,
			0x00, 0x01, 0xbe, 0xef,
			0xc0, 0xa8, 0x00, 0x01,
		},
		attr: &MappedAddr{
			Family: 1,
			Port:   0xbeef,
			IP:     net.IPv4(192, 168, 0, 1),
		},
	},
	{
		obj: []byte{
			byte(attrMAPPED_ADDRESS >> 8), byte(attrMAPPED_ADDRESS), 0, 4 + net.IPv6len,
			0x00, 0x02, 0xbe, 0xef,
			0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x01,
		},
		attr: &MappedAddr{
			Family: 2,
			Port:   0xbeef,
			IP:     net.IPv6loopback,
		},
	},

	// ERROR-CODE
	{
		obj: []byte{
			byte(attrERROR_CODE >> 8), byte(attrERROR_CODE), 0, 15,
			0x00, 0x00, 4, 38,
			'S', 't', 'a', 'l',
			'e', ' ', 'N', 'o',
			'n', 'c', 'e', 0x00,
		},
		attr: &ErrorCode{
			Code:   StatusStaleNonce,
			Reason: "Stale Nonce",
		},
	},

	// UNKNOWN-ATTRIBUTES
	{
		obj: []byte{
			byte(attrUNKNOWN_ATTRIBUTES >> 8), byte(attrUNKNOWN_ATTRIBUTES), 0, 6,
			0x00, 0x01, 0x00, 0x03,
			0x00, 0x06, 0x00, 0x00,
		},
		attr: &UnknownAttrs{
			Types: []int{attrMAPPED_ADDRESS, attrCHANGE_REQUEST, attrUSERNAME},
		},
	},

	// XOR-MAPPED-ADDRESS
	{
		obj: []byte{
			byte(attrXOR_MAPPED_ADDRESS >> 8), byte(attrXOR_MAPPED_ADDRESS), 0, 4 + net.IPv4len,
			0x00, 0x01, 0xff, 0x64,
			0x4b, 0xae, 0x8a, 0x5a,
		},
		tid: []byte{0x23, 0xbe, 0xf8, 0xbd, 0xc5, 0x50, 0xea, 0x5d, 0x5b, 0xe1, 0xa7, 0xdc},
		attr: &XORMappedAddr{
			Family: 1,
			Port:   56950,
			IP:     net.IPv4(106, 188, 46, 24),
		},
	},

	// SOFTWARE
	{
		obj: []byte{
			byte(attrSOFTWARE >> 8), byte(attrSOFTWARE & 0xff), 0, 14,
			'S', 'o', 'f', 't',
			'w', 'a', 'r', 'e',
			' ', 'D', 'e', 's',
			'c', 'r', 0x00, 0x00,
		},
		attr: &DefaultAttribute{
			Type: attrSOFTWARE,
			Data: []byte("Software Descr"),
		},
	},
}

func TestMarshalAndParseAttribute(t *testing.T) {
	for i, tt := range marshalAndParseAttributeTests {
		b, err := tt.attr.Marshal(tt.tid)
		if err != nil {
			t.Errorf("#%d: %v", i, err)
			continue
		}
		if !reflect.DeepEqual(b, tt.obj) {
			t.Errorf("#%d: got %#v; want %#v", i, b, tt.obj)
			continue
		}
		attrs, err := parseAttributes(tt.tid, b)
		if err != nil {
			t.Errorf("#%d: %v", i, err)
			continue
		}
		if !reflect.DeepEqual(attrs, []Attribute{tt.attr}) {
			t.Errorf("#%d: got %#v; want %#v", i, attrs[0], tt.attr)
			continue
		}
	}
}
