// Copyright 2015 Mikio Hara. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package stun

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"reflect"
	"testing"
	"time"
)

func TestParseFuzzAttribute(t *testing.T) {
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
		if _, _, err := parseAttrs(b, attrTestTID); err != nil {
			fmt.Fprintf(ioutil.Discard, "%v", err)
		}
	}
}

var attrTestTID = []byte{0x23, 0xbe, 0xf8, 0xbd, 0xc5, 0x50, 0xea, 0x5d, 0x5b, 0xe1, 0xa7, 0xdc}

func attrWireFormat(t, l int, b []byte) []byte {
	b = append(make([]byte, 4), b...)
	binary.BigEndian.PutUint16(b[:2], uint16(t))
	binary.BigEndian.PutUint16(b[2:4], uint16(l))
	return b
}

var marshalAndParseAttributeTests = []struct {
	wire []byte
	attr Attribute
}{
	// MAPPED-ADDRESS
	{
		wire: attrWireFormat(attrMAPPED_ADDRESS, 4+net.IPv4len,
			[]byte{
				0x00, 0x01, 0xbe, 0xef,
				0xc0, 0xa8, 0x00, 0x01,
			}),
		attr: &DefaultAttr{
			Type: attrMAPPED_ADDRESS,
			Data: []byte{0x00, 0x01, 0xbe, 0xef, 0xc0, 0xa8, 0x00, 0x01},
		},
	},

	// CHANGE-REQUEST
	{
		wire: attrWireFormat(attrCHANGE_REQUEST, 4,
			[]byte{
				0x00, 0x00, 0x0, 0x06,
			}),
		attr: &DefaultAttr{
			Type: attrCHANGE_REQUEST,
			Data: []byte{0x00, 0x00, 0x0, 0x06},
		},
	},

	// USERNAME
	{
		wire: attrWireFormat(attrUSERNAME, 11,
			[]byte{
				'F', 'o', 'o', ' ',
				'B', 'a', 'r', ' ',
				'B', 'a', 'z', 0x00,
			}),
		attr: Username("Foo Bar Baz"),
	},

	// MESSAGE-INTEGRITY
	{
		wire: attrWireFormat(attrMESSAGE_INTEGRITY, 20,
			[]byte{
				0x01, 0x23, 0x45, 0x67,
				0x89, 0xab, 0xcd, 0xef,
				0x01, 0x23, 0x45, 0x67,
				0x89, 0xab, 0xcd, 0xef,
				0xde, 0xad, 0xbe, 0xef,
			}),
		attr: MessageIntegrity{0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xde, 0xad, 0xbe, 0xef},
	},

	// MESSAGE-INTEGRITY-SHA256
	{
		wire: attrWireFormat(attrMESSAGE_INTEGRITY_SHA256, 32,
			[]byte{
				0x01, 0x23, 0x45, 0x67,
				0x89, 0xab, 0xcd, 0xef,
				0x01, 0x23, 0x45, 0x67,
				0x89, 0xab, 0xcd, 0xef,
				0x01, 0x23, 0x45, 0x67,
				0x89, 0xab, 0xcd, 0xef,
				0x01, 0x23, 0x45, 0x67,
				0xde, 0xad, 0xbe, 0xef,
			}),
		attr: MessageIntegritySHA256{0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0xde, 0xad, 0xbe, 0xef},
	},

	// ERROR-CODE
	{
		wire: attrWireFormat(attrERROR_CODE, 15,
			[]byte{
				0x00, 0x00, 4, 38,
				'S', 't', 'a', 'l',
				'e', ' ', 'N', 'o',
				'n', 'c', 'e', 0x00,
			}),
		attr: &Error{
			Code:   StatusStaleNonce,
			Reason: "Stale Nonce",
		},
	},

	// UNKNOWN-ATTRIBUTES
	{
		wire: attrWireFormat(attrUNKNOWN_ATTRIBUTES, 6,
			[]byte{
				0x00, 0x01, 0x00, 0x03,
				0x00, 0x06, 0x00, 0x00,
			}),
		attr: UnknownAttrs([]int{attrMAPPED_ADDRESS, attrCHANGE_REQUEST, attrUSERNAME}),
	},

	// CHANNEL-NUMBER
	{
		wire: attrWireFormat(attrCHANNEL_NUMBER, 4,
			[]byte{
				0x7f, 0xff, 0x00, 0x00,
			}),
		attr: &ChannelNumber{Number: 0x7fff},
	},

	// LIFETIME
	{
		wire: attrWireFormat(attrLIFETIME, 4,
			[]byte{
				0x07, 0x5b, 0xcd, 0x15,
			}),
		attr: Lifetime(time.Duration(123456789) * time.Second),
	},

	// XOR-PEER-ADDRESS
	{
		wire: attrWireFormat(attrXOR_PEER_ADDRESS, 4+net.IPv4len,
			[]byte{
				0x00, 0x01, 0xff, 0x64,
				0x4b, 0xae, 0x8a, 0x5a,
			}),
		attr: &XORPeerAddr{
			Port: 56950,
			IP:   net.IPv4(106, 188, 46, 24),
		},
	},

	// DATA
	{
		wire: attrWireFormat(attrDATA, 6,
			[]byte{
				0x12, 0x34, 0x45, 0x67,
				0x89, 0xab, 0x00, 0x00,
			}),
		attr: Data([]byte{0x12, 0x34, 0x45, 0x67, 0x89, 0xab}),
	},

	// REALM
	{
		wire: attrWireFormat(attrREALM, 11,
			[]byte{
				'F', 'o', 'o', ' ',
				'B', 'a', 'r', ' ',
				'B', 'a', 'z', 0x00,
			}),
		attr: Realm("Foo Bar Baz"),
	},

	// NONCE
	{
		wire: attrWireFormat(attrNONCE, 11,
			[]byte{
				'F', 'o', 'o', ' ',
				'B', 'a', 'r', ' ',
				'B', 'a', 'z', 0x00,
			}),
		attr: Nonce("Foo Bar Baz"),
	},

	// XOR-RELAYED-ADDRESS
	{
		wire: attrWireFormat(attrXOR_RELAYED_ADDRESS, 4+net.IPv4len,
			[]byte{
				0x00, 0x01, 0xff, 0x64,
				0x4b, 0xae, 0x8a, 0x5a,
			}),
		attr: &XORRelayedAddr{
			Port: 56950,
			IP:   net.IPv4(106, 188, 46, 24),
		},
	},

	// REQUESTED-ADDRESS-FAMILY
	{
		wire: attrWireFormat(attrREQUESTED_ADDRESS_FAMILY, 4,
			[]byte{
				0x02, 0x00, 0x00, 0x00,
			}),
		attr: &RequestedAddrFamily{ID: 0x02},
	},

	// EVEN-PORT
	{
		wire: attrWireFormat(attrEVEN_PORT, 1,
			[]byte{
				0x80, 0x00, 0x00, 0x00,
			}),
		attr: &EvenPort{R: true},
	},

	// REQUESTED-TRANSPORT
	{
		wire: attrWireFormat(attrREQUESTED_TRANSPORT, 4,
			[]byte{
				0x11, 0x00, 0x00, 0x00,
			}),
		attr: &RequestedTransport{Protocol: 17},
	},

	// DONT-FRAGMENT
	{
		wire: attrWireFormat(attrDONT_FRAGMENT, 0, nil),
		attr: &DontFragment{},
	},

	// XOR-MAPPED-ADDRESS
	{
		wire: attrWireFormat(attrXOR_MAPPED_ADDRESS, 4+net.IPv4len,
			[]byte{
				0x00, 0x01, 0xff, 0x64,
				0x4b, 0xae, 0x8a, 0x5a,
			}),
		attr: &XORMappedAddr{
			Port: 56950,
			IP:   net.IPv4(106, 188, 46, 24),
		},
	},

	// RESERVATION-TOKEN
	{
		wire: attrWireFormat(attrRESERVATION_TOKEN, 8,
			[]byte{
				0x12, 0x34, 0x45, 0x67,
				0x89, 0xab, 0xcd, 0xef,
			}),
		attr: ReservationToken([]byte{0x12, 0x34, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef}),
	},

	// PRIORITY
	{
		wire: attrWireFormat(attrPRIORITY, 4,
			[]byte{
				0x12, 0x34, 0x56, 0x78,
			}),
		attr: Priority(0x12345678),
	},

	// USE-CANDIDATE
	{
		wire: attrWireFormat(attrUSE_CANDIDATE, 0, nil),
		attr: &UseCandidate{},
	},

	// CONNECTION-ID
	{
		wire: attrWireFormat(attrCONNECTION_ID, 4,
			[]byte{
				0x12, 0x34, 0x56, 0x78,
			}),
		attr: ConnectionID(0x12345678),
	},

	// SOFTWARE
	{
		wire: attrWireFormat(attrSOFTWARE, 14,
			[]byte{
				'S', 'o', 'f', 't',
				'w', 'a', 'r', 'e',
				' ', 'D', 'e', 's',
				'c', 'r', 0x00, 0x00,
			}),
		attr: Software("Software Descr"),
	},

	// ALTERNATE-SERVER
	{
		wire: attrWireFormat(attrALTERNATE_SERVER, 4+net.IPv4len,
			[]byte{
				0x00, 0x01, 0xbe, 0xef,
				0xc0, 0xa8, 0x00, 0x01,
			}),
		attr: &AlternateServer{
			Port: 0xbeef,
			IP:   net.IPv4(192, 168, 0, 1),
		},
	},

	// FINGERPRINT
	{
		wire: attrWireFormat(attrFINGERPRINT, 4,
			[]byte{
				0x12, 0x34, 0x56, 0x78,
			}),
		attr: Fingerprint(0x12345678),
	},

	// ICE-CONTROLLED
	{
		wire: attrWireFormat(attrICE_CONTROLLED, 8,
			[]byte{
				0x12, 0x34, 0x56, 0x78,
				0xde, 0xad, 0xbe, 0xef,
			}),
		attr: ICEControlled(0x12345678deadbeef),
	},

	// ICE-CONTROLLING
	{
		wire: attrWireFormat(attrICE_CONTROLLING, 8,
			[]byte{
				0x12, 0x34, 0x56, 0x78,
				0xde, 0xad, 0xbe, 0xef,
			}),
		attr: ICEControlling(0x12345678deadbeef),
	},

	// ECN-CHECK
	{
		wire: attrWireFormat(attrECN_CHECK_STUN, 4,
			[]byte{
				0x00, 0x00, 0x00, 0x05,
			}),
		attr: &ECNCheck{ECF: 0x02, V: true},
	},

	// PASSWORD-ALGOIRTHMS
	{
		wire: attrWireFormat(attrPASSWORD_ALGORITHMS, 20,
			[]byte{
				0x00, 0x01, 0x00, 0x05,
				0x01, 0x23, 0x45, 0x67,
				0x89, 0x00, 0x00, 0x00,
				0x00, 0x02, 0x00, 0x03,
				0x01, 0x23, 0x45, 0x00,
			}),
		attr: PasswordAlgorithms{
			PasswordAlgorithm{Number: 0x0001, Params: []byte{0x01, 0x23, 0x45, 0x67, 0x89}},
			PasswordAlgorithm{Number: 0x0002, Params: []byte{0x01, 0x23, 0x45}},
		},
	},
	{
		wire: attrWireFormat(attrPASSWORD_ALGORITHMS, 0, nil),
		attr: PasswordAlgorithms(nil),
	},

	// PASSWORD-ALGOIRTHM
	{
		wire: attrWireFormat(attrPASSWORD_ALGORITHM, 9,
			[]byte{
				0x00, 0x01, 0x00, 0x05,
				0x01, 0x23, 0x45, 0x67,
				0x89, 0x00, 0x00, 0x00,
			}),
		attr: &PasswordAlgorithm{Number: 0x0001, Params: []byte{0x01, 0x23, 0x45, 0x67, 0x89}},
	},

	// ALTERNATE-DOMAIN
	{
		wire: attrWireFormat(attrALTERNATE_DOMAIN, 11,
			[]byte{
				'e', 'x', 'a', 'm',
				'p', 'l', 'e', '.',
				'o', 'r', 'g', 0x00,
			}),
		attr: AlternateDomain("example.org"),
	},

	// ORIGIN
	{
		wire: attrWireFormat(attrORIGIN, 21,
			[]byte{
				'h', 't', 't', 'p',
				':', '/', '/', 'l',
				'o', 'c', 'a', 'l',
				'h', 'o', 's', 't',
				':', '8', '0', '8',
				'0', 0x00, 0x00, 0x00,
			}),
		attr: Origin("http://localhost:8080"),
	},
}

func TestMarshalAndParseAttribute(t *testing.T) {
	var allAttrs []Attribute
	for i, tt := range marshalAndParseAttributeTests {
		b := make([]byte, 256)
		m := Control{Attrs: []Attribute{tt.attr}}
		if _, err := marshalAttrs(b, &m); err != nil {
			t.Errorf("#%d: %v", i, err)
			continue
		}
		l := roundup(4 + tt.attr.Len())
		b = b[controlHeaderLen : controlHeaderLen+l]
		if !reflect.DeepEqual(b, tt.wire) {
			t.Errorf("#%d: got %#v; want %#v", i, b, tt.wire)
			continue
		}
		attrs, _, err := parseAttrs(b, attrTestTID)
		if err != nil {
			t.Errorf("#%d: %v", i, err)
			continue
		}
		if !reflect.DeepEqual(attrs, []Attribute{tt.attr}) {
			t.Errorf("#%d: got %#v; want %#v", i, attrs[0], tt.attr)
			continue
		}
		allAttrs = append(allAttrs, attrs...)
	}
	l := controlHeaderLen
	for _, attr := range allAttrs {
		l += roundup(4 + attr.Len())
	}
	b := make([]byte, l)
	m := Control{Cookie: MagicCookie, TID: attrTestTID, Attrs: allAttrs}
	if _, err := marshalAttrs(b, &m); err != nil {
		t.Error(err)
	}
	if _, _, err := parseAttrs(b[controlHeaderLen:], attrTestTID); err != nil {
		t.Error(err)
	}
}
