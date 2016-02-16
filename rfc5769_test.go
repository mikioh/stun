// Copyright 2015 Mikio Hara. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package stun_test

import (
	"bytes"
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"hash"
	"net"
	"reflect"
	"testing"

	"github.com/mikioh/stun"
)

func shortTermAuth(username, realm, password string) hash.Hash {
	return hmac.New(sha1.New, []byte(password)) // implement PRECIS defined in RFC 7613
}

func longTermAuth(username, realm, password string, hash func() hash.Hash) hash.Hash {
	key := username + ":" + realm + ":" + password // implement PRECIS defined in RFC 7613
	h := md5.New()
	h.Write([]byte(key))
	return hmac.New(hash, h.Sum(nil))
}

type rfc5769Test struct {
	raw, msg          stun.Message
	hash              hash.Hash
	whiteSpacePadding bool
	wire              string
}

var rfc5769Tests = []rfc5769Test{
	// 2.1. Sample Request
	{
		raw: &stun.Control{
			Type:   stun.MessageType(stun.ClassRequest, stun.MethodBinding),
			Cookie: stun.MagicCookie,
			TID:    []byte("\xb7\xe7\xa7\x01\xbc\x34\xd6\x86\xfa\x87\xdf\xae"),
			Attrs: []stun.Attribute{
				stun.Software("STUN test client"),
				stun.Priority(0x6e0001ff),
				stun.ICEControlled(0x932ff9b151263b36),
				stun.Username("evtj:h6vY"),
				stun.MessageIntegrity{},
				stun.Fingerprint(0),
			},
		},
		msg: &stun.Control{
			Type:   stun.MessageType(stun.ClassRequest, stun.MethodBinding),
			Cookie: stun.MagicCookie,
			TID:    []byte("\xb7\xe7\xa7\x01\xbc\x34\xd6\x86\xfa\x87\xdf\xae"),
			Attrs: []stun.Attribute{
				stun.Software("STUN test client"),
				stun.Priority(0x6e0001ff),
				stun.ICEControlled(0x932ff9b151263b36),
				stun.Username("evtj:h6vY"),
				stun.MessageIntegrity("\x9a\xea\xa7\x0c\xbf\xd8\xcb\x56\x78\x1e\xf2\xb5\xb2\xd3\xf2\x49\xc1\xb5\x71\xa2"),
				stun.Fingerprint(0xe57a3bcf),
			},
		},
		hash:              shortTermAuth("", "", "VOkJxbRl1RmTxUk/WvJxBt"),
		whiteSpacePadding: true,
		wire: "\x00\x01\x00\x58" +
			"\x21\x12\xa4\x42" +
			"\xb7\xe7\xa7\x01\xbc\x34\xd6\x86\xfa\x87\xdf\xae" +
			"\x80\x22\x00\x10" +
			"STUN test client" +
			"\x00\x24\x00\x04" +
			"\x6e\x00\x01\xff" +
			"\x80\x29\x00\x08" +
			"\x93\x2f\xf9\xb1\x51\x26\x3b\x36" +
			"\x00\x06\x00\x09" +
			"\x65\x76\x74\x6a\x3a\x68\x36\x76\x59\x20\x20\x20" +
			"\x00\x08\x00\x14" +
			"\x9a\xea\xa7\x0c\xbf\xd8\xcb\x56\x78\x1e\xf2\xb5\xb2\xd3\xf2\x49\xc1\xb5\x71\xa2" +
			"\x80\x28\x00\x04" +
			"\xe5\x7a\x3b\xcf",
	},

	//  2.2. Sample IPv4 Response
	{
		raw: &stun.Control{
			Type:   stun.MessageType(stun.ClassSuccessResponse, stun.MethodBinding),
			Cookie: stun.MagicCookie,
			TID:    []byte("\xb7\xe7\xa7\x01\xbc\x34\xd6\x86\xfa\x87\xdf\xae"),
			Attrs: []stun.Attribute{
				stun.Software("test vector"),
				&stun.XORMappedAddr{
					Port: 32853,
					IP:   net.IPv4(192, 0, 2, 1),
				},
				stun.MessageIntegrity{},
				stun.Fingerprint(0),
			},
		},
		msg: &stun.Control{
			Type:   stun.MessageType(stun.ClassSuccessResponse, stun.MethodBinding),
			Cookie: stun.MagicCookie,
			TID:    []byte("\xb7\xe7\xa7\x01\xbc\x34\xd6\x86\xfa\x87\xdf\xae"),
			Attrs: []stun.Attribute{
				stun.Software("test vector"),
				&stun.XORMappedAddr{
					Port: 32853,
					IP:   net.IPv4(192, 0, 2, 1),
				},
				stun.MessageIntegrity("\x2b\x91\xf5\x99\xfd\x9e\x90\xc3\x8c\x74\x89\xf9\x2a\xf9\xba\x53\xf0\x6b\xe7\xd7"),
				stun.Fingerprint(0xc07d4c96),
			},
		},
		hash:              shortTermAuth("", "", "VOkJxbRl1RmTxUk/WvJxBt"),
		whiteSpacePadding: true,
		wire: "\x01\x01\x00\x3c" +
			"\x21\x12\xa4\x42" +
			"\xb7\xe7\xa7\x01\xbc\x34\xd6\x86\xfa\x87\xdf\xae" +
			"\x80\x22\x00\x0b" +
			"\x74\x65\x73\x74\x20\x76\x65\x63\x74\x6f\x72\x20" +
			"\x00\x20\x00\x08" +
			"\x00\x01\xa1\x47\xe1\x12\xa6\x43" +
			"\x00\x08\x00\x14" +
			"\x2b\x91\xf5\x99\xfd\x9e\x90\xc3\x8c\x74\x89\xf9\x2a\xf9\xba\x53\xf0\x6b\xe7\xd7" +
			"\x80\x28\x00\x04" +
			"\xc0\x7d\x4c\x96",
	},

	//  2.3. Sample IPv6 Response
	{
		raw: &stun.Control{
			Type:   stun.MessageType(stun.ClassSuccessResponse, stun.MethodBinding),
			Cookie: stun.MagicCookie,
			TID:    []byte("\xb7\xe7\xa7\x01\xbc\x34\xd6\x86\xfa\x87\xdf\xae"),
			Attrs: []stun.Attribute{
				stun.Software("test vector"),
				&stun.XORMappedAddr{
					Port: 32853,
					IP:   net.ParseIP("2001:db8:1234:5678:11:2233:4455:6677"),
				},
				stun.MessageIntegrity{},
				stun.Fingerprint(0),
			},
		},
		msg: &stun.Control{
			Type:   stun.MessageType(stun.ClassSuccessResponse, stun.MethodBinding),
			Cookie: stun.MagicCookie,
			TID:    []byte("\xb7\xe7\xa7\x01\xbc\x34\xd6\x86\xfa\x87\xdf\xae"),
			Attrs: []stun.Attribute{
				stun.Software("test vector"),
				&stun.XORMappedAddr{
					Port: 32853,
					IP:   net.ParseIP("2001:db8:1234:5678:11:2233:4455:6677"),
				},
				stun.MessageIntegrity("\xa3\x82\x95\x4e\x4b\xe6\x7b\xf1\x17\x84\xc9\x7c\x82\x92\xc2\x75\xbf\xe3\xed\x41"),
				stun.Fingerprint(0xc8fb0b4c),
			},
		},
		hash:              shortTermAuth("", "", "VOkJxbRl1RmTxUk/WvJxBt"),
		whiteSpacePadding: true,
		wire: "\x01\x01\x00\x48" +
			"\x21\x12\xa4\x42" +
			"\xb7\xe7\xa7\x01\xbc\x34\xd6\x86\xfa\x87\xdf\xae" +
			"\x80\x22\x00\x0b" +
			"\x74\x65\x73\x74\x20\x76\x65\x63\x74\x6f\x72\x20" +
			"\x00\x20\x00\x14" +
			"\x00\x02\xa1\x47" +
			"\x01\x13\xa9\xfa\xa5\xd3\xf1\x79\xbc\x25\xf4\xb5\xbe\xd2\xb9\xd9" +
			"\x00\x08\x00\x14" +
			"\xa3\x82\x95\x4e\x4b\xe6\x7b\xf1\x17\x84\xc9\x7c\x82\x92\xc2\x75\xbf\xe3\xed\x41" +
			"\x80\x28\x00\x04" +
			"\xc8\xfb\x0b\x4c",
	},

	//  2.4. Sample Request with Long-Term Authentication
	{
		raw: &stun.Control{
			Type:   stun.MessageType(stun.ClassRequest, stun.MethodBinding),
			Cookie: stun.MagicCookie,
			TID:    []byte("\x78\xad\x34\x33\xc6\xad\x72\xc0\x29\xda\x41\x2e"),
			Attrs: []stun.Attribute{
				stun.Username("\u30de\u30c8\u30ea\u30c3\u30af\u30b9"),
				stun.Nonce("f//499k954d6OL34oL9FSTvy64sA"),
				stun.Realm("example.org"),
				stun.MessageIntegrity{},
			},
		},
		msg: &stun.Control{
			Type:   stun.MessageType(stun.ClassRequest, stun.MethodBinding),
			Cookie: stun.MagicCookie,
			TID:    []byte("\x78\xad\x34\x33\xc6\xad\x72\xc0\x29\xda\x41\x2e"),
			Attrs: []stun.Attribute{
				stun.Username("\u30de\u30c8\u30ea\u30c3\u30af\u30b9"),
				stun.Nonce("f//499k954d6OL34oL9FSTvy64sA"),
				stun.Realm("example.org"),
				stun.MessageIntegrity("\xf6\x70\x24\x65\x6d\xd6\x4a\x3e\x02\xb8\xe0\x71\x2e\x85\xc9\xa2\x8c\xa8\x96\x66"),
			},
		},
		hash: longTermAuth("\u30de\u30c8\u30ea\u30c3\u30af\u30b9", "example.org", "TheMatrIX", sha1.New),
		wire: "\x00\x01\x00\x60" +
			"\x21\x12\xa4\x42" +
			"\x78\xad\x34\x33\xc6\xad\x72\xc0\x29\xda\x41\x2e" +
			"\x00\x06\x00\x12" +
			"\xe3\x83\x9e\xe3\x83\x88\xe3\x83\xaa\xe3\x83\x83\xe3\x82\xaf\xe3\x82\xb9\x00\x00" +
			"\x00\x15\x00\x1c" +
			"\x66\x2f\x2f\x34\x39\x39\x6b\x39\x35\x34\x64\x36\x4f\x4c\x33\x34\x6f\x4c\x39\x46\x53\x54\x76\x79\x36\x34\x73\x41" +
			"\x00\x14\x00\x0b" +
			"\x65\x78\x61\x6d\x70\x6c\x65\x2e\x6f\x72\x67\x00" +
			"\x00\x08\x00\x14" +
			"\xf6\x70\x24\x65\x6d\xd6\x4a\x3e\x02\xb8\xe0\x71\x2e\x85\xc9\xa2\x8c\xa8\x96\x66",
	},

	// TODO: X.X. Sample Request with Long-Term Authentication with MESSAGE-INTEGRITY-SHA256
	{
		raw: &stun.Control{
			Type:   stun.MessageType(stun.ClassRequest, stun.MethodBinding),
			Cookie: stun.MagicCookie,
			TID:    []byte("\x78\xad\x34\x33\xc6\xad\x72\xc0\x29\xda\x41\x2e"),
			Attrs: []stun.Attribute{
				stun.Username("\u30de\u30c8\u30ea\u30c3\u30af\u30b9"),
				stun.Nonce("f//499k954d6OL34oL9FSTvy64sA"),
				stun.Realm("example.org"),
				stun.MessageIntegritySHA256{},
			},
		},
		msg: &stun.Control{
			Type:   stun.MessageType(stun.ClassRequest, stun.MethodBinding),
			Cookie: stun.MagicCookie,
			TID:    []byte("\x78\xad\x34\x33\xc6\xad\x72\xc0\x29\xda\x41\x2e"),
			Attrs: []stun.Attribute{
				stun.Username("\u30de\u30c8\u30ea\u30c3\u30af\u30b9"),
				stun.Nonce("f//499k954d6OL34oL9FSTvy64sA"),
				stun.Realm("example.org"),
				stun.MessageIntegritySHA256("\x33\x0e\x33\x74\x8a\xf3\xd4\xd1\xd2\x83\x08\xbf\xf9\x16\x1c\x88\xb7\xf1\xba\x18\xcb\xc0\x8a\x4f\xfb\xca\x64\x08\xab\x35\x44\x09"),
			},
		},
		hash: longTermAuth("\u30de\u30c8\u30ea\u30c3\u30af\u30b9", "example.org", "TheMatrIX", sha256.New),
		wire: "\x00\x01\x00\x6c" +
			"\x21\x12\xa4\x42" +
			"\x78\xad\x34\x33\xc6\xad\x72\xc0\x29\xda\x41\x2e" +
			"\x00\x06\x00\x12" +
			"\xe3\x83\x9e\xe3\x83\x88\xe3\x83\xaa\xe3\x83\x83\xe3\x82\xaf\xe3\x82\xb9\x00\x00" +
			"\x00\x15\x00\x1c" +
			"\x66\x2f\x2f\x34\x39\x39\x6b\x39\x35\x34\x64\x36\x4f\x4c\x33\x34\x6f\x4c\x39\x46\x53\x54\x76\x79\x36\x34\x73\x41" +
			"\x00\x14\x00\x0b" +
			"\x65\x78\x61\x6d\x70\x6c\x65\x2e\x6f\x72\x67\x00" +
			// TODO: replace with value assigned by IANA
			"\x00\x2b\x00\x20" +
			"\x33\x0e\x33\x74\x8a\xf3\xd4\xd1\xd2\x83\x08\xbf\xf9\x16\x1c\x88\xb7\xf1\xba\x18\xcb\xc0\x8a\x4f\xfb\xca\x64\x08\xab\x35\x44\x09",
	},
}

func TestRFC5769(t *testing.T) {
	for i, tt := range rfc5769Tests {
		wire := make([]byte, len(tt.wire))
		copy(wire, []byte(tt.wire))
		_, m, err := stun.ParseMessage(wire, tt.hash)
		if err != nil {
			t.Errorf("#%d: %v", i, err)
			continue
		}
		if !reflect.DeepEqual(m, tt.msg) {
			t.Errorf("#%d: got %#v; want %#v", i, m, tt.msg)
		}
		if !bytes.Equal(wire, []byte(tt.wire)) {
			t.Errorf("#%d: got %#v; want %#v", i, wire, tt.wire)
		}
		b := make([]byte, 1500)
		n, err := tt.raw.Marshal(b, tt.hash)
		if err != nil {
			t.Error(err)
			continue
		}
		_, m, err = stun.ParseMessage(b[:n], tt.hash)
		if err != nil {
			t.Error(err)
			continue
		}
		if tt.whiteSpacePadding { // we don't use \u0020 for padding
			continue
		}
		if !reflect.DeepEqual(b[:n], wire) {
			t.Errorf("#%d: got %#v; want %#v", i, b, wire)
		}
	}
}
