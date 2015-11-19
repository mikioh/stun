// Copyright 2015 Mikio Hara. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package stun_test

import (
	"testing"

	"github.com/mikioh/stun"
)

var (
	rfc5769ShortTermAuthHash                = shortTermAuth("", "", "VOkJxbRl1RmTxUk/WvJxBt")
	rfc5769LongTermAuthHash                 = longTermAuth("\u30de\u30c8\u30ea\u30c3\u30af\u30b9", "example.org", "TheMatrIX")
	rfc5769LongTermAuthMessage stun.Message = &stun.Control{
		Type:   stun.MessageType(stun.ClassRequest, stun.MethodBinding),
		Cookie: stun.MagicCookie,
		TID:    []byte("\x78\xad\x34\x33\xc6\xad\x72\xc0\x29\xda\x41\x2e"),
		Attrs: []stun.Attribute{
			stun.Username("\u30de\u30c8\u30ea\u30c3\u30af\u30b9"),
			stun.Nonce("f//499k954d6OL34oL9FSTvy64sA"),
			stun.Realm("example.org"),
			stun.MessageIntegrity("\xf6\x70\x24\x65\x6d\xd6\x4a\x3e\x02\xb8\xe0\x71" +
				"\x2e\x85\xc9\xa2\x8c\xa8\x96\x66"),
		},
	}
	rfc5769LongTermAuthWire = []byte("\x00\x01\x00\x60" +
		"\x21\x12\xa4\x42" +
		"\x78\xad\x34\x33\xc6\xad\x72\xc0\x29\xda\x41\x2e" +
		"\x00\x06\x00\x12" +
		"\xe3\x83\x9e\xe3\x83\x88\xe3\x83\xaa\xe3\x83\x83" +
		"\xe3\x82\xaf\xe3\x82\xb9\x00\x00" +
		"\x00\x15\x00\x1c" +
		"\x66\x2f\x2f\x34\x39\x39\x6b\x39\x35\x34\x64\x36" +
		"\x4f\x4c\x33\x34\x6f\x4c\x39\x46\x53\x54\x76\x79" +
		"\x36\x34\x73\x41" +
		"\x00\x14\x00\x0b" +
		"\x65\x78\x61\x6d\x70\x6c\x65\x2e\x6f\x72\x67\x00" +
		"\x00\x08\x00\x14" +
		"\xf6\x70\x24\x65\x6d\xd6\x4a\x3e\x02\xb8\xe0\x71" +
		"\x2e\x85\xc9\xa2\x8c\xa8\x96\x66")
)

func BenchmarkMarshalRFC5769LongTermAuthMessage(b *testing.B) {
	wb := make([]byte, rfc5769LongTermAuthMessage.Len())
	for i := 0; i < b.N; i++ {
		if _, err := rfc5769LongTermAuthMessage.Marshal(wb, rfc5769LongTermAuthHash); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkParseRFC5769LongTermAuthMessage(b *testing.B) {
	for i := 0; i < b.N; i++ {
		if _, _, err := stun.ParseMessage(rfc5769LongTermAuthWire, rfc5769LongTermAuthHash); err != nil {
			b.Fatal(err)
		}
	}
}
