// Copyright 2015 Mikio Hara. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package stun_test

import (
	"bytes"
	"fmt"
	"log"
	"net"
	"time"

	"github.com/mikioh/stun"
)

func Example_clientUDP() {
	var err error
	var dst net.Addr
	for _, server := range []string{
		"stun.l.google.com:19302",
		"stun1.l.google.com:19302",
		"stun2.l.google.com:19302",
		"stun3.l.google.com:19302",
		"stun4.l.google.com:19302",
	} {
		dst, err = net.ResolveUDPAddr("udp", server)
		if err != nil {
			continue
		}
	}
	if dst == nil {
		log.Fatal("STUN server not found")
	}

	c, err := net.ListenPacket("udp", ":0")
	if err != nil {
		log.Fatal(err)
	}
	defer c.Close()

	tid, err := stun.TransactionID()
	if err != nil {
		log.Fatal(err)
	}
	wm := stun.Message{
		Type:  stun.MessageType(stun.ClassRequest, stun.MethodBinding),
		TID:   tid,
		Attrs: []stun.Attribute{&stun.Fingerprint{}},
	}
	wb, err := wm.Marshal()
	if err != nil {
		log.Fatal(err)
	}
	if _, err := c.WriteTo(wb, dst); err != nil {
		log.Fatal(err)
	}

	rb := make([]byte, 1500)
	if err := c.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		log.Fatal(err)
	}
	n, _, err := c.ReadFrom(rb)
	if err != nil {
		log.Fatal(err)
	}
	rm, err := stun.ParseMessage(rb[:n])
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(rm.Type.Class())
	fmt.Println(rm.Type.Method())
	if !bytes.Equal(rm.Cookie, stun.MagicCookie) {
		log.Fatalf("got %#v; want %#v", rm.Cookie, stun.MagicCookie)
	}
	if !bytes.Equal(rm.TID, wm.TID) {
		log.Fatalf("got %#v; want %#v", rm.TID, wm.TID)
	}
	var addrAttrs []stun.Attribute
	for _, attr := range rm.Attrs {
		switch attr.(type) {
		case *stun.MappedAddr, *stun.XORMappedAddr:
			addrAttrs = append(addrAttrs, attr)
		}
	}
	if len(addrAttrs) == 0 {
		log.Fatal("got no binding attribute")
	}
	// Output:
	// success response
	// binding
}
