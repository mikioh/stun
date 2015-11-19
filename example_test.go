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

func ExampleControl_clientUDP() {
	dst, err := net.ResolveUDPAddr("udp", "stun.l.google.com:19302")
	if err != nil {
		log.Fatal(err)
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
	wm := stun.Control{
		Type: stun.MessageType(stun.ClassRequest, stun.MethodBinding),
		TID:  tid,
		Attrs: []stun.Attribute{
			stun.Software("github.com/mikioh/stun"),
			stun.ICEControlling(1),
			&stun.UseCandidate{},
			stun.Priority(1),
			stun.Fingerprint(0),
		},
	}
	wb := make([]byte, wm.Len())
	n, err := wm.Marshal(wb, nil)
	if err != nil {
		log.Fatal(err)
	}
	if _, err := c.WriteTo(wb[:n], dst); err != nil {
		log.Fatal(err)
	}

	rb := make([]byte, 1500)
	if err := c.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		log.Fatal(err)
	}
	n, _, err = c.ReadFrom(rb)
	if err != nil {
		log.Fatal(err)
	}
	_, rm, err := stun.ParseMessage(rb[:n], nil)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(rm.(*stun.Control).Type.Class())
	fmt.Println(rm.(*stun.Control).Type.Method())
	if !bytes.Equal(rm.(*stun.Control).Cookie, stun.MagicCookie) {
		log.Fatalf("got %#v; want %#v", rm.(*stun.Control).Cookie, stun.MagicCookie)
	}
	if !bytes.Equal(rm.(*stun.Control).TID, wm.TID) {
		log.Fatalf("got %#v; want %#v", rm.(*stun.Control).TID, wm.TID)
	}
	// Output:
	// success response
	// binding
}
