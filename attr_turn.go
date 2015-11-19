// Copyright 2015 Mikio Hara. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package stun

import (
	"encoding/binary"
	"time"
)

// A ChannelNumber represents a STUN CHANNEL-NUMBER attribute.
type ChannelNumber struct {
	Number Type // channel number
}

// Len implements the Len method of Attribute interface.
func (cn *ChannelNumber) Len() int {
	if cn == nil {
		return 0
	}
	return 4
}

func marshalChannelNumberAttr(b []byte, t int, attr Attribute, _ []byte) error {
	if len(b) < 4+4 {
		return errBufferTooShort
	}
	marshalAttrTypeLen(b, t, 4)
	binary.BigEndian.PutUint16(b[4:6], uint16(attr.(*ChannelNumber).Number))
	return nil
}

func parseChannelNumberAttr(b []byte, min, max int, _ []byte, _, l int) (Attribute, error) {
	if min > l || l > max || len(b) < l {
		return nil, errAttributeTooShort
	}
	return &ChannelNumber{Number: Type(binary.BigEndian.Uint16(b[:2]))}, nil
}

// A Lifetime represents a STUN LIFETIME attribute.
type Lifetime time.Duration

// Len implements the Len method of Attribute interface.
func (_ Lifetime) Len() int {
	return 4
}

// A Data represents a STUN DATA attribute.
// It just refers to the underlying buffer when the returned value
// from ParseMessage.
type Data []byte

// Len implements the Len method of Attribute interface.
func (d Data) Len() int {
	return len(d)
}

// A RequestedAddrFamily represents a STUN REQUESTED-ADDRESS-FAMILY
// attribute.
type RequestedAddrFamily struct {
	ID int // identifier; 0x01 for IPv4, 0x02 for IPv6
}

// Len implements the Len method of Attribute interface.
func (af *RequestedAddrFamily) Len() int {
	if af == nil {
		return 0
	}
	return 4
}

func marshalRequestedAddrFamilyAttr(b []byte, t int, attr Attribute, _ []byte) error {
	if len(b) < 4+4 {
		return errBufferTooShort
	}
	marshalAttrTypeLen(b, t, 4)
	b[4] = byte(attr.(*RequestedAddrFamily).ID)
	return nil
}

func parseRequestedAddrFamilyAttr(b []byte, min, max int, _ []byte, _, l int) (Attribute, error) {
	if min > l || l > max || len(b) < l {
		return nil, errAttributeTooShort
	}
	return &RequestedAddrFamily{ID: int(b[0])}, nil
}

// An EvenPort represents a STUN EVEN-PORT attribute.
type EvenPort struct {
	R bool // request next-higher port number reservation
}

// Len implements the Len method of Attribute interface.
func (ep *EvenPort) Len() int {
	if ep == nil {
		return 0
	}
	return 1
}

func marshalEvenPortAttr(b []byte, t int, attr Attribute, _ []byte) error {
	if len(b) < 4+1 {
		return errBufferTooShort
	}
	marshalAttrTypeLen(b, t, 1)
	if attr.(*EvenPort).R {
		b[4] |= 0x80
	}
	return nil
}

func parseEvenPortAttr(b []byte, min, max int, _ []byte, _, l int) (Attribute, error) {
	if min > l || l > max || len(b) < l {
		return nil, errAttributeTooShort
	}
	var ep EvenPort
	if b[0]&0x80 != 0 {
		ep.R = true
	}
	return &ep, nil
}

// A RequestedTransport represents a STUN REQUESTED-TRANSPORT
// attribute.
type RequestedTransport struct {
	Protocol int // protocol number
}

// Len implements the Len method of Attribute interface.
func (rt *RequestedTransport) Len() int {
	if rt == nil {
		return 0
	}
	return 4
}

func marshalRequestedTransportAttr(b []byte, t int, attr Attribute, _ []byte) error {
	if len(b) < 4+4 {
		return errBufferTooShort
	}
	marshalAttrTypeLen(b, t, 4)
	b[4] = byte(attr.(*RequestedTransport).Protocol)
	return nil
}

func parseRequestedTransportAttr(b []byte, min, max int, _ []byte, _, l int) (Attribute, error) {
	if min > l || l > max || len(b) < l {
		return nil, errAttributeTooShort
	}
	return &RequestedTransport{Protocol: int(b[0])}, nil
}

// A DontFragment represents a STUN DONT-FRAGMENT attribute.
type DontFragment struct{}

// Len implements the Len method of Attribute interface.
func (_ *DontFragment) Len() int {
	return 0
}

func marshalDontFragmentAttr(b []byte, t int, _ Attribute, _ []byte) error {
	if len(b) < 4 {
		return errBufferTooShort
	}
	marshalAttrTypeLen(b, t, 0)
	return nil
}

func parseDontFragmentAttr(_ []byte, _, _ int, _ []byte, _, _ int) (Attribute, error) {
	return &DontFragment{}, nil
}

// A ReservationToken represents a STUN RESERVATION-TOKEN attribute.
type ReservationToken []byte

// Len implements the Len method of Attribute interface.
func (_ ReservationToken) Len() int {
	return 8
}

// A ConnectionID represents a STUN CONNECTION-ID attribute.
type ConnectionID uint

// Len implements the Len method of Attribute interface.
func (_ ConnectionID) Len() int {
	return 4
}
