// Copyright 2015 Mikio Hara. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package stun

import (
	"encoding/binary"
	"net"
)

// An XORPeerAddr represents a STUN XOR-PEER-ADDRESS attribute.
type XORPeerAddr Addr

// Len implements the Len method of Attribute interface.
func (xa *XORPeerAddr) Len() int {
	return addrAttrLen(xa.IP)
}

// An XORRelayedAddr represents a STUN XOR-RELAYED-ADDRESS attribute.
type XORRelayedAddr Addr

// Len implements the Len method of Attribute interface.
func (xa *XORRelayedAddr) Len() int {
	return addrAttrLen(xa.IP)
}

// An XORMappedAddr represents a STUN XOR-MAPPED-ADDRESS attribute.
type XORMappedAddr Addr

// Len implements the Len method of Attribute interface.
func (xa *XORMappedAddr) Len() int {
	return addrAttrLen(xa.IP)
}

// An AlternateServer represents a STUN ALTERNATE-SERVER attribute.
type AlternateServer Addr

// Len implements the Len method of Attribute interface.
func (as *AlternateServer) Len() int {
	return addrAttrLen(as.IP)
}

func addrAttrLen(ip net.IP) int {
	l := 4
	if ip.To4() != nil {
		l += net.IPv4len
	}
	if ip.To16() != nil && ip.To4() == nil {
		l += net.IPv6len
	}
	return l
}

func marshalAddrAttr(b []byte, t int, attr Attribute, tid []byte) error {
	if len(b) < 4+attr.Len() {
		return errBufferTooShort
	}
	var port int
	var ip net.IP
	switch attr := attr.(type) {
	case *XORPeerAddr:
		port = attr.Port
		ip = attr.IP
	case *XORRelayedAddr:
		port = attr.Port
		ip = attr.IP
	case *XORMappedAddr:
		port = attr.Port
		ip = attr.IP
	case *AlternateServer:
		port = attr.Port
		ip = attr.IP
	}
	if ip4 := ip.To4(); ip4 != nil {
		b[5] = 1
		copy(b[8:], ip4)
		switch t {
		case attrXOR_PEER_ADDRESS, attrXOR_RELAYED_ADDRESS, attrXOR_MAPPED_ADDRESS:
			for i := range b[8:12] {
				b[8+i] ^= MagicCookie[i]
			}
		}
	}
	if ip6 := ip.To16(); ip6 != nil && ip6.To4() == nil {
		b[5] = 2
		copy(b[8:], ip6)
		if t == attrXOR_MAPPED_ADDRESS {
			cookie := append(MagicCookie, tid...)
			for i := range b[8:20] {
				b[8+i] ^= cookie[i]
			}
		}
	}
	marshalAttrTypeLen(b, t, attr.Len())
	binary.BigEndian.PutUint16(b[6:8], uint16(port))
	switch t {
	case attrXOR_PEER_ADDRESS, attrXOR_RELAYED_ADDRESS, attrXOR_MAPPED_ADDRESS:
		b[6] ^= MagicCookie[0]
		b[7] ^= MagicCookie[1]
	}
	return nil
}

func parseAddrAttr(b []byte, _, _ int, tid []byte, t, l int) (Attribute, error) {
	if l-4 != net.IPv4len && l-4 != net.IPv6len {
		return nil, errAttributeTooShort
	}
	switch t {
	case attrXOR_PEER_ADDRESS:
		xa := XORPeerAddr{Port: int(binary.BigEndian.Uint16(b[2:4])), IP: make(net.IP, l-4)}
		copy(xa.IP, b[4:l])
		xa.Port, xa.IP = parseXORPortAddr(tid, xa.Port, xa.IP)
		return &xa, nil
	case attrXOR_RELAYED_ADDRESS:
		xa := XORRelayedAddr{Port: int(binary.BigEndian.Uint16(b[2:4])), IP: make(net.IP, l-4)}
		copy(xa.IP, b[4:l])
		xa.Port, xa.IP = parseXORPortAddr(tid, xa.Port, xa.IP)
		return &xa, nil
	case attrXOR_MAPPED_ADDRESS:
		xa := XORMappedAddr{Port: int(binary.BigEndian.Uint16(b[2:4])), IP: make(net.IP, l-4)}
		copy(xa.IP, b[4:l])
		xa.Port, xa.IP = parseXORPortAddr(tid, xa.Port, xa.IP)
		return &xa, nil
	case attrALTERNATE_SERVER:
		as := AlternateServer{Port: int(binary.BigEndian.Uint16(b[2:4])), IP: make(net.IP, net.IPv6len)}
		copy(as.IP, net.IP(b[4:l]).To16())
		return &as, nil
	default:
		return nil, errInvalidAttribute
	}
}

func parseXORPortAddr(tid []byte, port int, ip net.IP) (int, net.IP) {
	port ^= int(binary.BigEndian.Uint16(MagicCookie[:2]))
	if ip4 := ip.To4(); ip4 != nil {
		for i := range ip4 {
			ip4[i] ^= MagicCookie[i]
		}
		return port, ip4.To16()
	}
	if ip6 := ip.To16(); ip6 != nil && ip6.To4() == nil {
		cookie := append(MagicCookie, tid...)
		for i := range ip6 {
			ip6[i] ^= cookie[i]
		}
		return port, ip6
	}
	return -1, nil
}
