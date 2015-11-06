// Copyright 2015 Mikio Hara. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package stun

import "net"

// A MappedAddr represents a STUN MAPPED-ADDRESS attribute.
type MappedAddr struct {
	Family int    // address family identifier
	Port   int    // Port number
	IP     net.IP // IP address
}

// Len implements the Len method of Attribute interface.
func (ma *MappedAddr) Len() int {
	return addrAttrLen(ma.IP)
}

// Marshal implements the Marshal method of Attribute interface.
func (ma *MappedAddr) Marshal(tid []byte) ([]byte, error) {
	b := make([]byte, roundup(4+addrAttrLen(ma.IP)))
	if err := marshalAddrAttr(b, attrMAPPED_ADDRESS, ma, tid); err != nil {
		return nil, err
	}
	return b, nil
}

// An XORMappedAddr represents a STUN XOR-MAPPED-ADDRESS attribute.
type XORMappedAddr struct {
	Family int    // address family identifier
	Port   int    // Port number
	IP     net.IP // IP address
}

// Len implements the Len method of Attribute interface.
func (xa *XORMappedAddr) Len() int {
	return addrAttrLen(xa.IP)
}

// Marshal implements the Marshal method of Attribute interface.
func (xa *XORMappedAddr) Marshal(tid []byte) ([]byte, error) {
	b := make([]byte, roundup(4+addrAttrLen(xa.IP)))
	if err := marshalAddrAttr(b, attrXOR_MAPPED_ADDRESS, xa, tid); err != nil {
		return nil, err
	}
	return b, nil
}

// An AlternateServer represents a STUN ALTERNATE-SERVER attribute.
type AlternateServer struct {
	Family int    // address family identifier
	Port   int    // Port number
	IP     net.IP // IP address
}

// Len implements the Len method of Attribute interface.
func (as *AlternateServer) Len() int {
	return addrAttrLen(as.IP)
}

// Marshal implements the Marshal method of Attribute interface.
func (as *AlternateServer) Marshal(tid []byte) ([]byte, error) {
	b := make([]byte, roundup(4+addrAttrLen(as.IP)))
	if err := marshalAddrAttr(b, attrALTERNATE_SERVER, as, tid); err != nil {
		return nil, err
	}
	return b, nil
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
	if len(b) < 8 {
		return errBufferTooShort
	}
	var port int
	var ip net.IP
	switch attr := attr.(type) {
	case *MappedAddr:
		port = attr.Port
		ip = attr.IP
	case *XORMappedAddr:
		port = attr.Port
		ip = attr.IP
	case *AlternateServer:
		port = attr.Port
		ip = attr.IP
	}
	l := 4
	if ip4 := ip.To4(); ip4 != nil {
		b[5] = 1
		if len(b) < 12 {
			return errBufferTooShort
		}
		copy(b[8:], ip4)
		if t == attrXOR_MAPPED_ADDRESS {
			for i := range b[8:12] {
				b[8+i] ^= MagicCookie[i]
			}
		}
		l += net.IPv4len
	}
	if ip6 := ip.To16(); ip6 != nil && ip6.To4() == nil {
		b[5] = 2
		if len(b) < 24 {
			return errBufferTooShort
		}
		copy(b[8:], ip6)
		if t == attrXOR_MAPPED_ADDRESS {
			cookie := append(MagicCookie, tid...)
			for i := range b[8:20] {
				b[8+i] ^= cookie[i]
			}
		}
		l += net.IPv6len
	}
	marshalAttrTypeLen(b, t, l)
	b[6], b[7] = byte(port>>8), byte(port)
	if t == attrXOR_MAPPED_ADDRESS {
		b[6] ^= MagicCookie[0]
		b[7] ^= MagicCookie[1]
	}
	return nil
}

func parseAddrAttr(t, l int, tid, b []byte) (Attribute, error) {
	if l-4 != net.IPv4len && l-4 != net.IPv6len {
		return nil, errAttributeTooShort
	}
	switch t {
	case attrMAPPED_ADDRESS:
		ma := MappedAddr{Family: int(b[1]), Port: int(b[2])<<8 | int(b[3]), IP: make(net.IP, net.IPv6len)}
		copy(ma.IP, net.IP(b[4:l]).To16())
		return &ma, nil
	case attrXOR_MAPPED_ADDRESS:
		xa := XORMappedAddr{Family: int(b[1]), Port: int(b[2])<<8 | int(b[3]), IP: make(net.IP, l-4)}
		xa.Port ^= int(MagicCookie[0])<<8 | int(MagicCookie[1])
		copy(xa.IP, b[4:l])
		if ip4 := xa.IP.To4(); ip4 != nil {
			for i := range ip4 {
				ip4[i] ^= MagicCookie[i]
			}
			xa.IP = ip4.To16()
		}
		if ip6 := xa.IP.To16(); ip6 != nil && ip6.To4() == nil {
			cookie := append(MagicCookie, tid...)
			for i := range ip6 {
				ip6[i] ^= cookie[i]
			}
			xa.IP = ip6
		}
		return &xa, nil
	case attrALTERNATE_SERVER:
		as := XORMappedAddr{Family: int(b[1]), Port: int(b[2])<<8 | int(b[3]), IP: make(net.IP, net.IPv6len)}
		copy(as.IP, net.IP(b[4:l]).To16())
		return &as, nil
	default:
		return nil, errInvalidAttribute
	}
}
