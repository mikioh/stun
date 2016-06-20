// Copyright 2015 Mikio Hara. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package stun

import (
	"encoding/binary"
	"fmt"
	"time"
)

// An AttributeError represents a STUN  attribute error.
type AttributeError struct {
	// Type is the STUN attribute type.
	Type int

	// Err is the error that occurred.
	Err error
}

func (ae *AttributeError) Error() string {
	if ae == nil {
		return "<nil>"
	}
	return fmt.Sprintf("%#04x: %s", ae.Type, ae.Err.Error())
}

// An Attribute represents a STUN attribute.
type Attribute interface {
	// Len returns the length of STUN attribute value not
	// including the 4 byte attribute type and length fields, and
	// attribute padding bytes.
	Len() int
}

type fingerprint struct {
	attr Attribute // HMAC or CRC-32 fingerprint attribute
	off  int       // offset in a message
}

func marshalAttrs(b []byte, m *Control) ([]fingerprint, error) {
	b = b[controlHeaderLen:]
	off := controlHeaderLen
	var fps [3]fingerprint
	for _, attr := range m.Attrs {
		t, fn := attrTypeMarshaler(attr)
		switch t {
		case attrMESSAGE_INTEGRITY:
			if fps[0].attr == nil {
				fps[0].attr = attr
				fps[0].off = off
			}
		case attrMESSAGE_INTEGRITY_SHA256:
			if fps[1].attr == nil {
				fps[1].attr = attr
				fps[1].off = off
			}
		case attrFINGERPRINT:
			if fps[2].attr == nil {
				fps[2].attr = attr
				fps[2].off = off
			}
		}
		if err := fn(b, t, attr, m.TID); err != nil {
			return nil, &AttributeError{Type: t, Err: err}
		}
		l := roundup(4 + attr.Len())
		b = b[l:]
		off += l
	}
	return fps[:], nil
}

func attrTypeMarshaler(attr Attribute) (int, func([]byte, int, Attribute, []byte) error) {
	switch attr := attr.(type) {
	case Username:
		return attrUSERNAME, marshalStringAttr
	case Userhash:
		return attrUSERHASH, marshalBytesAttr
	case MessageIntegrity:
		return attrMESSAGE_INTEGRITY, marshalBytesAttr
	case MessageIntegritySHA256:
		return attrMESSAGE_INTEGRITY_SHA256, marshalBytesAttr
	case *Error:
		return attrERROR_CODE, marshalErrorAttr
	case UnknownAttrs:
		return attrUNKNOWN_ATTRIBUTES, marshalUnknownAttrs
	case *ChannelNumber:
		return attrCHANNEL_NUMBER, marshalChannelNumberAttr
	case Lifetime:
		return attrLIFETIME, marshalDurationAttr
	case *XORPeerAddr:
		return attrXOR_PEER_ADDRESS, marshalAddrAttr
	case Data:
		return attrDATA, marshalBytesAttr
	case Realm:
		return attrREALM, marshalStringAttr
	case Nonce:
		return attrNONCE, marshalStringAttr
	case *XORRelayedAddr:
		return attrXOR_RELAYED_ADDRESS, marshalAddrAttr
	case *RequestedAddrFamily:
		return attrREQUESTED_ADDRESS_FAMILY, marshalRequestedAddrFamilyAttr
	case *EvenPort:
		return attrEVEN_PORT, marshalEvenPortAttr
	case *RequestedTransport:
		return attrREQUESTED_TRANSPORT, marshalRequestedTransportAttr
	case *DontFragment:
		return attrDONT_FRAGMENT, marshalDontFragmentAttr
	case *XORMappedAddr:
		return attrXOR_MAPPED_ADDRESS, marshalAddrAttr
	case ReservationToken:
		return attrRESERVATION_TOKEN, marshalBytesAttr
	case Priority:
		return attrPRIORITY, marshalUintAttr
	case *UseCandidate:
		return attrUSE_CANDIDATE, marshalUseCandidateAttr
	case ConnectionID:
		return attrCONNECTION_ID, marshalUintAttr
	case Software:
		return attrSOFTWARE, marshalStringAttr
	case *AlternateServer:
		return attrALTERNATE_SERVER, marshalAddrAttr
	case Fingerprint:
		return attrFINGERPRINT, marshalUintAttr
	case ICEControlled:
		return attrICE_CONTROLLED, marshalUint64Attr
	case ICEControlling:
		return attrICE_CONTROLLING, marshalUint64Attr
	case *ECNCheck:
		return attrECN_CHECK_STUN, marshalECNCheckAttr
	case PasswordAlgorithms:
		return attrPASSWORD_ALGORITHMS, marshalPasswordAlgosAttr
	case *PasswordAlgorithm:
		return attrPASSWORD_ALGORITHM, marshalPasswordAlgoAttr
	case AlternateDomain:
		return attrALTERNATE_DOMAIN, marshalStringAttr
	case Origin:
		return attrORIGIN, marshalStringAttr
	case *DefaultAttr:
		return attr.Type, marshalDefaultAttr
	default:
		panic(fmt.Sprintf("unknown attribute: %T", attr))
	}
}

func marshalAttrTypeLen(b []byte, t, l int) {
	binary.BigEndian.PutUint16(b[:2], uint16(t))
	binary.BigEndian.PutUint16(b[2:4], uint16(l))
}

func marshalStringAttr(b []byte, t int, attr Attribute, _ []byte) error {
	if len(b) < 4+attr.Len() {
		return errBufferTooShort
	}
	marshalAttrTypeLen(b, t, attr.Len())
	switch t {
	case attrUSERNAME:
		copy(b[4:], attr.(Username))
	case attrREALM:
		copy(b[4:], attr.(Realm))
	case attrNONCE:
		copy(b[4:], attr.(Nonce))
	case attrSOFTWARE:
		copy(b[4:], attr.(Software))
	case attrALTERNATE_DOMAIN:
		copy(b[4:], attr.(AlternateDomain))
	case attrORIGIN:
		copy(b[4:], attr.(Origin))
	default:
		return errInvalidAttribute
	}
	return nil
}

func marshalBytesAttr(b []byte, t int, attr Attribute, _ []byte) error {
	if len(b) < 4+attr.Len() {
		return errBufferTooShort
	}
	marshalAttrTypeLen(b, t, attr.Len())
	switch t {
	case attrUSERHASH:
		copy(b[4:], attr.(Userhash))
	case attrMESSAGE_INTEGRITY:
		copy(b[4:], attr.(MessageIntegrity))
	case attrMESSAGE_INTEGRITY_SHA256:
		copy(b[4:], attr.(MessageIntegritySHA256))
	case attrDATA:
		copy(b[4:], attr.(Data))
	case attrRESERVATION_TOKEN:
		copy(b[4:], attr.(ReservationToken))
	default:
		return errInvalidAttribute
	}
	return nil
}

func marshalUintAttr(b []byte, t int, attr Attribute, _ []byte) error {
	if len(b) < 4+4 {
		return errBufferTooShort
	}
	marshalAttrTypeLen(b, t, 4)
	var v uint
	switch t {
	case attrPRIORITY:
		v = uint(attr.(Priority))
	case attrCONNECTION_ID:
		v = uint(attr.(ConnectionID))
	case attrFINGERPRINT:
		v = uint(attr.(Fingerprint))
	default:
		return errInvalidAttribute
	}
	binary.BigEndian.PutUint32(b[4:8], uint32(v))
	return nil
}

func marshalUint64Attr(b []byte, t int, attr Attribute, _ []byte) error {
	if len(b) < 4+8 {
		return errBufferTooShort
	}
	marshalAttrTypeLen(b, t, 8)
	var v uint64
	switch t {
	case attrICE_CONTROLLED:
		v = uint64(attr.(ICEControlled))
	case attrICE_CONTROLLING:
		v = uint64(attr.(ICEControlling))
	default:
		return errInvalidAttribute
	}
	binary.BigEndian.PutUint64(b[4:12], v)
	return nil
}

func marshalDurationAttr(b []byte, t int, attr Attribute, _ []byte) error {
	if len(b) < 4+4 {
		return errBufferTooShort
	}
	marshalAttrTypeLen(b, t, 4)
	switch t {
	case attrLIFETIME:
		v := uint32(time.Duration(attr.(Lifetime)).Seconds())
		binary.BigEndian.PutUint32(b[4:8], uint32(v))
	default:
		return errInvalidAttribute
	}
	return nil
}

func parseAttrs(b, tid []byte) ([]Attribute, []fingerprint, error) {
	if len(b) == 0 {
		return nil, nil, nil
	}
	var (
		off   int
		attrs []Attribute
		fps   [3]fingerprint
	)
	for len(b) > 0 {
		t, l, ll, err := parseAttrTypeLen(b)
		if err != nil {
			return nil, nil, &AttributeError{Type: t, Err: err}
		}
		var attr Attribute
		if p, ok := parsers[t]; !ok {
			attr, err = parseDefaultAttr(b[4:4+l], -1, -1, tid, t, l)
		} else {
			attr, err = p.fn(b[4:4+l], p.min, p.max, tid, t, l)
		}
		if err != nil {
			return nil, nil, &AttributeError{Type: t, Err: err}
		}
		if attr != nil {
			attrs = append(attrs, attr)
			switch t {
			case attrMESSAGE_INTEGRITY:
				if fps[0].attr == nil {
					fps[0].attr = attr
					fps[0].off = off
				}
			case attrMESSAGE_INTEGRITY_SHA256:
				if fps[1].attr == nil {
					fps[1].attr = attr
					fps[1].off = off
				}
			case attrFINGERPRINT:
				if fps[2].attr == nil {
					fps[2].attr = attr
					fps[2].off = off
				}
			}
		}
		b = b[ll:]
		off += ll
	}
	return attrs, fps[:], nil
}

func parseAttrTypeLen(b []byte) (t, l, ll int, err error) {
	if len(b) < 4 {
		return 0, 0, 0, errInvalidHeader
	}
	t = int(binary.BigEndian.Uint16(b[:2]))
	l = int(binary.BigEndian.Uint16(b[2:4]))
	ll = roundup(4 + l)
	if len(b) < ll {
		return t, l, ll, errAttributeTooShort
	}
	return t, l, ll, nil
}

type parser struct {
	fn  func([]byte, int, int, []byte, int, int) (Attribute, error)
	min int
	max int
}

var parsers = map[int]parser{
	attrUSERNAME:                 {parseStringAttr, 0, 512},
	attrUSERHASH:                 {parseBytesAttr, 32, 32},
	attrMESSAGE_INTEGRITY:        {parseBytesAttr, 20, 20},
	attrMESSAGE_INTEGRITY_SHA256: {parseBytesAttr, 32, 32},
	attrERROR_CODE:               {parseErrorAttr, 4, 4 + 763},
	attrUNKNOWN_ATTRIBUTES:       {parseUnknownAttrs, 0, 65535},
	attrCHANNEL_NUMBER:           {parseChannelNumberAttr, 4, 4},
	attrLIFETIME:                 {parseDurationAttr, 4, 4},
	attrXOR_PEER_ADDRESS:         {parseAddrAttr, -1, -1},
	attrDATA:                     {parseBytesAttr, 0, 65535},
	attrREALM:                    {parseStringAttr, 0, 763},
	attrNONCE:                    {parseStringAttr, 0, 763},
	attrXOR_RELAYED_ADDRESS:      {parseAddrAttr, -1, -1},
	attrREQUESTED_ADDRESS_FAMILY: {parseRequestedAddrFamilyAttr, 4, 4},
	attrEVEN_PORT:                {parseEvenPortAttr, 1, 1},
	attrREQUESTED_TRANSPORT:      {parseRequestedTransportAttr, 4, 4},
	attrDONT_FRAGMENT:            {parseDontFragmentAttr, 0, 0},
	attrXOR_MAPPED_ADDRESS:       {parseAddrAttr, -1, -1},
	attrRESERVATION_TOKEN:        {parseBytesAttr, 8, 8},
	attrPRIORITY:                 {parseUintAttr, 4, 4},
	attrUSE_CANDIDATE:            {parseUseCandidateAttr, 0, 0},
	attrCONNECTION_ID:            {parseUintAttr, 4, 4},
	attrSOFTWARE:                 {parseStringAttr, 0, 763},
	attrALTERNATE_SERVER:         {parseAddrAttr, -1, -1},
	attrFINGERPRINT:              {parseUintAttr, 4, 4},
	attrICE_CONTROLLED:           {parseUint64Attr, 8, 8},
	attrICE_CONTROLLING:          {parseUint64Attr, 8, 8},
	attrECN_CHECK_STUN:           {parseECNCheckAttr, 4, 4},
	attrPASSWORD_ALGORITHMS:      {parsePasswordAlgosAttr, 0, 65535},
	attrPASSWORD_ALGORITHM:       {parsePasswordAlgoAttr, 4, 65535},
	attrALTERNATE_DOMAIN:         {parseStringAttr, 0, 763},
	attrORIGIN:                   {parseStringAttr, 0, 65535},
}

func parseStringAttr(b []byte, min, max int, _ []byte, t, l int) (Attribute, error) {
	if min > l || l > max || len(b) < l {
		return nil, errAttributeTooShort
	}
	v := string(b[:l])
	switch t {
	case attrUSERNAME:
		return Username(v), nil
	case attrSOFTWARE:
		return Software(v), nil
	case attrREALM:
		return Realm(v), nil
	case attrNONCE:
		return Nonce(v), nil
	case attrALTERNATE_DOMAIN:
		return AlternateDomain(v), nil
	case attrORIGIN:
		return Origin(v), nil
	default:
		return nil, errInvalidAttribute
	}
}

func parseBytesAttr(b []byte, min, max int, _ []byte, t, l int) (Attribute, error) {
	if min > l || l > max || len(b) < l {
		return nil, errAttributeTooShort
	}
	switch t {
	case attrUSERHASH:
		v := make(Userhash, l)
		copy(v, b)
		return v, nil
	case attrMESSAGE_INTEGRITY:
		v := make(MessageIntegrity, l)
		copy(v, b)
		return v, nil
	case attrMESSAGE_INTEGRITY_SHA256:
		v := make(MessageIntegritySHA256, l)
		copy(v, b)
		return v, nil
	case attrDATA:
		return Data(b[:l]), nil
	case attrRESERVATION_TOKEN:
		v := make(ReservationToken, l)
		copy(v, b)
		return v, nil
	default:
		return nil, errInvalidAttribute
	}
}

func parseUintAttr(b []byte, min, max int, _ []byte, t, l int) (Attribute, error) {
	if min > l || l > max || len(b) < l {
		return nil, errAttributeTooShort
	}
	v := binary.BigEndian.Uint32(b[:4])
	switch t {
	case attrPRIORITY:
		return Priority(v), nil
	case attrCONNECTION_ID:
		return ConnectionID(v), nil
	case attrFINGERPRINT:
		return Fingerprint(v), nil
	default:
		return nil, errInvalidAttribute
	}
}

func parseUint64Attr(b []byte, min, max int, _ []byte, t, l int) (Attribute, error) {
	if min > l || l > max || len(b) < l {
		return nil, errAttributeTooShort
	}
	v := binary.BigEndian.Uint64(b[:8])
	switch t {
	case attrICE_CONTROLLED:
		return ICEControlled(v), nil
	case attrICE_CONTROLLING:
		return ICEControlling(v), nil
	default:
		return nil, errInvalidAttribute
	}
}

func parseDurationAttr(b []byte, min, max int, _ []byte, t, l int) (Attribute, error) {
	if min > l || l > max || len(b) < l {
		return nil, errAttributeTooShort
	}
	v := time.Duration(binary.BigEndian.Uint32(b[:4])) * time.Second
	switch t {
	case attrLIFETIME:
		return Lifetime(v), nil
	default:
		return nil, errInvalidAttribute
	}
}
