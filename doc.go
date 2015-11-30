// Copyright 2015 Mikio Hara. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

/*
Package stun provides basic functions for the manipulation of messages
used in the Session Traversal Utilities for NAT (STUN), Traversal
Using Relays around NAT (TURN) and Interactive Connectivity
Establishment (ICE) protocols.

STUN is defined in RFC 5389.
TURN is defined in RFC 5766.
Traversal Using Relays around NAT (TURN) Extensions for TCP Allocations is defined in RFC 6062.
Traversal Using Relays around NAT (TURN) Extension for IPv6 is defined in RFC 6156.
ICE is defined in RFC 5245.
Explicit Congestion Notification (ECN) for RTP over UDP is defined in RFC 6679.
An Origin Attribute for the STUN Protocol is defined in https://tools.ietf.org/html/draft-ietf-tram-stun-origin.

Also see https://tools.ietf.org/html/draft-ietf-tram-turnbis.

Note: THIRD-PARTY-AUTHORIZATION and ACCESS-TOKEN attributes defined in
RFC 7635 are not implemented yet and you can use DefaultAttr for those
attributes.
*/
package stun
