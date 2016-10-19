// Copyright 2015 Mikio Hara. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package stun

import (
	"fmt"
	"net"
)

// An Addr represents a STUN transport address.
type Addr struct {
	Port int    // port number
	IP   net.IP // IP address
}

// Network returns the address's network name, "stun".
func (a *Addr) Network() string {
	return "stun"
}

func (a *Addr) String() string {
	if a == nil {
		return "<nil>"
	}
	return net.JoinHostPort(a.IP.String(), fmt.Sprintf("%d", a.Port))
}
