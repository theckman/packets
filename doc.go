// Copyright 2015 Tim Heckman. All rights reserved.
// Use of this source code is governed by the BSD 3-Clause
// license that can be found in the LICENSE file.

// Package packets is for the creation/manipulation of raw TCP packets for sending over the network.
// It was designed to have a idiomatic (or so I think) interface.
//
// This package does have some internal error types that can be returned as errors from within
// this package. It's recommended you take a look at the packetserr package documenation as well.
// The packetserr package is a sub-package of packets.
package packets
