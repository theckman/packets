// Copyright 2015 Tim Heckman. All rights reserved.
// Use of this source code is governed by the BSD 3-Clause
// license that can be found in the LICENSE file.

package packetserr_test

import (
	"testing"

	"github.com/theckman/packets/err"
	. "gopkg.in/check.v1"
)

type TestSuite struct{}

var _ = Suite(&TestSuite{})

func Test(t *testing.T) { TestingT(t) }

func (t *TestSuite) TestTCPDataOffsetInvalid_Error(c *C) {
	c.Check(packetserr.TCPDataOffsetInvalid.Error(), Equals, "DataOffset field must be at least 5 and no more than 15")
}

func (t *TestSuite) TestChecksumInvalidKind_Error(c *C) {
	c.Check(packetserr.ChecksumInvalidKind.Error(), Equals, "Checksum kind should either be 'tcp' OR 'udp'.")
}

func (t *TestSuite) TestTCPDataOffsetTooSmall_Error(c *C) {
	var e packetserr.TCPDataOffsetTooSmall

	e = packetserr.TCPDataOffsetTooSmall{ExpectedSize: 100}

	c.Check(e.Error(), Equals, "The DataOffset field is too small for the data provided. It should be at least 100")
}

func (t *TestSuite) TestTCPOptionsOverflow_Error(c *C) {
	var e packetserr.TCPOptionsOverflow

	e = packetserr.TCPOptionsOverflow{MaxSize: 100}

	c.Check(e.Error(), Equals, "TCP Options are too large, must be less than 100 total bytes")
}

func (t *TestSuite) TestTCPOptionDataInvalid_Error(c *C) {
	var e packetserr.TCPOptionDataInvalid

	e = packetserr.TCPOptionDataInvalid{Index: 42}

	c.Check(e.Error(), Equals, "Option 42 Length doesn't match length of data")
}

func (t *TestSuite) TestTCPOptionDataTooLong_Error(c *C) {
	var e packetserr.TCPOptionDataTooLong

	e = packetserr.TCPOptionDataTooLong{Index: 42}

	c.Check(e.Error(), Equals, "Option 42 Data cannot be larger than 253 bytes")
}

func (t *TestSuite) TestUDPPayloadTooLarge_Error(c *C) {
	var e packetserr.UDPPayloadTooLarge

	e = packetserr.UDPPayloadTooLarge{
		MaxSize: 42,
		Len:     84,
	}

	c.Check(e.Error(), Equals, "UDP Payload must not be larger than 42 byte, was 84 bytes")
}
