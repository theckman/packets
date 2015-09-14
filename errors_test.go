// Copyright 2015 Tim Heckman. All rights reserved.
// Use of this source code is governed by the BSD 3-Clause
// license that can be found in the LICENSE file.

package packets_test

import (
	"github.com/theckman/packets"
	. "gopkg.in/check.v1"
)

func (t *TestSuite) TestErrTCPDataOffsetInvalid_Error(c *C) {
	c.Check(packets.ErrTCPDataOffsetInvalid.Error(), Equals, "DataOffset field must be at least 5 and no more than 15")
}

func (t *TestSuite) TestErrChecksumInvalidKind_Error(c *C) {
	c.Check(packets.ErrChecksumInvalidKind.Error(), Equals, "Checksum kind should either be 'tcp' OR 'udp'.")
}

func (t *TestSuite) TestErrTCPDataOffsetTooSmall_Error(c *C) {
	var e packets.ErrTCPDataOffsetTooSmall

	e = packets.ErrTCPDataOffsetTooSmall{ExpectedSize: 100}

	c.Check(e.Error(), Equals, "The DataOffset field is too small for the data provided. It should be at least 100")
}

func (t *TestSuite) TestErrTCPOptionsOverflow_Error(c *C) {
	var e packets.ErrTCPOptionsOverflow

	e = packets.ErrTCPOptionsOverflow{MaxSize: 100}

	c.Check(e.Error(), Equals, "TCP Options are too large, must be less than 100 total bytes")
}

func (t *TestSuite) TestErrTCPOptionDataInvalid_Error(c *C) {
	var e packets.ErrTCPOptionDataInvalid

	e = packets.ErrTCPOptionDataInvalid{Index: 42}

	c.Check(e.Error(), Equals, "Option 42 Length doesn't match length of data")
}

func (t *TestSuite) TestErrTCPOptionDataTooLong_Error(c *C) {
	var e packets.ErrTCPOptionDataTooLong

	e = packets.ErrTCPOptionDataTooLong{Index: 42}

	c.Check(e.Error(), Equals, "Option 42 Data cannot be larger than 253 bytes")
}

func (t *TestSuite) TestErrUDPPayloadTooLarge_Error(c *C) {
	var e packets.ErrUDPPayloadTooLarge

	e = packets.ErrUDPPayloadTooLarge{
		MaxSize: 42,
		Len:     84,
	}

	c.Check(e.Error(), Equals, "UDP Payload must not be larger than 42 byte, was 84 bytes")
}
