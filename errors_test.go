// Copyright 2015 Tim Heckman. All rights reserved.
// Use of this source code is governed by the BSD 3-Clause
// license that can be found in the LICENSE file.

package packets_test

import (
	"github.com/theckman/packets"
	. "gopkg.in/check.v1"
)

func (t *TestSuite) TestDataOffsetInvalid_Error(c *C) {
	var e packets.TCPDataOffsetInvalid

	e = packets.TCPDataOffsetInvalid{E: "test message"}

	c.Assert(e.Error(), Equals, "test message")
}

func (t *TestSuite) TestDataOffsetTooSmall_Error(c *C) {
	var e packets.TCPDataOffsetTooSmall

	e = packets.TCPDataOffsetTooSmall{E: "test message"}

	c.Assert(e.Error(), Equals, "test message")
}

func (t *TestSuite) TestOptionsOverflow_Error(c *C) {
	var e packets.TCPOptionsOverflow

	e = packets.TCPOptionsOverflow{E: "test message"}

	c.Assert(e.Error(), Equals, "test message")
}

func (t *TestSuite) TestOptionDataInvalid_Error(c *C) {
	var e packets.TCPOptionDataInvalid

	e = packets.TCPOptionDataInvalid{E: "test message"}

	c.Assert(e.Error(), Equals, "test message")
}

func (t *TestSuite) TestOptionDataTooLong_Error(c *C) {
	var e packets.TCPOptionDataTooLong

	e = packets.TCPOptionDataTooLong{E: "test message"}

	c.Assert(e.Error(), Equals, "test message")
}
