// Copyright 2015 Tim Heckman. All rights reserved.
// Use of this source code is governed by the BSD 3-Clause
// license that can be found in the LICENSE file.

package packets_test

import (
	"github.com/theckman/packets"
	. "gopkg.in/check.v1"
)

func (t *TestSuite) TestErrTCPDataOffsetInvalid_Error(c *C) {
	var e packets.ErrTCPDataOffsetInvalid

	e = packets.ErrTCPDataOffsetInvalid{E: "test message"}

	c.Assert(e.Error(), Equals, "test message")
}

func (t *TestSuite) TestErrTCPDataOffsetTooSmall_Error(c *C) {
	var e packets.ErrTCPDataOffsetTooSmall

	e = packets.ErrTCPDataOffsetTooSmall{E: "test message"}

	c.Assert(e.Error(), Equals, "test message")
}

func (t *TestSuite) TestErrTCPOptionsOverflow_Error(c *C) {
	var e packets.ErrTCPOptionsOverflow

	e = packets.ErrTCPOptionsOverflow{E: "test message"}

	c.Assert(e.Error(), Equals, "test message")
}

func (t *TestSuite) TestErrTCPOptionDataInvalid_Error(c *C) {
	var e packets.ErrTCPOptionDataInvalid

	e = packets.ErrTCPOptionDataInvalid{E: "test message"}

	c.Assert(e.Error(), Equals, "test message")
}

func (t *TestSuite) TestErrTCPOptionDataTooLong_Error(c *C) {
	var e packets.ErrTCPOptionDataTooLong

	e = packets.ErrTCPOptionDataTooLong{E: "test message"}

	c.Assert(e.Error(), Equals, "test message")
}
