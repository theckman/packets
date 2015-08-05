// Copyright 2015 Tim Heckman. All rights reserved.
// Use of this source code is governed by the BSD 3-Clause
// license that can be found in the LICENSE file.

package packets_test

import (
	"github.com/theckman/packets"
	. "gopkg.in/check.v1"
)

func (t *TestSuite) TestDataOffsetInvalid_Error(c *C) {
	var e packets.DataOffsetInvalid

	e = packets.DataOffsetInvalid{E: "test message"}

	c.Assert(e.Error(), Equals, "test message")
}
