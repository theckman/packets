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
