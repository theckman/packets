// Copyright 2015 Tim Heckman. All rights reserved.
// Use of this source code is governed by the BSD 3-Clause
// license that can be found in the LICENSE file.

package packets_test

import (
	"bytes"
	"encoding/binary"
	"reflect"

	"github.com/theckman/packets"
	"github.com/theckman/packets/err"
	. "gopkg.in/check.v1"
)

func (t *TestSuite) TestUnmarshalUDPHeader(c *C) {
	var header *packets.UDPHeader
	var err error

	buf := new(bytes.Buffer)

	// SourcePort
	binary.Write(buf, Te, uint16(4242))
	// DestinationPort
	binary.Write(buf, Te, uint16(53))
	// Length
	binary.Write(buf, Te, uint16(12))
	// Checksum
	binary.Write(buf, Te, uint16(0))

	// Imaginary Payload
	binary.Write(buf, Te, uint8(42))
	binary.Write(buf, Te, uint8(128))
	binary.Write(buf, Te, uint8(0))
	binary.Write(buf, Te, uint8(0))

	header, err = packets.UnmarshalUDPHeader(buf.Bytes())
	c.Assert(err, IsNil)
	c.Assert(header, Not(IsNil))

	c.Check(header.SourcePort, Equals, uint16(4242))
	c.Check(header.DestinationPort, Equals, uint16(53))
	c.Check(header.Length, Equals, uint16(12))
	c.Check(header.Checksum, Equals, uint16(0))

	c.Assert(len(header.Payload), Equals, 4)
	c.Check(header.Payload[0], Equals, uint8(42))
	c.Check(header.Payload[1], Equals, uint8(128))
	c.Check(header.Payload[2], Equals, uint8(0))
	c.Check(header.Payload[3], Equals, uint8(0))
}

func (t *TestSuite) TestUDPHeader_Marshal(c *C) {
	var data []byte
	var err error

	data, err = t.u.Marshal()
	c.Assert(err, IsNil)
	c.Assert(data, Not(IsNil))

	var u16 uint16
	var u8 uint8

	r := bytes.NewReader(data)

	// SourcePort
	c.Assert(binary.Read(r, Te, &u16), IsNil)
	c.Check(u16, Equals, uint16(4242))
	// DestinationPort
	c.Assert(binary.Read(r, Te, &u16), IsNil)
	c.Check(u16, Equals, uint16(53))
	// Length
	c.Assert(binary.Read(r, Te, &u16), IsNil)
	c.Check(u16, Equals, uint16(12))
	// Checksum
	c.Assert(binary.Read(r, Te, &u16), IsNil)
	c.Check(u16, Equals, uint16(0))

	// Payload
	c.Assert(binary.Read(r, Te, &u8), IsNil)
	c.Check(u8, Equals, uint8(42))
	c.Assert(binary.Read(r, Te, &u8), IsNil)
	c.Check(u8, Equals, uint8(128))
	c.Assert(binary.Read(r, Te, &u8), IsNil)
	c.Check(u8, Equals, uint8(0))
	c.Assert(binary.Read(r, Te, &u8), IsNil)
	c.Check(u8, Equals, uint8(0))

	//
	// Test with a payload that is too large
	//

	t.u.Payload = make([]byte, int(^uint16(0))+1)
	for i := range t.u.Payload {
		t.u.Payload[i] = byte('a')
	}

	data, err = t.u.Marshal()
	c.Assert(err, Not(IsNil))
	c.Check(data, IsNil)

	switch err.(type) {
	case packetserr.UDPPayloadTooLarge:
		e := err.(packetserr.UDPPayloadTooLarge)
		c.Check(e.MaxSize, Equals, 65527)
		c.Check(e.Len, Equals, 65536)
		c.Check(err.Error(), Equals, "UDP Payload must not be larger than 65527 byte, was 65536 bytes")
	default:
		c.Fatalf("error type should be packetserr.UDPPayloadTooLarge was %s", reflect.TypeOf(err).String())
	}
}

func (t *TestSuite) TestUDPHeader_MarshalWithChecksum(c *C) {
	var data []byte
	var err error

	data, err = t.u.MarshalWithChecksum("127.0.0.1", "127.0.0.2")
	c.Assert(err, IsNil)
	c.Assert(data, Not(IsNil))

	var u16 uint16
	var u8 uint8

	r := bytes.NewReader(data)

	// SourcePort
	c.Assert(binary.Read(r, Te, &u16), IsNil)
	c.Check(u16, Equals, uint16(4242))
	// DestinationPort
	c.Assert(binary.Read(r, Te, &u16), IsNil)
	c.Check(u16, Equals, uint16(53))
	// Length
	c.Assert(binary.Read(r, Te, &u16), IsNil)
	c.Check(u16, Equals, uint16(12))
	// Checksum
	c.Assert(binary.Read(r, Te, &u16), IsNil)
	c.Check(u16, Equals, uint16(35782))

	// Payload
	c.Assert(binary.Read(r, Te, &u8), IsNil)
	c.Check(u8, Equals, uint8(42))
	c.Assert(binary.Read(r, Te, &u8), IsNil)
	c.Check(u8, Equals, uint8(128))
	c.Assert(binary.Read(r, Te, &u8), IsNil)
	c.Check(u8, Equals, uint8(0))
	c.Assert(binary.Read(r, Te, &u8), IsNil)
	c.Check(u8, Equals, uint8(0))
}
