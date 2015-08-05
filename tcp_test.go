// Copyright 2015 Tim Heckman. All rights reserved.
// Use of this source code is governed by the BSD 3-Clause
// license that can be found in the LICENSE file.

package packets_test

import (
	"bytes"
	"encoding/binary"
	"reflect"
	"testing"

	"github.com/theckman/packets"
	. "gopkg.in/check.v1"
)

var Te = binary.BigEndian

type TestSuite struct {
	t *packets.TCPHeader
}

var _ = Suite(&TestSuite{})

func Test(t *testing.T) { TestingT(t) }

func (t *TestSuite) SetUpTest(c *C) {
	t.t = &packets.TCPHeader{
		SourcePort:      44273,
		DestinationPort: 22,
		SeqNum:          42,
		AckNum:          0,
		DataOffset:      5,
		Reserved:        0,
		NS:              false,
		CWR:             false,
		ECE:             false,
		URG:             false,
		ACK:             false,
		PSH:             true,
		RST:             false,
		SYN:             true,
		FIN:             false,
		WindowSize:      43690,
		Checksum:        0,
		UrgentPointer:   0,
	}
}

func (t *TestSuite) TestUnmarshalTCPHeader(c *C) {
	var header *packets.TCPHeader

	rawBytes := new(bytes.Buffer)

	// Source Port
	binary.Write(rawBytes, Te, uint16(44273))
	// Destination Port
	binary.Write(rawBytes, Te, uint16(22))
	// TCP Sequence Number
	binary.Write(rawBytes, Te, uint32(42))
	// Acknowledgement number
	binary.Write(rawBytes, Te, uint32(0))

	// Data offset (4 bits), Reserved (3 bits), NS, CWR, ECE,
	// URG, ACK,
	mix := uint16(5)<<12 | // Data Offset (4 bits)
		uint16(0)<<9 | // Reserved (3 bits)
		uint16(0)<<6 | // ECN (3 bits)
		uint16(8) | // PSH (1 bit)
		uint16(2) // SYN (1 bit)

	binary.Write(rawBytes, Te, mix)

	// Window Size
	binary.Write(rawBytes, Te, uint16(43690))
	// Checksum
	binary.Write(rawBytes, Te, uint16(42332))
	// Urgent
	binary.Write(rawBytes, Te, uint16(0))

	// laddr := "127.0.0.1"
	// raddr := "127.0.0.2"

	// csum1, fullData := packets.ChecksumIPv4(rawBytes.Bytes(), laddr, raddr)
	// fmt.Println(string(fullData))
	// fmt.Println(csum1)
	header, err := packets.UnmarshalTCPHeader(rawBytes.Bytes())
	c.Assert(err, IsNil)

	c.Check(header.SourcePort, Equals, uint16(44273))
	c.Check(header.DestinationPort, Equals, uint16(22))
	c.Check(header.SeqNum, Equals, uint32(42))
	c.Check(header.AckNum, Equals, uint32(0))
	c.Check(header.NS, Equals, false)
	c.Check(header.CWR, Equals, false)
	c.Check(header.ECE, Equals, false)
	c.Check(header.URG, Equals, false)
	c.Check(header.ACK, Equals, false)
	c.Check(header.PSH, Equals, true)
	c.Check(header.RST, Equals, false)
	c.Check(header.SYN, Equals, true)
	c.Check(header.ACK, Equals, false)
	c.Check(header.WindowSize, Equals, uint16(43690))
	c.Check(header.Checksum, Equals, uint16(42332))
	c.Check(header.UrgentPointer, Equals, uint16(0))
}

func (t *TestSuite) TestChecksumIPv4(c *C) {
	var csum uint16

	rawBytes := new(bytes.Buffer)

	// Source Port
	binary.Write(rawBytes, Te, uint16(44273))
	// Destination Port
	binary.Write(rawBytes, Te, uint16(22))
	// TCP Sequence Number
	binary.Write(rawBytes, Te, uint32(42))
	// Acknowledgement number
	binary.Write(rawBytes, Te, uint32(0))

	// Data offset (4 bits), Reserved (3 bits), NS, CWR, ECE,
	// URG, ACK,
	mix := uint16(5)<<12 | // Data Offset (4 bits)
		uint16(0)<<9 | // Reserved (3 bits)
		uint16(0)<<6 | // ECN (3 bits)
		uint16(8) | // PSH (1 bit)
		uint16(2) // SYN (1 bit)

	binary.Write(rawBytes, Te, mix)

	// Window Size
	binary.Write(rawBytes, Te, uint16(43690))
	// Checksum
	binary.Write(rawBytes, Te, uint16(0))
	// Urgent
	binary.Write(rawBytes, Te, uint16(0))

	csum = packets.ChecksumIPv4(rawBytes.Bytes(), "127.0.0.1", "127.0.0.2")
	c.Check(csum, Equals, uint16(0xfb59))
}

func (t *TestSuite) TestMarshal(c *C) {
	var data []byte
	var err error

	data, err = t.t.Marshal()
	c.Assert(err, IsNil)
	c.Assert(data, Not(IsNil))

	var u32 uint32
	var u16 uint16
	var u8 uint8

	r := bytes.NewReader(data)
	e := binary.BigEndian

	// SourcePort
	c.Assert(binary.Read(r, e, &u16), IsNil)
	c.Check(u16, Equals, uint16(44273))

	// DestinationPort
	c.Assert(binary.Read(r, e, &u16), IsNil)
	c.Check(u16, Equals, uint16(22))

	// SeqNum
	c.Assert(binary.Read(r, e, &u32), IsNil)
	c.Check(u32, Equals, uint32(42))

	// AckNum
	c.Assert(binary.Read(r, e, &u32), IsNil)
	c.Check(u32, Equals, uint32(0))

	// DataOffset, Reserved, and all Control Flags!
	c.Assert(binary.Read(r, e, &u16), IsNil)
	c.Check(u16>>12, Equals, uint16(5))  // DataOffset
	c.Check(u16>>9&7, Equals, uint16(0)) // Reserved (should always be 000)
	c.Check(u16>>8&1, Equals, uint16(0)) // NS
	c.Check(u16>>7&1, Equals, uint16(0)) // CWR
	c.Check(u16>>6&1, Equals, uint16(0)) // ECE
	c.Check(u16>>5&1, Equals, uint16(0)) // URG
	c.Check(u16>>4&1, Equals, uint16(0)) // ACK
	c.Check(u16>>3&1, Equals, uint16(1)) // PSH
	c.Check(u16>>2&1, Equals, uint16(0)) // RST
	c.Check(u16>>1&1, Equals, uint16(1)) // SYN
	c.Check(u16&1, Equals, uint16(0))    // FIN

	// WindowSize
	c.Assert(binary.Read(r, e, &u16), IsNil)
	c.Check(u16, Equals, uint16(43690))

	// Checksum
	c.Assert(binary.Read(r, e, &u16), IsNil)
	c.Check(u16, Equals, uint16(0))

	// UrgentPointer
	c.Assert(binary.Read(r, e, &u16), IsNil)
	c.Check(u16, Equals, uint16(0))

	//
	// TEST WHEN DataOffset IS LARGE ENOUGH TO NEED PADDING
	//
	t.SetUpTest(c) // reset!

	t.t.DataOffset = 6

	data, err = t.t.Marshal()
	c.Assert(err, IsNil)
	c.Assert(data, Not(IsNil))

	r = bytes.NewReader(data)

	// SourcePort
	c.Assert(binary.Read(r, e, &u16), IsNil)
	c.Check(u16, Equals, uint16(44273))

	// DestinationPort
	c.Assert(binary.Read(r, e, &u16), IsNil)
	c.Check(u16, Equals, uint16(22))

	// SeqNum
	c.Assert(binary.Read(r, e, &u32), IsNil)
	c.Check(u32, Equals, uint32(42))

	// AckNum
	c.Assert(binary.Read(r, e, &u32), IsNil)
	c.Check(u32, Equals, uint32(0))

	// DataOffset, Reserved, and all Control Flags!
	c.Assert(binary.Read(r, e, &u16), IsNil)
	c.Check(u16>>12, Equals, uint16(6))  // DataOffset
	c.Check(u16>>9&7, Equals, uint16(0)) // Reserved (should always be 000)
	c.Check(u16>>8&1, Equals, uint16(0)) // NS
	c.Check(u16>>7&1, Equals, uint16(0)) // CWR
	c.Check(u16>>6&1, Equals, uint16(0)) // ECE
	c.Check(u16>>5&1, Equals, uint16(0)) // URG
	c.Check(u16>>4&1, Equals, uint16(0)) // ACK
	c.Check(u16>>3&1, Equals, uint16(1)) // PSH
	c.Check(u16>>2&1, Equals, uint16(0)) // RST
	c.Check(u16>>1&1, Equals, uint16(1)) // SYN
	c.Check(u16&1, Equals, uint16(0))    // FIN

	// WindowSize
	c.Assert(binary.Read(r, e, &u16), IsNil)
	c.Check(u16, Equals, uint16(43690))

	// Checksum
	c.Assert(binary.Read(r, e, &u16), IsNil)
	c.Check(u16, Equals, uint16(0))

	// UrgentPointer
	c.Assert(binary.Read(r, e, &u16), IsNil)
	c.Check(u16, Equals, uint16(0))

	// 4 padded bytes due to DataOffset being too big
	c.Assert(binary.Read(r, e, &u8), IsNil) // 0-7
	c.Check(u8, Equals, uint8(0))
	c.Assert(binary.Read(r, e, &u8), IsNil) // 8-15
	c.Check(u8, Equals, uint8(0))
	c.Assert(binary.Read(r, e, &u8), IsNil) // 16-23
	c.Check(u8, Equals, uint8(0))
	c.Assert(binary.Read(r, e, &u8), IsNil) // 24-31
	c.Check(u8, Equals, uint8(0))
}

func (t *TestSuite) TestMarshalWithChecksum(c *C) {
	var data []byte
	var err error

	data, err = t.t.MarshalWithChecksum("127.0.0.1", "127.0.0.2")
	c.Assert(err, IsNil)
	c.Assert(data, Not(IsNil))

	var u32 uint32
	var u16 uint16

	r := bytes.NewReader(data)
	e := binary.BigEndian

	// SourcePort
	c.Assert(binary.Read(r, e, &u16), IsNil)
	c.Check(u16, Equals, uint16(44273))

	// DestinationPort
	c.Assert(binary.Read(r, e, &u16), IsNil)
	c.Check(u16, Equals, uint16(22))

	// SeqNum
	c.Assert(binary.Read(r, e, &u32), IsNil)
	c.Check(u32, Equals, uint32(42))

	// AckNum
	c.Assert(binary.Read(r, e, &u32), IsNil)
	c.Check(u32, Equals, uint32(0))

	// DataOffset, Reserved, and all Control Flags!
	c.Assert(binary.Read(r, e, &u16), IsNil)
	c.Check(u16>>12, Equals, uint16(5))  // DataOffset
	c.Check(u16>>9&7, Equals, uint16(0)) // Reserved (should always be 000)
	c.Check(u16>>8&1, Equals, uint16(0)) // NS
	c.Check(u16>>7&1, Equals, uint16(0)) // CWR
	c.Check(u16>>6&1, Equals, uint16(0)) // ECE
	c.Check(u16>>5&1, Equals, uint16(0)) // URG
	c.Check(u16>>4&1, Equals, uint16(0)) // ACK
	c.Check(u16>>3&1, Equals, uint16(1)) // PSH
	c.Check(u16>>2&1, Equals, uint16(0)) // RST
	c.Check(u16>>1&1, Equals, uint16(1)) // SYN
	c.Check(u16&1, Equals, uint16(0))    // FIN

	// WindowSize
	c.Assert(binary.Read(r, e, &u16), IsNil)
	c.Check(u16, Equals, uint16(43690))

	// Checksum
	c.Assert(binary.Read(r, e, &u16), IsNil)
	c.Check(u16, Equals, uint16(64345))

	// UrgentPointer
	c.Assert(binary.Read(r, e, &u16), IsNil)
	c.Check(u16, Equals, uint16(0))

	//
	// TEST WHEN DataOffset IS ZERO
	//
	t.SetUpTest(c) // reset!

	t.t.DataOffset = 0

	data, err = t.t.MarshalWithChecksum("127.0.0.1", "127.0.0.2")
	c.Assert(err, IsNil)
	c.Assert(data, Not(IsNil))

	r = bytes.NewReader(data)

	// SourcePort
	c.Assert(binary.Read(r, e, &u16), IsNil)
	c.Check(u16, Equals, uint16(44273))

	// DestinationPort
	c.Assert(binary.Read(r, e, &u16), IsNil)
	c.Check(u16, Equals, uint16(22))

	// SeqNum
	c.Assert(binary.Read(r, e, &u32), IsNil)
	c.Check(u32, Equals, uint32(42))

	// AckNum
	c.Assert(binary.Read(r, e, &u32), IsNil)
	c.Check(u32, Equals, uint32(0))

	// DataOffset, Reserved, and all Control Flags!
	c.Assert(binary.Read(r, e, &u16), IsNil)
	c.Check(u16>>12, Equals, uint16(5))  // DataOffset
	c.Check(u16>>9&7, Equals, uint16(0)) // Reserved (should always be 000)
	c.Check(u16>>8&1, Equals, uint16(0)) // NS
	c.Check(u16>>7&1, Equals, uint16(0)) // CWR
	c.Check(u16>>6&1, Equals, uint16(0)) // ECE
	c.Check(u16>>5&1, Equals, uint16(0)) // URG
	c.Check(u16>>4&1, Equals, uint16(0)) // ACK
	c.Check(u16>>3&1, Equals, uint16(1)) // PSH
	c.Check(u16>>2&1, Equals, uint16(0)) // RST
	c.Check(u16>>1&1, Equals, uint16(1)) // SYN
	c.Check(u16&1, Equals, uint16(0))    // FIN

	// WindowSize
	c.Assert(binary.Read(r, e, &u16), IsNil)
	c.Check(u16, Equals, uint16(43690))

	// Checksum
	c.Assert(binary.Read(r, e, &u16), IsNil)
	c.Check(u16, Equals, uint16(64345))

	// UrgentPointer
	c.Assert(binary.Read(r, e, &u16), IsNil)
	c.Check(u16, Equals, uint16(0))

	//
	// TEST WHEN DataOffset IS INVALID
	//
	t.SetUpTest(c) // reset!

	t.t.DataOffset = 3

	data, err = t.t.MarshalWithChecksum("127.0.0.1", "127.0.0.2")
	c.Assert(err, Not(IsNil))
	c.Check(data, IsNil)

	switch err.(type) {
	case packets.DataOffsetInvalid:
		c.Check(err.Error(), Equals, "DataOffset field must be at least 5 and no more than 15")
	default:
		c.Fatalf("Unexpected error type! Should be packets.DataOffset was '%s'", reflect.TypeOf(err).String())
	}

	//
	// TEST WHEN WindowSize IS ZERO
	//
	t.SetUpTest(c)

	t.t.WindowSize = 0

	data, err = t.t.MarshalWithChecksum("127.0.0.1", "127.0.0.2")
	c.Assert(err, IsNil)
	c.Assert(data, Not(IsNil))

	r = bytes.NewReader(data)

	// SourcePort
	c.Assert(binary.Read(r, e, &u16), IsNil)
	c.Check(u16, Equals, uint16(44273))

	// DestinationPort
	c.Assert(binary.Read(r, e, &u16), IsNil)
	c.Check(u16, Equals, uint16(22))

	// SeqNum
	c.Assert(binary.Read(r, e, &u32), IsNil)
	c.Check(u32, Equals, uint32(42))

	// AckNum
	c.Assert(binary.Read(r, e, &u32), IsNil)
	c.Check(u32, Equals, uint32(0))

	// DataOffset, Reserved, and all Control Flags!
	c.Assert(binary.Read(r, e, &u16), IsNil)
	c.Check(u16>>12, Equals, uint16(5))  // DataOffset
	c.Check(u16>>9&7, Equals, uint16(0)) // Reserved (should always be 000)
	c.Check(u16>>8&1, Equals, uint16(0)) // NS
	c.Check(u16>>7&1, Equals, uint16(0)) // CWR
	c.Check(u16>>6&1, Equals, uint16(0)) // ECE
	c.Check(u16>>5&1, Equals, uint16(0)) // URG
	c.Check(u16>>4&1, Equals, uint16(0)) // ACK
	c.Check(u16>>3&1, Equals, uint16(1)) // PSH
	c.Check(u16>>2&1, Equals, uint16(0)) // RST
	c.Check(u16>>1&1, Equals, uint16(1)) // SYN
	c.Check(u16&1, Equals, uint16(0))    // FIN

	// WindowSize
	c.Assert(binary.Read(r, e, &u16), IsNil)
	c.Check(u16, Equals, uint16(65535))

	// Checksum
	c.Assert(binary.Read(r, e, &u16), IsNil)
	c.Check(u16, Equals, uint16(42500))

	// UrgentPointer
	c.Assert(binary.Read(r, e, &u16), IsNil)
	c.Check(u16, Equals, uint16(0))
}
