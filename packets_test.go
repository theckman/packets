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
	u *packets.UDPHeader
}

var _ = Suite(&TestSuite{})

func Test(t *testing.T) { TestingT(t) }

func (t *TestSuite) SetUpTest(c *C) {
	t.t = &packets.TCPHeader{
		SourcePort:      44273,
		DestinationPort: 22,
		SeqNum:          42,
		AckNum:          0,
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

	udpPayload := make([]byte, 4)

	udpPayload[0] = uint8(42)
	udpPayload[1] = uint8(128)
	udpPayload[2] = uint8(0)
	udpPayload[3] = uint8(0)

	t.u = &packets.UDPHeader{
		SourcePort:      4242,
		DestinationPort: 53,
		Length:          12,
		Checksum:        0,
		Payload:         udpPayload,
	}
}

func (t *TestSuite) TestChecksumIPv4(c *C) {
	var csum uint16
	var err error

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

	csum, err = packets.ChecksumIPv4(rawBytes.Bytes(), "tcp", "127.0.0.1", "127.0.0.2")
	c.Assert(err, IsNil)
	c.Check(csum, Equals, uint16(0xfb59))

	//
	// TEST KIND UDP
	//
	rawBytes.Reset()

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
	binary.Write(rawBytes, Te, mix)

	// Window Size
	binary.Write(rawBytes, Te, uint16(43690))
	// Checksum
	binary.Write(rawBytes, Te, uint16(0))
	// Urgent
	binary.Write(rawBytes, Te, uint16(0))

	csum, err = packets.ChecksumIPv4(rawBytes.Bytes(), "udp", "127.0.0.1", "127.0.0.2")
	c.Assert(err, IsNil)
	c.Check(csum, Equals, uint16(0xf059))

	csum, err = packets.ChecksumIPv4(rawBytes.Bytes(), "invalid", "127.0.0.1", "127.0.0.2")
	c.Assert(err, Not(IsNil))
	c.Check(csum, Equals, uint16(0))

	switch err.(type) {
	case packets.ErrChecksumInvalidKind:
		c.Check(err.Error(), Equals, "Checksum kind should either be 'tcp' OR 'udp'.")
	default:
		c.Fatalf("error type should be packets.ErrChecksumInvalidKind was %s", reflect.TypeOf(err).String())
	}
}
