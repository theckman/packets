// Copyright 2015 Tim Heckman. All rights reserved.
// Use of this source code is governed by the BSD 3-Clause
// license that can be found in the LICENSE file.

package packets_test

import (
	"bytes"
	"encoding/binary"
	"reflect"

	"github.com/theckman/packets"
	. "gopkg.in/check.v1"
)

func (t *TestSuite) TestTCPOptionSlice_Marshal(c *C) {
	var data []byte
	var err error

	optSlice := make(packets.TCPOptionSlice, 0)

	opt := &packets.TCPOption{
		Kind:   3,
		Length: 3,
		Data:   []byte{uint8(128)},
	}

	optSlice = append(optSlice, opt)

	// also make sure we have a nil check in the codepath
	// which should just move on to the next item in the slice
	optSlice = append(optSlice, nil)

	opt = &packets.TCPOption{
		Kind:   4,
		Length: 2,
		Data:   make([]byte, 0),
	}

	optSlice = append(optSlice, opt)

	data, err = optSlice.Marshal()
	c.Assert(err, IsNil)
	c.Assert(data, Not(IsNil))

	e := binary.BigEndian
	r := bytes.NewReader(data)

	var u8 uint8

	// First opttion
	c.Assert(binary.Read(r, e, &u8), IsNil)
	c.Check(u8, Equals, uint8(3))
	c.Assert(binary.Read(r, e, &u8), IsNil)
	c.Check(u8, Equals, uint8(3))
	c.Assert(binary.Read(r, e, &u8), IsNil)
	c.Check(u8, Equals, uint8(128))
	// TCP Option padding (ones)
	c.Assert(binary.Read(r, e, &u8), IsNil)
	c.Check(u8, Equals, uint8(1))
	// Second option
	c.Assert(binary.Read(r, e, &u8), IsNil)
	c.Check(u8, Equals, uint8(4))
	c.Assert(binary.Read(r, e, &u8), IsNil)
	c.Check(u8, Equals, uint8(2))

	//
	// TEST ErrTCPOptionDataTooLong
	//

	optSlice = make(packets.TCPOptionSlice, 0)

	failTestData := make([]byte, 256)

	for i := range failTestData {
		failTestData[i] = byte(0)
	}

	opt = &packets.TCPOption{
		Kind:   3,
		Length: 3,
		Data:   failTestData,
	}

	optSlice = append(optSlice, opt)

	data, err = optSlice.Marshal()
	c.Assert(err, Not(IsNil))
	c.Assert(data, IsNil)

	switch err.(type) {
	case packets.ErrTCPOptionDataTooLong:
		c.Check(err.(packets.ErrTCPOptionDataTooLong).Index, Equals, 0)
		c.Check(err.Error(), Equals, "Option 0 Data cannot be larger than 253 bytes")
	default:
		c.Fatalf("error type should be packets.ErrTCPOptionDataTooLarge was %s", reflect.TypeOf(err).String())
	}

	//
	// TEST ErrTCPOptionDataInvalid
	//

	optSlice[0].Data = make([]byte, 0)

	data, err = optSlice.Marshal()
	c.Assert(err, Not(IsNil))
	c.Assert(data, IsNil)

	switch err.(type) {
	case packets.ErrTCPOptionDataInvalid:
		c.Check(err.(packets.ErrTCPOptionDataInvalid).Index, Equals, 0)
		c.Check(err.Error(), Equals, "Option 0 Length doesn't match length of data")
	default:
		c.Fatalf("error type should be packets.ErrTCPOptionDataInvalid was %s", reflect.TypeOf(err).String())
	}
}

func (t *TestSuite) TestUnmarshalTCPOptionSlice(c *C) {
	var tcpos packets.TCPOptionSlice
	var err error

	optSlice := make(packets.TCPOptionSlice, 0)

	opt := &packets.TCPOption{
		Kind:   3,
		Length: 3,
		Data:   []byte{uint8(128)},
	}

	optSlice = append(optSlice, opt)

	opt = &packets.TCPOption{
		Kind:   4,
		Length: 2,
		Data:   make([]byte, 0),
	}

	optSlice = append(optSlice, opt)

	optBytes, err := optSlice.Marshal()
	c.Assert(err, IsNil)
	c.Assert(optBytes, Not(IsNil))

	rawBytes := new(bytes.Buffer)
	binary.Write(rawBytes, Te, optBytes)

	// add zero padding to nearest 32-bit boundary
	for i := 0; i < rawBytes.Len()%4; i++ {
		binary.Write(rawBytes, Te, uint8(0))
	}

	tcpos, err = packets.UnmarshalTCPOptionSlice(rawBytes.Bytes())
	c.Assert(err, IsNil)
	c.Assert(len(tcpos), Equals, 2)

	c.Assert(tcpos[0], Not(IsNil))
	opt = tcpos[0]

	c.Check(opt.Kind, Equals, uint8(3))
	c.Check(opt.Length, Equals, uint8(3))
	c.Assert(len(opt.Data), Equals, 1)
	c.Check(opt.Data[0], Equals, uint8(128))

	c.Assert(tcpos[1], Not(IsNil))
	opt = tcpos[1]

	c.Check(opt.Kind, Equals, uint8(4))
	c.Check(opt.Length, Equals, uint8(2))
	c.Assert(len(opt.Data), Equals, 0)
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
	mix := uint16(7)<<12 | // Data Offset (4 bits)
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

	optSlice := make(packets.TCPOptionSlice, 0)

	opt := &packets.TCPOption{
		Kind:   3,
		Length: 3,
		Data:   []byte{uint8(128)},
	}

	optSlice = append(optSlice, opt)

	opt = &packets.TCPOption{
		Kind:   4,
		Length: 2,
		Data:   make([]byte, 0),
	}

	optSlice = append(optSlice, opt)

	optBytes, err := optSlice.Marshal()
	c.Assert(err, IsNil)

	binary.Write(rawBytes, Te, optBytes)

	// add zero padding to nearest 32-bit boundary
	for i := 0; i < rawBytes.Len()%4; i++ {
		binary.Write(rawBytes, Te, uint8(0))
	}

	header, err = packets.UnmarshalTCPHeader(rawBytes.Bytes())
	c.Assert(err, IsNil)

	c.Check(header.SourcePort, Equals, uint16(44273))
	c.Check(header.DestinationPort, Equals, uint16(22))
	c.Check(header.SeqNum, Equals, uint32(42))
	c.Check(header.AckNum, Equals, uint32(0))
	c.Check(header.DataOffset, Equals, uint8(7))
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

	// Options
	c.Assert(len(header.Options), Equals, 2)
	// First option
	c.Check(header.Options[0].Kind, Equals, uint8(3))
	c.Check(header.Options[0].Length, Equals, uint8(3))
	c.Assert(len(header.Options[0].Data), Equals, 1)
	c.Check(header.Options[0].Data[0], Equals, uint8(128))
	// Second option
	c.Check(header.Options[1].Kind, Equals, uint8(4))
	c.Check(header.Options[1].Length, Equals, uint8(2))
	c.Check(len(header.Options[1].Data), Equals, 0)
}

func (t *TestSuite) TestTCPHeader_Marshal(c *C) {
	var data []byte
	var err error

	data, err = t.t.Marshal()
	c.Assert(err, IsNil)
	c.Assert(data, Not(IsNil))

	// should end on a 32-bit boundary
	c.Check(len(data)%4, Equals, 0)

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

	// should end on a 32-bit boundary
	c.Check(len(data)%4, Equals, 0)

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

	//
	// TEST TCP OPTION HANDLING
	//

	t.SetUpTest(c) // reset!

	optSlice := make(packets.TCPOptionSlice, 0)

	opt := &packets.TCPOption{
		Kind:   3,
		Length: 3,
		Data:   []byte{uint8(128)},
	}

	optSlice = append(optSlice, opt)

	opt = &packets.TCPOption{
		Kind:   4,
		Length: 2,
		Data:   make([]byte, 0),
	}

	optSlice = append(optSlice, opt)

	t.t.Options = optSlice

	data, err = t.t.Marshal()
	c.Assert(err, IsNil)
	c.Assert(data, Not(IsNil))

	// should end on a 32-bit boundary
	c.Check(len(data)%4, Equals, 0)

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
	c.Check(u16>>12, Equals, uint16(7))  // DataOffset
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

	// TCP Options
	// First opttion
	c.Assert(binary.Read(r, e, &u8), IsNil)
	c.Check(u8, Equals, uint8(3))
	c.Assert(binary.Read(r, e, &u8), IsNil)
	c.Check(u8, Equals, uint8(3))
	c.Assert(binary.Read(r, e, &u8), IsNil)
	c.Check(u8, Equals, uint8(128))
	// TCP Option padding (ones)
	c.Assert(binary.Read(r, e, &u8), IsNil)
	c.Check(u8, Equals, uint8(1))
	// Second option
	c.Assert(binary.Read(r, e, &u8), IsNil)
	c.Check(u8, Equals, uint8(4))
	c.Assert(binary.Read(r, e, &u8), IsNil)
	c.Check(u8, Equals, uint8(2))
	// TCP Header padding (zeroes)
	c.Assert(binary.Read(r, e, &u8), IsNil)
	c.Check(u8, Equals, uint8(0))
	c.Assert(binary.Read(r, e, &u8), IsNil)
	c.Check(u8, Equals, uint8(0))

	//
	// TEST TCP OPTION ERROR CONDITIONS
	//

	//
	// ErrTCPOptionaDataTooLong
	//
	t.SetUpTest(c) // reset!

	optSlice = make(packets.TCPOptionSlice, 0)

	failTestData := make([]byte, 256)

	for i := range failTestData {
		failTestData[i] = byte(0)
	}

	opt = &packets.TCPOption{
		Kind:   3,
		Length: 3,
		Data:   failTestData,
	}

	optSlice = append(optSlice, opt)

	t.t.Options = optSlice

	data, err = t.t.Marshal()
	c.Assert(err, Not(IsNil))
	c.Assert(data, IsNil)

	switch err.(type) {
	case packets.ErrTCPOptionDataTooLong:
		c.Check(err.(packets.ErrTCPOptionDataTooLong).Index, Equals, 0)
		c.Check(err.Error(), Equals, "Option 0 Data cannot be larger than 253 bytes")
	default:
		c.Fatalf("error type should be packets.ErrTCPOptionDataTooLarge was %s", reflect.TypeOf(err).String())
	}

	//
	// ErrTCPOptionaDataTooLong
	//
	optSlice = make(packets.TCPOptionSlice, 0)

	failTestData = make([]byte, 253)

	for i := range failTestData {
		failTestData[i] = byte(0)
	}

	opt = &packets.TCPOption{
		Kind:   3,
		Length: 3,
		Data:   failTestData,
	}

	optSlice = append(optSlice, opt)

	t.t.Options = optSlice
	data, err = t.t.Marshal()
	c.Assert(err, Not(IsNil))
	c.Assert(data, IsNil)

	switch err.(type) {
	case packets.ErrTCPOptionDataInvalid:
		c.Check(err.(packets.ErrTCPOptionDataInvalid).Index, Equals, 0)
		c.Check(err.Error(), Equals, "Option 0 Length doesn't match length of data")
	default:
		c.Fatalf("error type should be packets.ErrTCPOptionDataInvalid was %s", reflect.TypeOf(err).String())
	}

	//
	// ErrTCPOptionsOverflow
	//
	optSlice = make(packets.TCPOptionSlice, 4)

	for i := range optSlice {
		failTestData = make([]byte, 253)

		for i := range failTestData {
			failTestData[i] = byte(0)
		}

		optSlice[i] = &packets.TCPOption{
			Kind:   3,
			Length: 255,
			Data:   failTestData,
		}
	}

	t.t.Options = optSlice
	data, err = t.t.Marshal()
	c.Assert(err, Not(IsNil))
	c.Assert(data, IsNil)

	switch err.(type) {
	case packets.ErrTCPOptionsOverflow:
		c.Check(err.(packets.ErrTCPOptionsOverflow).MaxSize, Equals, 40)
		c.Check(err.Error(), Equals, "TCP Options are too large, must be less than 40 total bytes")
	default:
		c.Fatalf("error type should be packets.ErrTCPOptionsOverflow was %s", reflect.TypeOf(err).String())
	}

	//
	// TEST DataOffset MIN LENGTH VALIDATION
	//

	optSlice = make(packets.TCPOptionSlice, 0)

	failTestData = make([]byte, 0)

	opt = &packets.TCPOption{
		Kind:   3,
		Length: 2,
		Data:   failTestData,
	}

	optSlice = append(optSlice, opt)

	t.t.Options = optSlice
	t.t.DataOffset = 5

	data, err = t.t.Marshal()
	c.Assert(err, Not(IsNil))
	c.Assert(data, IsNil)

	switch err.(type) {
	case packets.ErrTCPDataOffsetTooSmall:
		c.Check(err.(packets.ErrTCPDataOffsetTooSmall).ExpectedSize, Equals, uint8(6))
		c.Check(err.Error(), Equals, "The DataOffset field is too small for the data provided. It should be at least 6")
	default:
		c.Fatalf("error type should be packets.ErrTCPDataOffsetTooSmall type was %s", reflect.TypeOf(err).String())
	}
}

func (t *TestSuite) TestTCPHeader_MarshalWithChecksum(c *C) {
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
	c.Check(err, Equals, packets.ErrTCPDataOffsetInvalid)

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
