package packets

import (
	"bytes"
	"encoding/binary"
	"math"
	"strconv"
	"strings"
)

// These are the control (CTRL) bits of the TCP header. We primarily use these
// for calculating how many bits to shift to get/set them within the header.
const (
	nsBit  uint16 = 256 // NS
	cwrBit uint16 = 128 // CWR
	eceBit uint16 = 64  // ECE
	urgBit uint16 = 32  // URG
	ackBit uint16 = 16  // ACK
	pshBit uint16 = 8   // PSH
	rstBit uint16 = 4   // RST
	synBit uint16 = 2   // SYN
	finBit uint16 = 1   // FIN
)

// TCPHeader is a struct representing a TCP header. The options portion
// of the TCP header is not implemented in this struct.
//
// This struct is a simplified representation of a TCP header. This includes
// making the control (CTRL) bits boolean fields, instead of forcing users of
// this package to do their own bitshifting.
type TCPHeader struct {
	SourcePort      uint16
	DestinationPort uint16
	SeqNum          uint32
	AckNum          uint32
	DataOffset      uint8 // should be either 0 or >= 5 or <=15 (default: 5)
	Reserved        uint8 // this should always be 0
	NS              bool
	CWR             bool
	ECE             bool
	URG             bool
	ACK             bool
	PSH             bool
	RST             bool
	SYN             bool
	FIN             bool
	WindowSize      uint16 // if set to 0 this becomes 65535
	Checksum        uint16 // suggest setting this to 0 thus offloading to the kernel
	UrgentPointer   uint16
}

// UnmarshalTCPHeader is a function that takes a byte slice and parses it in to an
// instance of *TCPHeader.
func UnmarshalTCPHeader(data []byte) (*TCPHeader, error) {
	return unmarshalTCPHeader(data)
}

// Marshal is a function to marshal the *TCPHeader instance to a byte slice
// without explicitly calculating the checksum for the data. Because there is no
// checksumming of the data, the local and remote addresses are not required.
//
// To note, if the checksum is not provided (i.e. 0) the kernel SHOULD automatically
// calculate this for you.
//
// However, if the *TCPHeader instance has the Checksum field set, it will be
// included in the marshaled data.
func (tcp *TCPHeader) Marshal() ([]byte, error) {
	return tcp.marshalTCPHeader()
}

// MarshalWithChecksum is a function to marshal the TCPHeader to a byte slice.
// This function is almost the same as Marshal() However, this calculates also
// the TCP checksum and adds it to the header / marshaled data.
//
// It's suggested that you use Marshal() instead and offload the
// checksumming to your kernel (which should do it automatically if not present).
func (tcp *TCPHeader) MarshalWithChecksum(laddr, raddr string) ([]byte, error) {
	// marshal the header
	data, err := tcp.marshalTCPHeader()

	if err != nil {
		return nil, err
	}

	// calculate the checksum using the data that was marshaled
	tcp.Checksum = ChecksumIPv4(data, laddr, raddr)

	// remarshal again, with a proper Checksum this time
	fullData, err := tcp.marshalTCPHeader()

	if err != nil {
		return nil, err
	}

	return fullData, nil
}

// ChecksumIPv4 is a function for computing the TCP checksum of an IPv4 packet.
func ChecksumIPv4(data []byte, laddr, raddr string) uint16 {
	// convert the IP address strings to their byte equivalents
	srcBytes, dstBytes := ipv4AddrToBytes(laddr), ipv4AddrToBytes(raddr)

	// create a pseudo header for the packet checksumming
	pHeader := new(bytes.Buffer)

	binary.Write(pHeader, binary.BigEndian, srcBytes[0])
	binary.Write(pHeader, binary.BigEndian, srcBytes[1])
	binary.Write(pHeader, binary.BigEndian, srcBytes[2])
	binary.Write(pHeader, binary.BigEndian, srcBytes[3])
	binary.Write(pHeader, binary.BigEndian, dstBytes[0])
	binary.Write(pHeader, binary.BigEndian, dstBytes[1])
	binary.Write(pHeader, binary.BigEndian, dstBytes[2])
	binary.Write(pHeader, binary.BigEndian, dstBytes[3])
	binary.Write(pHeader, binary.BigEndian, uint8(0))
	binary.Write(pHeader, binary.BigEndian, uint8(6))
	binary.Write(pHeader, binary.BigEndian, uint16(len(data)))
	pHeader.Write(data)

	return checksum(pHeader.Bytes())
}

func (tcp *TCPHeader) marshalTCPHeader() ([]byte, error) {
	// if the field is the type's default, and an obviously invalid value
	// then just set it to the bare minimum for the TCP header.
	if tcp.DataOffset == 0 {
		tcp.DataOffset = 5
	}

	// if the offset is outside of the acceptable range
	// fail with a DataOffsetInvalid error
	if tcp.DataOffset > 15 || tcp.DataOffset < 5 {
		return nil, DataOffsetInvalid{E: "DataOffset field must be at least 5 and no more than 15"}
	}

	// if the WindowSize field is the default let's set it to something better
	if tcp.WindowSize == 0 {
		tcp.WindowSize = 65535
	}

	// build the DataOffset, Reserved, and Control Flags data
	ctrl := uint16(tcp.DataOffset)<<12 |
		uint16(tcp.Reserved)<<9 |
		ctrlBitSet(tcp.NS, nsBit) |
		ctrlBitSet(tcp.CWR, cwrBit) |
		ctrlBitSet(tcp.ECE, eceBit) |
		ctrlBitSet(tcp.URG, urgBit) |
		ctrlBitSet(tcp.ACK, ackBit) |
		ctrlBitSet(tcp.PSH, pshBit) |
		ctrlBitSet(tcp.RST, rstBit) |
		ctrlBitSet(tcp.SYN, synBit) |
		ctrlBitSet(tcp.FIN, finBit)

	buf := new(bytes.Buffer)

	// write all the data to the byte buffer
	binary.Write(buf, binary.BigEndian, tcp.SourcePort)
	binary.Write(buf, binary.BigEndian, tcp.DestinationPort)
	binary.Write(buf, binary.BigEndian, tcp.SeqNum)
	binary.Write(buf, binary.BigEndian, tcp.AckNum)
	binary.Write(buf, binary.BigEndian, ctrl)
	binary.Write(buf, binary.BigEndian, tcp.WindowSize)
	binary.Write(buf, binary.BigEndian, tcp.Checksum)
	binary.Write(buf, binary.BigEndian, tcp.UrgentPointer)

	return buf.Bytes(), nil
}

func checksum(data []byte) uint16 {
	dataSize := len(data) - 1

	var sum uint32

	for i := 0; i+1 < dataSize; i += 2 {
		sum += uint32(data[i+1])<<8 | uint32(data[i])
	}

	if dataSize&1 == 1 {
		sum += uint32(data[dataSize])
	}

	sum = sum>>16 + sum&0xffff
	sum = sum + sum>>16

	return ^uint16(sum)
}

// ipv4AddrToBytes converts an IPv4 address to its four individual pieces in bytes
func ipv4AddrToBytes(addr string) []byte {
	o := strings.Split(addr, ".")

	o0, _ := strconv.Atoi(o[0])
	o1, _ := strconv.Atoi(o[1])
	o2, _ := strconv.Atoi(o[2])
	o3, _ := strconv.Atoi(o[3])

	return []byte{byte(o0), byte(o1), byte(o2), byte(o3)}
}

func ctrlBitSet(value bool, bit uint16) uint16 {
	// if the value is false, set it to zero
	if !value {
		return 0
	}

	// flip the bit in a uint16 so that we can bitwise OR it
	// with our existing value
	//
	// figure out how many bits we need to shift to set what we want
	shift := uint(math.Log2(float64(bit)))

	return uint16(1) << shift
}

func ctrlBitValue(ctrl uint16, bit uint16) bool {
	// figure out how many bits we need to shift to get what we want
	shift := uint(math.Log2(float64(bit)))

	// if the bit is one, return true
	if ctrl>>shift&1 == 1 {
		return true
	}

	// otherwise false
	return false
}

func unmarshalTCPHeader(data []byte) (*TCPHeader, error) {
	var header TCPHeader
	var ctrl uint16

	reader := bytes.NewReader(data)

	// pull all the fields from the data
	binary.Read(reader, binary.BigEndian, &header.SourcePort)
	binary.Read(reader, binary.BigEndian, &header.DestinationPort)
	binary.Read(reader, binary.BigEndian, &header.SeqNum)
	binary.Read(reader, binary.BigEndian, &header.AckNum)
	binary.Read(reader, binary.BigEndian, &ctrl)
	binary.Read(reader, binary.BigEndian, &header.WindowSize)
	binary.Read(reader, binary.BigEndian, &header.Checksum)
	binary.Read(reader, binary.BigEndian, &header.UrgentPointer)

	header.DataOffset = uint8(ctrl >> 12)
	header.Reserved = uint8(ctrl >> 9 & 7)

	// We need to convert the control flags to their boolean counterparts.
	// Each control flag is one bit in size, so shift that bit to the end
	// and use a bitwise AND of 1 to see if it's enabled.
	header.NS = ctrlBitValue(ctrl, nsBit)
	header.CWR = ctrlBitValue(ctrl, cwrBit)
	header.ECE = ctrlBitValue(ctrl, eceBit)
	header.URG = ctrlBitValue(ctrl, urgBit)
	header.ACK = ctrlBitValue(ctrl, ackBit)
	header.PSH = ctrlBitValue(ctrl, pshBit)
	header.RST = ctrlBitValue(ctrl, rstBit)
	header.SYN = ctrlBitValue(ctrl, synBit)
	header.FIN = ctrlBitValue(ctrl, finBit)

	return &header, nil
}
