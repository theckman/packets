package packets

import (
	"bytes"
	"encoding/binary"
)

// ChecksumIPv4 is a function for computing the TCP checksum of an IPv4 packet. The kind
// field is either 'tcp' or 'udp' and returns an error if invalid input is given.
//
// The returned error type may be ErrChecksumInvalidKind if an invalid kind field
// is provided.
func ChecksumIPv4(data []byte, kind, laddr, raddr string) (uint16, error) {
	// convert the IP address strings to their byte equivalents
	srcBytes, dstBytes := ipv4AddrToBytes(laddr), ipv4AddrToBytes(raddr)

	var protocol uint8

	switch kind {
	case "tcp", "TCP":
		protocol = 6
	case "udp", "UDP":
		protocol = 17
	default:
		return 0, ErrChecksumInvalidKind{
			E: "Checksum kind should either be 'tcp' OR 'udp'.",
		}
	}

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
	binary.Write(pHeader, binary.BigEndian, protocol)
	binary.Write(pHeader, binary.BigEndian, uint16(len(data)))
	pHeader.Write(data)

	return checksum(pHeader.Bytes()), nil
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
