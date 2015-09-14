// Copyright 2015 Tim Heckman. All rights reserved.
// Use of this source code is governed by the BSD 3-Clause
// license that can be found in the LICENSE file.

package packets

import (
	"errors"
	"fmt"
)

// ErrTCPDataOffsetInvalid is a type that implements the error interface. It's used for errors
// marshaling the TCPHeader data.
var ErrTCPDataOffsetInvalid = errors.New("DataOffset field must be at least 5 and no more than 15")

// ErrChecksumInvalidKind is a type that implements the error interface. It's used when
// an invalid packet kind is provided to the ChecksumIPv4 function.
var ErrChecksumInvalidKind = errors.New("Checksum kind should either be 'tcp' OR 'udp'.")

// ErrTCPDataOffsetTooSmall is a type that implements the error interface. It's used for errors
// marshaling the TCPHeader data. Specifically, this is used when the DataOffset is too small
// for the amount of data in the TCP header.
type ErrTCPDataOffsetTooSmall struct {
	ExpectedSize uint8
}

func (e ErrTCPDataOffsetTooSmall) Error() string {
	return fmt.Sprintf(
		"The DataOffset field is too small for the data provided. It should be at least %d",
		e.ExpectedSize,
	)
}

// ErrTCPOptionsOverflow is a type that implements the error interface. It's used for errors
// marshaling the TCPHeader data. Specifically, this is used when the TCP Options field exceeds
// its maximum length as specified by the RFC.
type ErrTCPOptionsOverflow struct {
	MaxSize int
}

func (e ErrTCPOptionsOverflow) Error() string {
	return fmt.Sprintf("TCP Options are too large, must be less than %d total bytes", e.MaxSize)
}

// ErrTCPOptionDataInvalid is a type that implements the error interface. It's used for errors
// marshaling the TCPHeader data. Specifically, this is used when the TCP Options Length field
// doesn't match the data provided.
type ErrTCPOptionDataInvalid struct {
	Index int
}

func (e ErrTCPOptionDataInvalid) Error() string {
	return fmt.Sprintf("Option %d Length doesn't match length of data", e.Index)
}

// ErrTCPOptionDataTooLong is a type that implements the error interface. It's used for errors
// marshaling the TCPHeader data. Specifically, this is use for when the TCP Options Data field is
// too long for the Options field as per the RFC.
type ErrTCPOptionDataTooLong struct {
	Index int
}

func (e ErrTCPOptionDataTooLong) Error() string {
	return fmt.Sprintf("Option %d Data cannot be larger than 253 bytes", e.Index)
}

// ErrUDPPayloadTooLarge is a type that implements the error interface. It's used for errors
// marshaling the UDPHeader data. Specifically, this is use for when the UDP payload is too large.
type ErrUDPPayloadTooLarge struct {
	MaxSize, Len int
}

func (e ErrUDPPayloadTooLarge) Error() string {
	return fmt.Sprintf(
		"UDP Payload must not be larger than %d byte, was %d bytes",
		e.MaxSize, e.Len,
	)
}
