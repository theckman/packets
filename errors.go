// Copyright 2015 Tim Heckman. All rights reserved.
// Use of this source code is governed by the BSD 3-Clause
// license that can be found in the LICENSE file.

package packets

// ErrTCPDataOffsetInvalid is a type that implements the error interface. It's used for errors
// marshaling the TCPHeader data. You can type assert against it to handle that input
// differently.
type ErrTCPDataOffsetInvalid struct {
	E string
}

func (e ErrTCPDataOffsetInvalid) Error() string {
	return e.E
}

// ErrTCPDataOffsetTooSmall is a type that implements the error interface. It's used for errors
// marshaling the TCPHeader data. Specifically, this is used when the DataOffset is too small
// for the amount of data in the TCP header.
type ErrTCPDataOffsetTooSmall struct {
	E string
}

func (e ErrTCPDataOffsetTooSmall) Error() string {
	return e.E
}

// ErrTCPOptionsOverflow is a type that implements the error interface. It's used for errors
// marshaling the TCPHeader data. Specifically, this is used when the TCP Options field exceeds
// its maximum length as specified by the RFC.
type ErrTCPOptionsOverflow struct {
	E string
}

func (e ErrTCPOptionsOverflow) Error() string {
	return e.E
}

// ErrTCPOptionDataInvalid is a type that implements the error interface. It's used for errors
// marshaling the TCPHeader data. Specifically, this is used when the TCP Options Length field
// doesn't match the data provided.
type ErrTCPOptionDataInvalid struct {
	E string
}

func (e ErrTCPOptionDataInvalid) Error() string {
	return e.E
}

// ErrTCPOptionDataTooLong is a type that implements the error interface. It's used for errors
// marshaling the TCPHeader data. Specifically, this is use for when the TCP Options Data field is
// too long for the Options field as per the RFC.
type ErrTCPOptionDataTooLong struct {
	E string
}

func (e ErrTCPOptionDataTooLong) Error() string {
	return e.E
}
