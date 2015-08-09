// Copyright 2015 Tim Heckman. All rights reserved.
// Use of this source code is governed by the BSD 3-Clause
// license that can be found in the LICENSE file.

package packets

// TCPDataOffsetInvalid is a type that implements the error interface. It's used for errors
// marshaling the TCPHeader data. You can type assert against it to handle that input
// differently.
type TCPDataOffsetInvalid struct {
	E string
}

func (e TCPDataOffsetInvalid) Error() string {
	return e.E
}

// TCPDataOffsetTooSmall is a type that implements the error interface. It's used for errors
// marshaling the TCPHeader data. Specifically, this is used when the DataOffset is too small
// for the amount of data in the TCP header.
type TCPDataOffsetTooSmall struct {
	E string
}

func (e TCPDataOffsetTooSmall) Error() string {
	return e.E
}

// TCPOptionsOverflow is a type that implements the error interface. It's used for errors
// marshaling the TCPHeader data. Specifically, this is used when the TCP Options field exceeds
// its maximum length as specified by the RFC.
type TCPOptionsOverflow struct {
	E string
}

func (e TCPOptionsOverflow) Error() string {
	return e.E
}

// TCPOptionDataInvalid is a type that implements the error interface. It's used for errors
// marshaling the TCPHeader data. Specifically, this is used when the TCP Options Length field
// doesn't match the data provided.
type TCPOptionDataInvalid struct {
	E string
}

func (e TCPOptionDataInvalid) Error() string {
	return e.E
}

// TCPOptionDataTooLong is a type that implements the error interface. It's used for errors
// marshaling the TCPHeader data. Specifically, this is use for when the TCP Options Data field is
// too long for the Options field as per the RFC.
type TCPOptionDataTooLong struct {
	E string
}

func (e TCPOptionDataTooLong) Error() string {
	return e.E
}
