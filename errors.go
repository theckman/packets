// Copyright 2015 Tim Heckman. All rights reserved.
// Use of this source code is governed by the BSD 3-Clause
// license that can be found in the LICENSE file.

package packets

// DataOffsetInvalid is a type that implements the error interface. It's used for errors
// marshaling the TCPHeader data. You can type assert against it to handle that input
// differently.
type DataOffsetInvalid struct {
	E string
}

func (e DataOffsetInvalid) Error() string {
	return e.E
}

// DataOffsetTooSmall is a type that implements the error interface. It's used for errors
// marshaling the TCPHeader data. Specifically, this is used when the DataOffset is too small
// for the amount of data in the TCP header.
type DataOffsetTooSmall struct {
	E string
}

func (e DataOffsetTooSmall) Error() string {
	return e.E
}
