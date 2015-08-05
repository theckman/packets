package packets

// DataOffsetInvalid is a type that implements the error interface. It's used for errors
// marshaling the TCPHeader data. You can type assert against it to handle that input
// differently
type DataOffsetInvalid struct {
	E string
}

func (e DataOffsetInvalid) Error() string {
	return e.E
}
