package padding

var (
	// NO ...
	NO = &no{}
)

// pkcs5Padding is a pkcs5 padding struct.
type no struct{}

// Padding implements the Padding interface Padding method.
func (p *no) Padding(src []byte, blockSize int) []byte {
	return src
}

// Unpadding implements the Padding interface Unpadding method.
func (p *no) Unpadding(src []byte, blockSize int) ([]byte, error) {
	return src, nil
}
