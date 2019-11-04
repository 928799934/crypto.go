package padding

var (
	// ZERO ...
	ZERO = &zero{}
)

// pkcs5Padding is a pkcs5 padding struct.
type zero struct{}

// Padding implements the Padding interface Padding method.
func (p *zero) Padding(src []byte, blockSize int) []byte {
	srcLen := len(src)
	padLen := byte(blockSize - (srcLen % blockSize))
	pd := make([]byte, srcLen+int(padLen))
	copy(pd, src)
	for i := srcLen; i < len(pd); i++ {
		pd[i] = 0
	}
	return pd
}

// Unpadding implements the Padding interface Unpadding method.
func (p *zero) Unpadding(src []byte, blockSize int) ([]byte, error) {
	srcLen := len(src)
	paddingLen := 1
	for i := srcLen - 1; i > 0; i-- {
		if src[i] != 0 {
			paddingLen += i
			break
		}
	}
	return src[:paddingLen], nil
}
