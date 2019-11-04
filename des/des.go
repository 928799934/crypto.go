package des

import (
	icipher "crypto/cipher"
	ides "crypto/des"
	"errors"
	"github.com/928799934/crypto.go/cipher"
	"github.com/928799934/crypto.go/padding"
)

var (
	ErrDesBlockSize = errors.New("plaintext is not a multiple of the block size")
	ErrDesSrcSize   = errors.New("ciphertext too short")
	ErrDesIVSize    = errors.New("iv size is not a block size")
)

// ECBEncrypt aes ecb encrypt.
func ECBEncrypt(src, key []byte, p padding.Padding) ([]byte, error) {
	if p == nil {
		if len(src) < ides.BlockSize || len(src)%ides.BlockSize != 0 {
			return nil, ErrDesBlockSize
		}
	} else {
		src = p.Padding(src, ides.BlockSize)
	}
	block, err := ides.NewCipher(key)
	if err != nil {
		return nil, err
	}
	mode := cipher.NewECBEncrypter(block)
	encryptText := make([]byte, len(src))
	mode.CryptBlocks(encryptText, src)
	return encryptText, nil
}

// ECBDecrypt aes cbc decrypt.
func ECBDecrypt(src, key []byte, p padding.Padding) ([]byte, error) {
	if len(src) < ides.BlockSize || len(src)%ides.BlockSize != 0 {
		return nil, ErrDesSrcSize
	}
	block, err := ides.NewCipher(key)
	if err != nil {
		return nil, err
	}
	mode := cipher.NewECBDecrypter(block)
	decryptText := make([]byte, len(src))
	mode.CryptBlocks(decryptText, src)
	if p == nil {
		return decryptText, nil
	} else {
		return p.Unpadding(decryptText, ides.BlockSize)
	}
}

// CBCEncrypt aes ecb encrypt.
func CBCEncrypt(src, key, iv []byte, p padding.Padding) ([]byte, error) {
	if len(iv) != ides.BlockSize {
		return nil, ErrDesIVSize
	}
	block, err := ides.NewCipher(key)
	if err != nil {
		return nil, err
	}
	if p == nil {
		if len(src) < ides.BlockSize || len(src)%ides.BlockSize != 0 {
			return nil, ErrDesSrcSize
		}
	} else {
		src = p.Padding(src, ides.BlockSize)
	}
	mode := icipher.NewCBCEncrypter(block, iv)
	encryptText := make([]byte, len(src))
	mode.CryptBlocks(encryptText, src)
	return encryptText, nil
}

// CBCDecrypt aes cbc decrypt.
func CBCDecrypt(src, key, iv []byte, p padding.Padding) ([]byte, error) {
	if len(src) < ides.BlockSize || len(src)%ides.BlockSize != 0 {
		return nil, ErrDesSrcSize
	}
	if len(iv) != ides.BlockSize {
		return nil, ErrDesIVSize
	}
	block, err := ides.NewCipher(key)
	if err != nil {
		return nil, err
	}
	mode := icipher.NewCBCDecrypter(block, iv)
	decryptText := make([]byte, len(src))
	mode.CryptBlocks(decryptText, src)
	if p == nil {
		return decryptText, nil
	} else {
		return p.Unpadding(decryptText, ides.BlockSize)
	}
}

// CBCEncrypt aes ecb encrypt.
func TripleCBCEncrypt(src, key, iv []byte, p padding.Padding) ([]byte, error) {
	if len(iv) != ides.BlockSize {
		return nil, ErrDesIVSize
	}
	block, err := ides.NewTripleDESCipher(key)
	if err != nil {
		return nil, err
	}
	if p == nil {
		if len(src) < ides.BlockSize*3 || len(src)%ides.BlockSize != 0 {
			return nil, ErrDesSrcSize
		}
	} else {
		src = p.Padding(src, ides.BlockSize)
	}
	mode := icipher.NewCBCEncrypter(block, iv)
	encryptText := make([]byte, len(src))
	mode.CryptBlocks(encryptText, src)
	return encryptText, nil
}

// CBCDecrypt aes cbc decrypt.
func TripleCBCDecrypt(src, key, iv []byte, p padding.Padding) ([]byte, error) {
	if len(key) < ides.BlockSize*3 || len(key)%ides.BlockSize != 0 {
		return nil, ErrDesSrcSize
	}
	if len(iv) != ides.BlockSize {
		return nil, ErrDesIVSize
	}
	block, err := ides.NewTripleDESCipher(key)
	if err != nil {
		return nil, err
	}
	mode := icipher.NewCBCDecrypter(block, iv)
	decryptText := make([]byte, len(src))
	mode.CryptBlocks(decryptText, src)
	if p == nil {
		return decryptText, nil
	} else {
		return p.Unpadding(decryptText, ides.BlockSize*3)
	}
}

// TripleDESEncode
func TripleDESEncode(data, key []byte) (rb []byte, err error) {
	if len(key) != 16 && len(key) != 24 {
		err = errors.New("key length error, must be 16 or 24")
		return
	}
	tripleDESKey := make([]byte, 0, 24)
	if len(key) == 16 {
		tripleDESKey = append(tripleDESKey, key[:16]...)
		tripleDESKey = append(tripleDESKey, key[:8]...)
	} else {
		tripleDESKey = append(tripleDESKey, key[:]...)
	}

	td, err := ides.NewTripleDESCipher(tripleDESKey)
	if err != nil {
		return
	}

	mod := len(data) % td.BlockSize()
	v := td.BlockSize() - mod

	for i := 0; i < v; i++ {
		data = append(data, byte(v))
	}

	n := len(data) / td.BlockSize()
	for i := 0; i < n; i++ {
		dst := make([]byte, td.BlockSize())
		td.Encrypt(dst, data[i*8:(i+1)*8])
		rb = append(rb, dst[:]...)
	}
	return
}
