package aes

import (
	iaes "crypto/aes"
	icipher "crypto/cipher"
	"errors"
	"github.com/928799934/crypto.go/cipher"
	"github.com/928799934/crypto.go/padding"
)

var (
	// ErrAesBlockSize ...
	ErrAesBlockSize = errors.New("plaintext is not a multiple of the block size")
	// ErrAesSrcSize ...
	ErrAesSrcSize = errors.New("ciphertext too short")
	// ErrAesIVSize ...
	ErrAesIVSize = errors.New("iv size is not a block size")
)

// ECBEncrypt aes ecb encrypt.
func ECBEncrypt(src, key []byte, p padding.Padding) ([]byte, error) {
	if p == nil {
		if len(src) < iaes.BlockSize || len(src)%iaes.BlockSize != 0 {
			return nil, ErrAesBlockSize
		}
	} else {
		src = p.Padding(src, iaes.BlockSize)
	}
	b, err := iaes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	mode := cipher.NewECBEncrypter(b)
	encryptText := make([]byte, len(src))
	mode.CryptBlocks(encryptText, src)
	return encryptText, nil
}

// ECBDecrypt aes ecb decrypt.
func ECBDecrypt(src, key []byte, p padding.Padding) ([]byte, error) {
	b, err := iaes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	mode := cipher.NewECBDecrypter(b)
	decryptText := make([]byte, len(src))
	mode.CryptBlocks(decryptText, src)
	if p == nil {
		// if no padding check src
		if len(decryptText) < iaes.BlockSize || len(decryptText)%iaes.BlockSize != 0 {
			return nil, ErrAesSrcSize
		}
	} else {
		return p.Unpadding(decryptText, iaes.BlockSize)
	}
	return decryptText, nil
}

// CBCEncrypt aes cbc encrypt.
func CBCEncrypt(src, key, iv []byte, p padding.Padding) ([]byte, error) {
	// check iv
	if len(iv) != iaes.BlockSize {
		return nil, ErrAesIVSize
	}
	if p == nil {
		// if no padding check src
		if len(src) < iaes.BlockSize || len(src)%iaes.BlockSize != 0 {
			return nil, ErrAesSrcSize
		}
	} else {
		// padding
		src = p.Padding(src, iaes.BlockSize)
	}
	block, err := iaes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	mode := icipher.NewCBCEncrypter(block, iv)
	encryptText := make([]byte, len(src))
	mode.CryptBlocks(encryptText, src)
	return encryptText, nil
}

// CBCDecrypt aes cbc decrypt.
func CBCDecrypt(src, key, iv []byte, p padding.Padding) ([]byte, error) {
	// check iv
	if len(iv) != iaes.BlockSize {
		return nil, ErrAesIVSize
	}
	block, err := iaes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	mode := icipher.NewCBCDecrypter(block, iv)
	decryptText := make([]byte, len(src))
	mode.CryptBlocks(decryptText, src)
	if p == nil {
		// if no padding check src
		if len(decryptText) < iaes.BlockSize || len(decryptText)%iaes.BlockSize != 0 {
			return nil, ErrAesSrcSize
		}
	} else {
		return p.Unpadding(decryptText, iaes.BlockSize)
	}
	return decryptText, nil
}

// CFBEncrypt aes cbc encrypt.
func CFBEncrypt(src, key, iv []byte, p padding.Padding) ([]byte, error) {
	// check iv
	if len(iv) != iaes.BlockSize {
		return nil, ErrAesIVSize
	}
	if p == nil {
		// if no padding check src
		if len(src) < iaes.BlockSize || len(src)%iaes.BlockSize != 0 {
			return nil, ErrAesSrcSize
		}
	} else {
		// padding
		src = p.Padding(src, iaes.BlockSize)
	}
	block, err := iaes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	mode := icipher.NewCFBEncrypter(block, iv)
	encryptText := make([]byte, len(src))

	mode.XORKeyStream(encryptText, src)
	return encryptText, nil
}

// CFBDecrypt aes cbc decrypt.
func CFBDecrypt(src, key, iv []byte, p padding.Padding) ([]byte, error) {
	// check iv
	if len(iv) != iaes.BlockSize {
		return nil, ErrAesIVSize
	}
	block, err := iaes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	mode := icipher.NewCFBDecrypter(block, iv)
	decryptText := make([]byte, len(src))
	mode.XORKeyStream(decryptText, src)
	if p == nil {
		// if no padding check src
		if len(decryptText) < iaes.BlockSize || len(decryptText)%iaes.BlockSize != 0 {
			return nil, ErrAesSrcSize
		}
	} else {
		return p.Unpadding(decryptText, iaes.BlockSize)
	}
	return decryptText, nil
}
