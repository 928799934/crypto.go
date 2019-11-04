package tea

import (
	"encoding/binary"
	"errors"
	"github.com/928799934/crypto.go/padding"
)

var (
	ErrBlockSize   error          = errors.New("plaintext is not a multiple of the block size")
	ErrPaddingSize error          = errors.New("padding size error")
	delta          uint32         = 0x9e3779b9
	blockSize      int            = 8
	byteSize       int            = 4
	byte2Size      int            = 4 * 2
	wheelChunk     map[uint32]int = map[uint32]int{
		Wheel2Chunk:  2,
		Wheel4Chunk:  4,
		Wheel8Chunk:  8,
		Wheel16Chunk: 16,
		Wheel32Chunk: 32,
		Wheel64Chunk: 64,
	}
)

const (
	Wheel2Chunk  uint32 = 1
	Wheel4Chunk  uint32 = 2
	Wheel8Chunk  uint32 = 3
	Wheel16Chunk uint32 = 4
	Wheel32Chunk uint32 = 5
	Wheel64Chunk uint32 = 6
)

func encryptTEA(firstChunk, secondChunk uint32, key [4]uint32, wheel uint32) (uint32, uint32) {
	var (
		sum  uint32
		y, z uint32 = firstChunk, secondChunk
	)
	for i, max_wheel := 0, wheelChunk[wheel]; i < max_wheel; i++ {
		sum = sum + delta
		y = y + ((z<<4 + key[0]) ^ (z + sum) ^ (z>>5 + key[1]))
		z = z + ((y<<4 + key[2]) ^ (y + sum) ^ (y>>5 + key[3]))
	}
	return y, z
}

func decryptTEA(firstChunk, secondChunk uint32, key [4]uint32, wheel uint32) (uint32, uint32) {
	var (
		sum  uint32 = delta << wheel
		y, z uint32 = firstChunk, secondChunk
	)
	for i, max_wheel := 0, wheelChunk[wheel]; i < max_wheel; i++ {
		z = z - ((y<<4 + key[2]) ^ (y + sum) ^ (y>>5 + key[3]))
		y = y - ((z<<4 + key[0]) ^ (z + sum) ^ (z>>5 + key[1]))
		sum = sum - delta
	}
	return y, z
}

func Encrypt(src []byte, key [16]byte, p padding.Padding) ([]byte, error) {
	src = p.Padding(src, blockSize)
	keyArr := [4]uint32{
		binary.LittleEndian.Uint32(key[0:4]),
		binary.LittleEndian.Uint32(key[4:8]),
		binary.LittleEndian.Uint32(key[8:12]),
		binary.LittleEndian.Uint32(key[12:16]),
	}
	var firstChunk, secondChunk uint32
	i, max := 0, len(src)
	for i < max {
		firstChunk = binary.LittleEndian.Uint32(src[i : i+byteSize])
		secondChunk = binary.LittleEndian.Uint32(src[i+byteSize : i+byte2Size])
		firstChunk, secondChunk =
			encryptTEA(firstChunk, secondChunk, keyArr, Wheel8Chunk)
		binary.LittleEndian.PutUint32(src[i:i+byteSize], firstChunk)
		binary.LittleEndian.PutUint32(src[i+byteSize:i+byte2Size], secondChunk)
		i = i + byte2Size
	}
	return src, nil
}

func Decrypt(dest []byte, key [16]byte, p padding.Padding) ([]byte, error) {
	if len(dest) < blockSize || len(dest)%blockSize != 0 {
		return nil, ErrBlockSize
	}
	keyArr := [4]uint32{
		binary.LittleEndian.Uint32(key[0:4]),
		binary.LittleEndian.Uint32(key[4:8]),
		binary.LittleEndian.Uint32(key[8:12]),
		binary.LittleEndian.Uint32(key[12:16]),
	}
	var firstChunk, secondChunk uint32
	i, max := 0, len(dest)
	for i < max {
		firstChunk = binary.LittleEndian.Uint32(dest[i : i+byteSize])
		secondChunk = binary.LittleEndian.Uint32(dest[i+byteSize : i+byte2Size])
		firstChunk, secondChunk =
			decryptTEA(firstChunk, secondChunk, keyArr, Wheel8Chunk)
		binary.LittleEndian.PutUint32(dest[i:i+byteSize], firstChunk)
		binary.LittleEndian.PutUint32(dest[i+byteSize:i+byte2Size], secondChunk)
		i = i + byte2Size
	}
	return p.Unpadding(dest, blockSize)
}

type TEA struct {
	keyArr [4]uint32
	wheel  uint32
	p      padding.Padding
}

func NewTEAPKCS5(key []byte, wheel uint32) *TEA {
	return NewTEA(key, wheel, padding.PKCS5)
}

func NewTEA(key []byte, wheel uint32, p padding.Padding) *TEA {
	tmpKey := [16]byte{}
	for i, v := range key {
		if i == 16 {
			break
		}
		tmpKey[i] = v
	}
	keyArr := [4]uint32{
		binary.LittleEndian.Uint32(tmpKey[0:4]),
		binary.LittleEndian.Uint32(tmpKey[4:8]),
		binary.LittleEndian.Uint32(tmpKey[8:12]),
		binary.LittleEndian.Uint32(tmpKey[12:16]),
	}
	tea := &TEA{keyArr, wheel, p}
	return tea
}

func (this *TEA) Encrypt(src []byte) ([]byte, error) {
	src = this.p.Padding(src, blockSize)
	var firstChunk, secondChunk uint32
	i, max := 0, len(src)
	for i < max {
		firstChunk = binary.LittleEndian.Uint32(src[i : i+byteSize])
		secondChunk = binary.LittleEndian.Uint32(src[i+byteSize : i+byte2Size])
		firstChunk, secondChunk =
			encryptTEA(firstChunk, secondChunk, this.keyArr, this.wheel)
		binary.LittleEndian.PutUint32(src[i:i+byteSize], firstChunk)
		binary.LittleEndian.PutUint32(src[i+byteSize:i+byte2Size], secondChunk)
		i = i + byte2Size
	}
	return src, nil
}

func (this *TEA) Decrypt(dest []byte) ([]byte, error) {
	if len(dest) < blockSize || len(dest)%blockSize != 0 {
		return nil, ErrBlockSize
	}
	var firstChunk, secondChunk uint32
	i, max := 0, len(dest)
	for i < max {
		firstChunk = binary.LittleEndian.Uint32(dest[i : i+byteSize])
		secondChunk = binary.LittleEndian.Uint32(dest[i+byteSize : i+byte2Size])
		firstChunk, secondChunk =
			decryptTEA(firstChunk, secondChunk, this.keyArr, this.wheel)
		binary.LittleEndian.PutUint32(dest[i:i+byteSize], firstChunk)
		binary.LittleEndian.PutUint32(dest[i+byteSize:i+byte2Size], secondChunk)
		i = i + byte2Size
	}
	return this.p.Unpadding(dest, blockSize)
}
