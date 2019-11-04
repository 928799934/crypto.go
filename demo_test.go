package crypto

import (
	"crypto/md5"
	"github.com/928799934/crypto.go/aes"
	"github.com/928799934/crypto.go/des"
	"github.com/928799934/crypto.go/hmac"
	"github.com/928799934/crypto.go/padding"
	"github.com/928799934/crypto.go/tea"
	"testing"
)

func Benchmark_TEA8(b *testing.B) {
	src := []byte("abcdefg")
	key := [16]byte{}
	for i, v := range []byte("testkey") {
		key[i] = v
	}
	te := tea.NewTEA([]byte("testkey"), tea.Wheel8Chunk, padding.PKCS5)
	for i := 0; i < b.N; i++ {
		dest, _ := te.Encrypt(src)
		src, _ = te.Decrypt(dest)
	}
}

func Benchmark_TEA16(b *testing.B) {
	src := []byte("abcdefg")
	key := [16]byte{}
	for i, v := range []byte("testkey") {
		key[i] = v
	}
	te := tea.NewTEA([]byte("testkey"), tea.Wheel16Chunk, padding.PKCS5)
	for i := 0; i < b.N; i++ {
		dest, _ := te.Encrypt(src)
		src, _ = te.Decrypt(dest)
	}
}

func Benchmark_AES_CBC(b *testing.B) {
	src := []byte("abcdefg")
	key := []byte("1111111111111111")
	for i := 0; i < b.N; i++ {
		dest, _ := aes.CBCEncrypt(src, key, key, padding.PKCS5)
		src, _ = aes.CBCDecrypt(dest, key, key, padding.PKCS5)
	}
}

func Benchmark_AES_ECB(b *testing.B) {
	src := []byte("abcdefg")
	key := []byte("1111111111111111")
	for i := 0; i < b.N; i++ {
		dest, _ := aes.ECBEncrypt(src, key, padding.PKCS5)
		src, _ = aes.ECBDecrypt(dest, key, padding.PKCS5)
	}
}

func Benchmark_DES_CBC(b *testing.B) {
	src := []byte("abcdefg")
	key := []byte("11111111")
	for i := 0; i < b.N; i++ {
		dest, _ := des.CBCEncrypt(src, key, key, padding.PKCS5)
		src, _ = des.CBCDecrypt(dest, key, key, padding.PKCS5)
	}
}

func Benchmark_MD5(b *testing.B) {
	src := []byte("abcdefg")
	md := md5.New()
	for i := 0; i < b.N; i++ {
		md.Sum(src)
	}
}

func Benchmark_HMAC(b *testing.B) {
	src := []byte("abcdefg")
	key := []byte("testkey")
	for i := 0; i < b.N; i++ {
		hmac.HmacSha1(key, src)
	}
}
