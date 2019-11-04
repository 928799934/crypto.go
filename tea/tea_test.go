package tea

import (
	"github.com/928799934/crypto.go/padding"
	"testing"
)

func TestEncryptTEA(t *testing.T) {
	src := []byte("abcdefg")
	key := [16]byte{}
	for i, v := range []byte("testkey") {
		key[i] = v
	}
	dest, _ := Encrypt(src, key, padding.PKCS5)
	src, _ = Decrypt(dest, key, padding.PKCS5)
	if string(src) != "abcdefg" {
		t.Fail()
	}
	src = []byte("abcdefgh")
	tea := NewTEA([]byte("testkeyss"), Wheel32Chunk, padding.PKCS5)
	dest, _ = tea.Encrypt(src)
	src, _ = tea.Decrypt(dest)
	if string(src) != "abcdefgh" {
		t.Fail()
	}
}
