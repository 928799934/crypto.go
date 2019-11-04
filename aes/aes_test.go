package aes

import (
	"encoding/base64"
	"github.com/928799934/crypto.go/padding"
	"testing"
)

func TestECB(t *testing.T) {
	a := []byte("111111111111111111")
	k := []byte("aaaaaaaaaaaaaaaa")
	b, err := ECBEncrypt(a, k, padding.PKCS5)
	if err != nil {
		t.Error(err)
	}
	c, err := ECBDecrypt(b, k, padding.PKCS5)
	if err != nil {
		t.Error(err)
	}
	if string(a) != string(c) {
		t.Error("decrypt error")
	}
	d := []byte("1")
	b, err = ECBEncrypt(d, k, padding.PKCS5)
	if err != nil {
		t.Error(err)
	}
	c, err = ECBDecrypt(b, k, padding.PKCS5)
	if err != nil {
		t.Error(err)
	}
	if string(d) != string(c) {
		t.Error("decrypt error")
	}
}

func TestCBC(t *testing.T) {
	a := []byte("0123456789abcdef")
	k := []byte("aaaaaaaaaaaaaaaa")
	b, err := CBCEncrypt(a, k, a, padding.PKCS5)
	if err != nil {
		t.Error(err)
	}
	c, err := CBCDecrypt(b, k, a, padding.PKCS5)
	if err != nil {
		t.Error(err)
	}
	if string(a) != string(c) {
		t.Error("decrypt error")
	}
	d := []byte("1")
	b, err = CBCEncrypt(d, a, a, padding.PKCS5)
	if err != nil {
		t.Error(err)
	}
	c, err = CBCDecrypt(b, a, a, padding.PKCS5)
	if err != nil {
		t.Error(err)
	}
	if string(d) != string(c) {
		t.Error("decrypt error")
	}
}

func TestCFB(t *testing.T) {
	a := []byte(`[{"user":"0708efd1ac030e53c6fac335e85b2208017b1ef9"}]`)
	k := []byte("UVed-5vkWh~m3k-ZAbvoaOg~-z:2d;Es")

	iv := []byte("0123456789abcdef")
	b, err := CFBEncrypt(a, k, iv, padding.NO)
	if err != nil {
		t.Error(err)
	}
	dd := append([]byte{}, iv...)
	dd = append(dd, b...)
	dest := base64.StdEncoding.EncodeToString(dd)
	dd, _ = base64.StdEncoding.DecodeString(dest)
	iv = dd[:16]
	b = dd[16:]
	c, err := CFBDecrypt(b, k, iv, padding.NO)
	if err != nil {
		t.Error(err)
	}
	if string(a) != string(c) {
		t.Error("decrypt error")
	}
}
