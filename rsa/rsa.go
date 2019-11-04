package rsa

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
)

type PublicKey rsa.PublicKey
type PrivateKey rsa.PrivateKey

// RSA校验签名
func RsaVerifySign(src, sign []byte, publicKey *PublicKey) error {
	public := (*rsa.PublicKey)(publicKey)
	hashed := sha1.Sum(src)
	return rsa.VerifyPKCS1v15(public, crypto.SHA1, hashed[:], sign)
}

// get public key by x509 base64 str
func GetPublicKeyByBase64Str(base64str string) (*PublicKey, error) {
	b, err := base64.StdEncoding.DecodeString(base64str)
	if err != nil {
		return nil, err
	}
	public, err := x509.ParsePKIXPublicKey(b)
	if err != nil {
		return nil, err
	}
	publicKey := public.(*rsa.PublicKey)
	return (*PublicKey)(publicKey), nil
}

// get pkcs8 private key by x509 base64 str
func GetPrivateKeyByBase64Str(base64str string) (*PrivateKey, error) {
	b, err := base64.StdEncoding.DecodeString(base64str)
	if err != nil {
		return nil, err
	}
	private, err := x509.ParsePKCS8PrivateKey(b)
	if err != nil {
		return nil, err
	}
	privateKey := private.(*rsa.PrivateKey)
	return (*PrivateKey)(privateKey), nil
}

// get pkcs1 private key by x509 base64 str
func GetPKCS1PrivateKeyByBase64Str(base64str string) (*PrivateKey, error) {
	b, err := base64.StdEncoding.DecodeString(base64str)
	if err != nil {
		return nil, err
	}
	private, err := x509.ParsePKCS1PrivateKey(b)
	if err != nil {
		return nil, err
	}
	return (*PrivateKey)(private), nil
}

// rsa base64 encrypt
func RsaEncrypt(src []byte, publicKey *PublicKey) ([]byte, error) {
	public := (*rsa.PublicKey)(publicKey)
	return rsa.EncryptPKCS1v15(rand.Reader, public, src)
}

// rsa base64 encrypt
func RsaDecrypt(src []byte, privateKey *PrivateKey) ([]byte, error) {
	private := (*rsa.PrivateKey)(privateKey)
	return rsa.DecryptPKCS1v15(nil, private, src)
}

// rsa private key sign
func RsaSha1Sign(data []byte, privateKey *PrivateKey) ([]byte, error) {
	private := (*rsa.PrivateKey)(privateKey)
	hashed := sha1.Sum(data)
	return rsa.SignPKCS1v15(rand.Reader, private, crypto.SHA1, hashed[:])
}

//rsa public key verify
func RsaSha1Verify(src []byte, sign []byte, publicKey *PublicKey) error {
	public := (*rsa.PublicKey)(publicKey)
	hashed := sha1.Sum(src)
	return rsa.VerifyPKCS1v15(public, crypto.SHA1, hashed[:], sign)
}

// rsa private key sign
func RsaSha256Sign(data []byte, privateKey *PrivateKey) ([]byte, error) {
	private := (*rsa.PrivateKey)(privateKey)
	hashed := sha256.Sum256(data)
	return rsa.SignPKCS1v15(rand.Reader, private, crypto.SHA256, hashed[:])
}

//rsa public key verify
func RsaSha256Verify(src []byte, sign []byte, publicKey *PublicKey) error {
	public := (*rsa.PublicKey)(publicKey)
	hashed := sha256.Sum256(src)
	return rsa.VerifyPKCS1v15(public, crypto.SHA256, hashed[:], sign)
}

func RsaSegmentDecrypt(src []byte, privateKey *PrivateKey) ([]byte, error) {
	var (
		out  []byte
		nSep int
	)
	private := (*rsa.PrivateKey)(privateKey)
	nSep = private.D.BitLen() / 8
	for len(src) > 0 {
		if nSep > len(src) {
			nSep = len(src)
		}
		dest, err := RsaDecrypt(src[:nSep], privateKey)
		if err != nil {
			return nil, err
		}
		out = append(out, dest...)
		src = src[nSep:]
	}
	return out, nil
}

func RsaSegmentEncrypt(src []byte, publicKey *PublicKey) ([]byte, error) {
	var (
		out  []byte
		nSep int
	)
	public := (*rsa.PublicKey)(publicKey)
	nSep = public.N.BitLen()/8 - 11
	for len(src) > 0 {
		if nSep > len(src) {
			nSep = len(src)
		}
		dest, err := RsaEncrypt(src[:nSep], publicKey)
		if err != nil {
			return nil, err
		}
		out = append(out, dest...)
		src = src[nSep:]
	}
	return out, nil
}
