package webpush

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"golang.org/x/crypto/hkdf"
	"io"
)

var curve = elliptic.P256()

func encode(b []byte) string {
	return base64.RawURLEncoding.EncodeToString(b)
}

func newEcdhSecret(asPrivate, uaPublic []byte) ([]byte, error) {
	// ecdh_secret = ECDH(as_private, ua_public)
	x, y := elliptic.Unmarshal(curve, uaPublic)
	if x == nil {
		return nil, fmt.Errorf("Unmarshal(P256, ua_public=%s) failed", encode(uaPublic))
	}
	secret, _ := curve.ScalarMult(x, y, asPrivate)
	return secret.Bytes(), nil
}

func newKeyInfo(uaPublic, asPublic []byte) []byte {
	// key_info = "WebPush: info" || 0x00 || ua_public || as_public
	prefix := []byte("WebPush: info\x00")
	keyInfo := make([]byte, len(prefix)+len(uaPublic)+len(asPublic))
	n := copy(keyInfo, prefix)
	n += copy(keyInfo[n:], uaPublic)
	copy(keyInfo[n:], asPublic)
	return keyInfo
}

func calcHKDF(secret, salt, info []byte, l int) ([]byte, error) {
	f := hkdf.New(sha256.New, secret, salt, info)
	buf := make([]byte, l)
	_, err := io.ReadFull(f, buf)
	if err != nil {
		return nil, fmt.Errorf("hkdf(secret=%s, salt=%s, info=%s, l_key=%d) - %v", encode(secret), encode(salt), encode(info), l, err)
	}
	return buf, nil
}

func newIKM(uaPublic, asPublic, ecdhSecret, authSecret []byte) ([]byte, error) {
	// # HKDF-Extract(salt=auth_secret, IKM=ecdh_secret)
	// PRK_key = HMAC-SHA-256(auth_secret, ecdh_secret)
	// # HKDF-Expand(PRK_key, key_info, L_key=32)
	// IKM = HMAC-SHA-256(PRK_key, key_info || 0x01)
	return calcHKDF(ecdhSecret, authSecret, newKeyInfo(uaPublic, asPublic), 32)
}

func newCekInfo() []byte {
	// cek_info = "Content-Encoding: aes128gcm" || 0x00
	return []byte("Content-Encoding: aes128gcm\x00")
}

func newCek(IKM, salt []byte) ([]byte, error) {
	// # HKDF-Extract(salt, IKM)
	// PRK = HMAC-SHA-256(salt, IKM)
	// # HKDF-Expand(PRK, cek_info, L_cek=16)
	// CEK = HMAC-SHA-256(PRK, cek_info || 0x01)[0..15]
	return calcHKDF(IKM, salt, newCekInfo(), 16)
}

func newNonceInfo() []byte {
	// nonce_info = "Content-Encoding: nonce" || 0x00
	return []byte("Content-Encoding: nonce\x00")
}

func newNonce(IKM, salt []byte) ([]byte, error) {
	// # HKDF-Extract(salt, IKM)
	// PRK = HMAC-SHA-256(salt, IKM)
	// # HKDF-Expand(PRK, nonce_info, L_nonce=12)
	// NONCE = HMAC-SHA-256(PRK, nonce_info || 0x01)[0..11]
	return calcHKDF(IKM, salt, newNonceInfo(), 12)
}

func newHeader(salt, keyid []byte) []byte {
	// https://tools.ietf.org/html/rfc8188#section-2.1
	var b []byte
	b = append(b, salt...)

	rs := make([]byte, 4)
	binary.BigEndian.PutUint32(rs, 4096)
	b = append(b, rs...)

	b = append(b, byte(len(keyid)))
	b = append(b, keyid...)

	return b
}

func newCiphertext(plaintext string, CEK, NONCE []byte) ([]byte, error) {
	// https://tools.ietf.org/html/rfc8188#section-2
	b := []byte(plaintext)
	b = append(b, 0x02)

	block, err := aes.NewCipher(CEK)
	if err != nil {
		return nil, fmt.Errorf("NewCipher(%s) - %v", encode(CEK), err)
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("NewGCM(%v) - %v", block, err)
	}

	return aesgcm.Seal(nil, NONCE, b, nil), nil
}

// Encrypt encrypts `plaintext` using an encrypted content encoding [https://tools.ietf.org/html/rfc8188].
// https://tools.ietf.org/html/rfc8291
func Encrypt(asPublic, asPrivate, uaPublic, authSecret, salt []byte, plaintext string) ([]byte, error) {
	ecdhSecret, err := newEcdhSecret(asPrivate, uaPublic)
	if err != nil {
		return nil, err
	}

	IKM, err := newIKM(uaPublic, asPublic, ecdhSecret, authSecret)
	if err != nil {
		return nil, err
	}

	CEK, err := newCek(IKM, salt)
	if err != nil {
		return nil, err
	}

	NONCE, err := newNonce(IKM, salt)
	if err != nil {
		return nil, err
	}

	ciphertext, err := newCiphertext(plaintext, CEK, NONCE)
	if err != nil {
		return nil, err
	}

	header := newHeader(salt, asPublic)

	return append(header, ciphertext...), nil
}
