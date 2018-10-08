package webpush

import (
	"encoding/base64"
	"fmt"
	"testing"
)

// https://tools.ietf.org/html/rfc8291#appendix-A
// Appendix A.  Intermediate Values for Encryption
const (
	plaintext  = "When I grow up, I want to be a watermelon"
	asPublic   = "BP4z9KsN6nGRTbVYI_c7VJSPQTBtkgcy27mlmlMoZIIgDll6e3vCYLocInmYWAmS6TlzAC8wEqKK6PBru3jl7A8"
	asPrivate  = "yfWPiYE-n46HLnH0KqZOF1fJJU3MYrct3AELtAQ-oRw"
	uaPublic   = "BCVxsr7N_eNgVRqvHtD0zTZsEc6-VV-JvLexhqUzORcxaOzi6-AYWXvTBHm4bjyPjs7Vd8pZGH6SRpkNtoIAiw4"
	uaPrivate  = "q1dXpw3UpT5VOmu_cf_v6ih07Aems3njxI-JWgLcM94"
	salt       = "DGv6ra1nlYgDCS1FRnbzlw"
	authSecret = "BTBZMqHH6r4Tts7J_aSIgg"
	ecdhSecret = "kyrL1jIIOHEzg3sM2ZWRHDRB62YACZhhSlknJ672kSs"
	PKRKey     = "Snr3JMxaHVDXHWJn5wdC52WjpCtd2EIEGBykDcZW32k"
	keyInfo    = "V2ViUHVzaDogaW5mbwAEJXGyvs3942BVGq8e0PTNNmwRzr5VX4m8t7GGpTM5FzFo7OLr4BhZe9MEebhuPI-OztV3ylkYfpJGmQ22ggCLDgT-M_SrDepxkU21WCP3O1SUj0EwbZIHMtu5pZpTKGSCIA5Zent7wmC6HCJ5mFgJkuk5cwAvMBKiiujwa7t45ewP"
	IKM        = "S4lYMb_L0FxCeq0WhDx813KgSYqU26kOyzWUdsXYyrg"
	PRK        = "09_eUZGrsvxChDCGRCdkLiDXrReGOEVeSCdCcPBSJSc"
	cekInfo    = "Q29udGVudC1FbmNvZGluZzogYWVzMTI4Z2NtAA"
	CEK        = "oIhVW04MRdy2XN9CiKLxTg"
	nonceInfo  = "Q29udGVudC1FbmNvZGluZzogbm9uY2UA"
	NONCE      = "4h_95klXJ5E_qnoN"
	header     = "DGv6ra1nlYgDCS1FRnbzlwAAEABBBP4z9KsN6nGRTbVYI_c7VJSPQTBtkgcy27mlmlMoZIIgDll6e3vCYLocInmYWAmS6TlzAC8wEqKK6PBru3jl7A8"
	ciphertext = "8pfeW0KbunFT06SuDKoJH9Ql87S1QUrdirN6GcG7sFz1y1sqLgVi1VhjVkHsUoEsbI_0LpXMuGvnzQ"
	message    = "DGv6ra1nlYgDCS1FRnbzlwAAEABBBP4z9KsN6nGRTbVYI_c7VJSPQTBtkgcy27mlmlMoZIIgDll6e3vCYLocInmYWAmS6TlzAC8wEqKK6PBru3jl7A_yl95bQpu6cVPTpK4Mqgkf1CXztLVBSt2Ks3oZwbuwXPXLWyouBWLVWGNWQexSgSxsj_Qulcy4a-fN"
)

func decode(s string) []byte {
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		panic(fmt.Sprintf("%s - %v", s, err))
	}
	return b
}

func check(expected string, t *testing.T) func([]byte, error) {
	return func(actual []byte, err error) {
		if err != nil {
			t.Fatal(err)
		}
		if s := encode(actual); s != expected {
			t.Errorf("expected %s but actual %s", expected, s)
		}
	}
}

func check1(expected string, t *testing.T, actual []byte) {
	if s := encode(actual); s != expected {
		t.Errorf("expected %s but actual %s", expected, s)
	}
}

func Test_newEcdhSecret(t *testing.T) {
	check(ecdhSecret, t)(newEcdhSecret(decode(asPrivate), decode(uaPublic)))
}

func Test_newKeyInfo(t *testing.T) {
	check1(keyInfo, t, newKeyInfo(decode(uaPublic), decode(asPublic)))
}

func Test_newIKM(t *testing.T) {
	check(IKM, t)(newIKM(decode(uaPublic), decode(asPublic), decode(ecdhSecret), decode(authSecret)))
}

func Test_newCekInfo(t *testing.T) {
	check1(cekInfo, t, newCekInfo())
}

func Test_newCek(t *testing.T) {
	check(CEK, t)(newCek(decode(IKM), decode(salt)))
}

func Test_newNonceInfo(t *testing.T) {
	check1(nonceInfo, t, newNonceInfo())
}

func Test_newNonce(t *testing.T) {
	check(NONCE, t)(newNonce(decode(IKM), decode(salt)))
}

func Test_newCiphertext(t *testing.T) {
	check(ciphertext, t)(newCiphertext(plaintext, decode(CEK), decode(NONCE)))
}

func Test_newHeader(t *testing.T) {
	check1(header, t, newHeader(decode(salt), decode(asPublic)))
}

func Test_Encrypt(t *testing.T) {
	check(message, t)(Encrypt(decode(asPublic), decode(asPrivate), decode(uaPublic), decode(authSecret), decode(salt), plaintext))
}
