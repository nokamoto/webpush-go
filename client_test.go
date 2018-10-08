package webpush

import (
	"crypto/ecdsa"
	"encoding/base64"
	"fmt"
	"github.com/dgrijalva/jwt-go"
	pb "github.com/nokamoto/webpush-go/types/webpush/protobuf"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strconv"
	"testing"
	"time"
)

const (
	privateKey = "AJFotoB4FS7IX6tbm5t0SGyISTQ6l54mMzpfYipdOD+N"
	publicKey  = "BNuvjW90TpDawYyxhvK79QVyNEplaSQZOWo1CwXDmWwfya6qnyBvIx3tFvKEBetExvil4rNNRL0/ZR2WLjGEAbQ="
	auth       = "LsUmSxGzGt+KcuczkTfFrQ=="
	p256dh     = "BOVFfCoBB/2Sn6YZrKytKc1asM+IOXFKz6+T1NLOnrGrRXh/xJEgiJIoFBO9I6twWDAj6OYvhval8jxq8F4K0iM="
)

func stdDecode(s string) []byte {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		panic(fmt.Sprintf("%s - %v", s, err))
	}
	return b
}

func TestClient_Send(t *testing.T) {
	ttl := uint32(30)

	client := NewClient(&http.Client{}, stdDecode(privateKey), stdDecode(publicKey), nil)

	server := httptest.NewServer(http.HandlerFunc(func(write http.ResponseWriter, req *http.Request) {
		check := func(key, expected string) {
			if s := req.Header.Get(key); s != expected {
				t.Errorf("[%s] expected %s but actual %s", key, expected, s)
			}
		}

		check("TTL", fmt.Sprint(ttl))
		check("Content-Encoding", "aes128gcm")
		check("Content-Type", "application/octet-stream")

		l := req.Header.Get("Content-Length")
		if i, err := strconv.Atoi(l); err != nil || i <= 0 {
			t.Errorf("[Content-Length] expected greater than 0 but actual %d - %v", i, err)
		}

		vapid := req.Header.Get("Authorization")
		tr := regexp.MustCompile(`t=([^,]+)`)
		kr := regexp.MustCompile(`k=(.+)`)

		param := func(s []string) string {
			if len(s) != 1 {
				t.Fatalf("%v", s)
			}
			tmp := s[0]
			return tmp[2:len(tmp)]
		}

		tv := param(tr.FindAllString(vapid, -1))
		token, err := jwt.Parse(tv, func(token *jwt.Token) (interface{}, error) {
			x, y := curve.ScalarBaseMult(client.private.D.Bytes())
			return &ecdsa.PublicKey{Curve: curve, X: x, Y: y}, nil
		})
		if err != nil {
			t.Error(err)
		}

		if s := token.Header["typ"]; s != "JWT" {
			t.Errorf("typ expected JWT but actual %s", s)
		}
		if s := token.Header["alg"]; s != "ES256" {
			t.Errorf("alg expected ES256 but actual %s", s)
		}

		claims := token.Claims.(jwt.MapClaims)

		audr := regexp.MustCompile(`http://127.0.0.1:[1-9][0-9]+`)
		if s := claims["aud"]; !audr.MatchString(s.(string)) {
			t.Errorf("aud expected %v but actual %v", audr, s)
		}

		exp := time.Unix(int64(claims["exp"].(float64)), 0).Unix()
		now := time.Now().Unix()
		twentyFourHoursLater := time.Now().Add(24 * time.Hour).Unix()
		if exp <= now || twentyFourHoursLater <= exp {
			t.Errorf("exp expected (%d, %d) but actual %d", now, twentyFourHoursLater, exp)
		}

		kv := param(kr.FindAllString(vapid, -1))
		if kv != client.k {
			t.Errorf("expected %s but actual %s", client.k, kv)
		}

		if sub, ok := claims["sub"]; ok {
			t.Errorf("sub expected undefined but actual %v", sub)
		}

		write.WriteHeader(201)
	}))
	defer server.Close()

	msg := pb.Message{
		Subscription: &pb.PushSubscription{
			Endpoint: server.URL,
			Auth:     stdDecode(auth),
			P256Dh:   stdDecode(p256dh),
		},
		Ttl: ttl,
	}

	res, err := client.Send(msg)
	if err != nil {
		t.Fatal(err)
	}

	if code := res.StatusCode; code != 201 {
		t.Errorf("expected 201 but actual %d", code)
	}
}
