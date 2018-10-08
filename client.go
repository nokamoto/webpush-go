package webpush

import (
	"bytes"
	"crypto/ecdsa"
	"encoding/base64"
	"fmt"
	"github.com/dgrijalva/jwt-go"
	pb "github.com/nokamoto/webpush-go/types/webpush/protobuf"
	"math/big"
	"net/http"
	"net/url"
	"time"
)

// Client is a webpush client.
type Client struct {
	client  *http.Client
	private *ecdsa.PrivateKey
	subject *string
	k       string
}

// NewClient creates a new webpush client.
// `privateKey` and `publicKey` are a VAPID application server key pair described in [RFC8292].
// `subject` is a contact URI for the application server as either a "mailto:" (email) [RFC6068] or an "https:" [RFC2818] URI. If `subject` is nil, a "sub" claim in the JWT is absent.
// https://tools.ietf.org/html/rfc8292
func NewClient(client *http.Client, privateKey []byte, publicKey []byte, subject *string) *Client {
	d := big.Int{}
	return &Client{
		client: client,
		private: &ecdsa.PrivateKey{
			PublicKey: ecdsa.PublicKey{Curve: curve},
			D:         d.SetBytes(privateKey),
		},
		k:       base64.RawURLEncoding.EncodeToString(publicKey),
		subject: subject,
	}
}

func (c *Client) newJwt(endpoint string, expiry int64) (string, error) {
	origin, err := url.Parse(endpoint)
	if err != nil {
		return "", fmt.Errorf("url.Parse(%s) - %v", endpoint, err)
	}

	audience := fmt.Sprintf("%s://%s", origin.Scheme, origin.Host)

	claims := jwt.MapClaims{
		"aud": audience,
		"exp": expiry,
	}
	if c.subject != nil {
		claims["sub"] = *c.subject
	}

	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)

	return token.SignedString(c.private)
}

// Send posts a new http request described in [RFC8291], [RFC8292], and [RFC8030] to send the webpush message.
// https://tools.ietf.org/html/rfc8291
// https://tools.ietf.org/html/rfc8292
// https://tools.ietf.org/html/rfc8030
func (c *Client) Send(msg pb.Message) (*http.Response, error) {
	message, err := Encrypt(msg.GetSubscription().GetP256Dh(), msg.GetSubscription().GetAuth(), msg.GetPlaintext())
	if err != nil {
		return nil, fmt.Errorf("Encrypt(%v) - %v", msg, err)
	}

	req, err := http.NewRequest("POST", msg.GetSubscription().GetEndpoint(), bytes.NewReader(message))
	if err != nil {
		return nil, fmt.Errorf("NewRequest(POST, %v) - %v", msg, err)
	}

	req.Header.Add("TTL", fmt.Sprint(msg.GetTtl()))
	req.Header.Add("Content-Encoding", "aes128gcm")
	req.Header.Add("Content-Type", "application/octet-stream")

	expiry := time.Now().Add(12 * time.Hour).Unix()
	t, err := c.newJwt(msg.GetSubscription().GetEndpoint(), expiry)
	if err != nil {
		return nil, fmt.Errorf("newJwt(%v, %d) - %v", msg, expiry, err)
	}

	k := c.k

	req.Header.Add("Authorization", fmt.Sprintf("vapid t=%s,k=%s", t, k))

	return c.client.Do(req)
}
