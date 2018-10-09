package test

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	webpush "github.com/nokamoto/webpush-go"
	pb "github.com/nokamoto/webpush-go/types/webpush/protobuf"
	"io/ioutil"
	"net/http"
	"testing"
	"time"
)

type suite struct {
	ID           string `json:"id"`
	Subscription struct {
		Endpoint string `json:"endpoint"`
		Auth     string `json:"auth"`
		P256dh   string `json:"p256dh"`
	} `json:"subscription"`
	Events []string `json:"events"`
}

const (
	privateKey = "AJFotoB4FS7IX6tbm5t0SGyISTQ6l54mMzpfYipdOD+N"
	publicKey  = "BNuvjW90TpDawYyxhvK79QVyNEplaSQZOWo1CwXDmWwfya6qnyBvIx3tFvKEBetExvil4rNNRL0/ZR2WLjGEAbQ="
)

func stdDecode(s string) []byte {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		panic(fmt.Sprintf("%s - %v", s, err))
	}
	return b
}

func unmarshal(res *http.Response) (*suite, error) {
	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}
	s := &suite{}
	return s, json.Unmarshal(body, s)
}

func test(t *testing.T, driver string) {
	createdURL := fmt.Sprintf("http://localhost:9000/testing/%s", driver)
	created, err := http.Post(createdURL, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer created.Body.Close()

	if created.StatusCode != 201 {
		t.Fatalf("%s - %d != 201", createdURL, created.StatusCode)
	}

	suite, err := unmarshal(created)
	if err != nil {
		t.Fatalf("%s - %v", createdURL, err)
	}

	defer func() {
		req, err := http.NewRequest("DELETE", fmt.Sprintf("http://localhost:9000/testing/%s", suite.ID), nil)
		if err != nil {
			t.Log(err)
		} else {
			c := &http.Client{}
			_, err := c.Do(req)
			if err != nil {
				t.Log(err)
			}
		}
	}()

	subject := "mailto:nokamoto.engr@gmail.com"
	client := webpush.NewClient(&http.Client{}, stdDecode(privateKey), stdDecode(publicKey), &subject)

	msg := pb.Message{
		Subscription: &pb.PushSubscription{
			Endpoint: suite.Subscription.Endpoint,
			Auth:     stdDecode(suite.Subscription.Auth),
			P256Dh:   stdDecode(suite.Subscription.P256dh),
		},
		Ttl:       30,
		Plaintext: fmt.Sprintf(`{"id":"%s", "message": "hello world"}`, suite.ID),
	}

	res, err := client.Send(msg)
	if err != nil {
		t.Fatalf("%v - %v", msg, err)
	}
	defer res.Body.Close()

	if res.StatusCode != 201 {
		t.Fatalf("%v - %d != 201", msg, res.StatusCode)
	}

	time.Sleep(10 * time.Second) // Wait for transmission of the message, push service -> service worker -> webpush testing service

	getURL := fmt.Sprintf("http://localhost:9000/testing/%s", suite.ID)
	got, err := http.Get(getURL)
	if err != nil {
		t.Fatalf("%v - %v", getURL, err)
	}

	if got.StatusCode != 200 {
		t.Fatalf("%v - %d != 200", getURL, got.StatusCode)
	}

	events, err := unmarshal(got)
	if err != nil {
		t.Fatalf("%v - %v", getURL, err)
	}

	if len(events.Events) != 1 {
		t.Fatalf("len(%v) != 1", events.Events)
	}

	if s := events.Events[0]; s != msg.Plaintext {
		t.Errorf("expected %s but actual %s", msg.Plaintext, s)
	}
}

func Test_firefox(t *testing.T) {
	test(t, "firefox")
}

func Test_chrome(t *testing.T) {
	test(t, "chrome")
}
