package webpush

import (
	pb "github.com/nokamoto/webpush-go/types/webpush/protobuf"
	"testing"
)

func TestClient_send(t *testing.T) {
	msg := pb.Message{}
	client := &Client{}

	client.send(msg)
}
