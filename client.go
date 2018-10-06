package webpush

import (
	pb "github.com/nokamoto/webpush-go/types/webpush/protobuf"
)

// Client ...
type Client struct{}

func (c *Client) send(msg pb.Message) {}
