package client

import (
	"io"
)

type Client interface {
	RequestToken() io.Reader
}
