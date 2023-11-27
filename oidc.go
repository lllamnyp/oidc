package oidc

import (
	"sync"
	"time"

	"github.com/lllamnyp/oidc/internal/token"
)

type TokenSource interface {
	Token() token.Token
}

type threadSafeTokenSource struct {
	t token.Token
	sync.RWMutex
	TokenSource
}

func (t *threadSafeTokenSource) Token() token.Token {
	t.RLock()
	defer t.RUnlock()
	return t.t
}

func (t *threadSafeTokenSource) updateToken() {
	t.Lock()
	defer t.Unlock()
	t.t = t.TokenSource.Token()
}

type maintainedTokenSource struct {
	threadSafeTokenSource
	d time.Time
}

func (t *maintainedTokenSource) maintain() {
}
