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
	// Executing TokenSource.Token() might take a while so we get a copy first
	// and only then acquire the lock to write the new value to the struct.
	updatedToken := t.TokenSource.Token()
	t.Lock()
	defer t.Unlock()
	t.t = updatedToken
}

type maintainedTokenSource struct {
	threadSafeTokenSource
	d time.Time
	e time.Duration
	f uint64
}

func (t *maintainedTokenSource) updateDeadline() time.Time {
	if t.f < 2 {
		t.f = 2
	}
	return t.d.Add(-t.e / time.Duration(t.f))
}

func (t *maintainedTokenSource) updateToken() {
	if t.updateDeadline().Before(time.Now()) {
		t.threadSafeTokenSource.updateToken()
		t.e = time.Duration(t.t.ExpiresIn) * time.Second
		t.d = time.Now().Add(t.e)
	}
}

func (t *maintainedTokenSource) maintainToken() {
	for {
		if updateDeadline := t.updateDeadline(); updateDeadline.Before(time.Now()) {
			time.Sleep(time.Until(updateDeadline))
		}
		t.updateToken()
	}
}
