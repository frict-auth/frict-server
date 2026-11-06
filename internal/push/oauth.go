package push

import (
	"context"
	"net/http"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

type tokenFunc func(ctx context.Context) (string, error)

func (f tokenFunc) Token(ctx context.Context) (string, error) { return f(ctx) }

// ServiceAccountTokens mints FCMScope tokens with a service-account key,
// given as the key file's JSON; any other credential type is an error. It
// posts a signed JWT to the key's token_uri over client and reuses each
// token until 10 s before it expires (oauth2.ReuseTokenSource).
//
// Token ignores its context: a mint is bounded by client's Timeout.
func ServiceAccountTokens(key []byte, client *http.Client) (TokenSource, error) {
	cfg, err := google.JWTConfigFromJSON(key, FCMScope)
	if err != nil {
		return nil, err
	}
	ts := cfg.TokenSource(context.WithValue(context.Background(), oauth2.HTTPClient, client))
	return tokenFunc(func(context.Context) (string, error) {
		t, err := ts.Token()
		if err != nil {
			return "", err
		}
		return t.AccessToken, nil
	}), nil
}
