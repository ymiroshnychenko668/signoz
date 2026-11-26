package communityoidc

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/go-jose/go-jose/v4"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"

	"github.com/SigNoz/signoz/pkg/types/authtypes"
	"github.com/SigNoz/signoz/pkg/valuer"
)

// A real TLS discovery, JWKS and token exchange using a test-only issuer.
func TestBrowserFlow(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: key}, (&jose.SignerOptions{}).WithHeader("kid", "test"))
	require.NoError(t, err)
	for _, test := range []string{"success", "wrong-state", "no-browser", "unverified-email", "wrong-nonce", "wrong-audience", "wrong-issuer", "no-group", "expired", "wrong-azp", "wrong-signature"} {
		t.Run(test, func(t *testing.T) {
			var issuer, nonce, challenge string
			mux := http.NewServeMux()
			server := httptest.NewTLSServer(mux)
			defer server.Close()
			issuer = server.URL
			writeJSON := func(w http.ResponseWriter, v any) {
				w.Header().Set("Content-Type", "application/json")
				require.NoError(t, json.NewEncoder(w).Encode(v))
			}
			mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
				writeJSON(w, map[string]any{"issuer": issuer, "authorization_endpoint": issuer + "/auth", "token_endpoint": issuer + "/token", "jwks_uri": issuer + "/keys", "id_token_signing_alg_values_supported": []string{"RS256"}})
			})
			mux.HandleFunc("/keys", func(w http.ResponseWriter, r *http.Request) {
				writeJSON(w, jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &key.PublicKey, KeyID: "test", Use: "sig", Algorithm: "RS256"}}})
			})
			mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
				id, secret, ok := r.BasicAuth()
				if !ok || id != "test-client" || secret != "test-secret" || r.FormValue("code") != "test-code" || oauth2.S256ChallengeFromVerifier(r.FormValue("code_verifier")) != challenge {
					http.Error(w, "invalid exchange", 400)
					return
				}
				claims := map[string]any{"iss": issuer, "aud": "test-client", "sub": "stable-subject", "exp": time.Now().Add(3 * time.Minute).Unix(), "iat": time.Now().Unix(), "nonce": nonce, "email": "editor@example.org", "email_verified": true, "groups": []string{"readers", "editors"}}
				switch test {
				case "unverified-email":
					claims["email_verified"] = false
				case "wrong-nonce":
					claims["nonce"] = "different"
				case "wrong-audience":
					claims["aud"] = "another"
				case "wrong-issuer":
					claims["iss"] = "https://wrong.example"
				case "no-group":
					claims["groups"] = []string{"irrelevant"}
				case "expired":
					claims["exp"] = time.Now().Add(-time.Minute).Unix()
				case "wrong-azp":
					claims["azp"] = "another"
				}
				payload, err := json.Marshal(claims)
				require.NoError(t, err)
				tokenSigner := signer
				if test == "wrong-signature" {
					other, err := rsa.GenerateKey(rand.Reader, 2048)
					require.NoError(t, err)
					tokenSigner, err = jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: other}, nil)
					require.NoError(t, err)
				}
				signed, err := tokenSigner.Sign(payload)
				require.NoError(t, err)
				serialized, err := signed.CompactSerialize()
				require.NoError(t, err)
				writeJSON(w, map[string]any{"access_token": "test-idp-access", "token_type": "Bearer", "id_token": serialized})
			})
			publicURL := "https://app.example.org/base"
			p := &Provider{Config: Config{Issuer: issuer, ClientID: "test-client", PublicURL: publicURL, GroupRoles: map[string]string{"readers": authtypes.SigNozViewerRoleName, "editors": authtypes.SigNozEditorRoleName}, MaxSessionSeconds: 900}, secret: "test-secret"}
			ctx := oidc.ClientContext(context.Background(), server.Client())
			w := httptest.NewRecorder()
			dest, err := p.Begin(ctx, w)
			require.NoError(t, err)
			loginURL, err := url.Parse(dest)
			require.NoError(t, err)
			v := loginURL.Query()
			nonce = v.Get("nonce")
			challenge = v.Get("code_challenge")
			require.NotEmpty(t, nonce)
			require.NotEmpty(t, challenge)
			require.Equal(t, "S256", v.Get("code_challenge_method"))
			require.Equal(t, publicURL+CallbackPath, v.Get("redirect_uri"))
			browser := w.Result().Cookies()[0]
			require.True(t, browser.HttpOnly && browser.Secure)
			require.Equal(t, http.SameSiteLaxMode, browser.SameSite)
			state := v.Get("state")
			if test == "wrong-state" {
				state = "invalid"
			}
			req := httptest.NewRequest(http.MethodGet, publicURL+CallbackPath+"?state="+state+"&code=test-code", nil)
			if test != "no-browser" {
				req.AddCookie(browser)
			}
			w = httptest.NewRecorder()
			dest, err = p.Callback(ctx, w, req)
			if test != "success" {
				require.Error(t, err)
				require.Empty(t, dest)
				return
			}
			require.NoError(t, err)
			require.Equal(t, publicURL+"/login#community-oidc", dest)
			handoffCookie := w.Result().Cookies()[0]
			require.Equal(t, "/base"+CompletePath, handoffCookie.Path)
			require.True(t, handoffCookie.HttpOnly && handoffCookie.Secure)
			require.Equal(t, http.SameSiteStrictMode, handoffCookie.SameSite)
			_, err = p.Callback(ctx, httptest.NewRecorder(), req)
			require.Error(t, err)
			req = httptest.NewRequest(http.MethodPost, publicURL+CompletePath, nil)
			req.AddCookie(handoffCookie)
			req.AddCookie(browser)
			req.Header.Set("Origin", "https://other.example.org")
			_, err = p.Consume(httptest.NewRecorder(), req)
			require.Error(t, err)
			req.Header.Set("Origin", "https://app.example.org")
			identity, err := p.Consume(httptest.NewRecorder(), req)
			require.NoError(t, err)
			require.Equal(t, "stable-subject", identity.Subject)
			require.Equal(t, authtypes.SigNozEditorRoleName, identity.Role)
			require.WithinDuration(t, time.Now().Add(3*time.Minute), identity.Deadline, 2*time.Second)
			_, err = p.Consume(httptest.NewRecorder(), req)
			require.Error(t, err)
		})
	}
}

func TestConfigAndIdentityBindings(t *testing.T) {
	org := valuer.GenerateUUID()
	legacy := valuer.GenerateUUID()
	cfg := Config{OrgID: org, Issuer: "https://sso.example.org/realms/test", PublicURL: "https://app.example.org", ClientID: "client", ClientSecretFile: "secret", Links: map[string]valuer.UUID{"legacy": legacy}, GroupRoles: map[string]string{"readers": "signoz-viewer"}, MaxSessionSeconds: 600}
	require.NoError(t, cfg.validate())
	a, linked := cfg.Target("opaque")
	require.False(t, linked)
	b, _ := cfg.Target("different")
	require.NotEqual(t, a, b)
	b, linked = cfg.Target("legacy")
	require.Equal(t, legacy, b)
	require.True(t, linked)
	other := cfg
	other.OrgID = valuer.GenerateUUID()
	b, _ = other.Target("opaque")
	require.NotEqual(t, a, b)
	other = cfg
	other.Issuer = "https://another.example.org"
	b, _ = other.Target("opaque")
	require.NotEqual(t, a, b)
	cfg.Links["another"] = legacy
	require.Error(t, cfg.validate())
	delete(cfg.Links, "another")
	cfg.Links["another"] = a
	require.Error(t, cfg.validate())
	delete(cfg.Links, "another")
	cfg.PublicURL = "http://example.org"
	require.Error(t, cfg.validate())
}
