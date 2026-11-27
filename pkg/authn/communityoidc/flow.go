package communityoidc

import (
	"context"
	"crypto/subtle"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"

	"github.com/SigNoz/signoz/pkg/errors"
	"github.com/SigNoz/signoz/pkg/valuer"
)

const LoginPath = "/api/v1/community-oidc/login"
const CallbackPath = "/api/v1/community-oidc/callback"
const CompletePath = "/api/v1/community-oidc/complete"
const StatusPath = "/api/v1/community-oidc/status"
const flowCookie = "__Host-signoz-community-oidc-flow"
const handoffCookie = "__Secure-signoz-community-oidc-completion"

type Provider struct {
	Config
	secret       string
	discoveryMu  sync.Mutex
	discovery    *oidc.Provider
	transactions tickets[transaction]
	completions  tickets[handoff]
}

type handoff struct {
	login   Login
	browser string
}

type transaction struct{ state, nonce, verifier string }

// Login contains only information from a verified ID token constrained by the
// configured issuer, audience and group mapping.
type Login struct {
	Subject, Name, Role string
	Email               valuer.Email
	Deadline            time.Time
}

type entry[T any] struct {
	value T
	until time.Time
}
type tickets[T any] struct {
	mu      sync.Mutex
	entries map[string]entry[T]
}

func (t *tickets[T]) put(value T, ttl time.Duration) (string, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.entries == nil {
		t.entries = make(map[string]entry[T])
	}
	now := time.Now()
	for key, e := range t.entries {
		if !now.Before(e.until) {
			delete(t.entries, key)
		}
	}
	if len(t.entries) >= 2048 {
		return "", errors.New(errors.TypeTooManyRequests, errors.CodeTooManyRequests, "too many pending sign-ins")
	}
	key := oauth2.GenerateVerifier()
	t.entries[key] = entry[T]{value, now.Add(ttl)}
	return key, nil
}

func (t *tickets[T]) take(key string) (T, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	e, ok := t.entries[key]
	delete(t.entries, key)
	return e.value, ok && time.Now().Before(e.until)
}

func denied() error {
	return errors.New(errors.TypeForbidden, errors.CodeForbidden, "single sign-on was not authorized")
}

func (p *Provider) discover(ctx context.Context) (*oidc.Provider, error) {
	p.discoveryMu.Lock()
	defer p.discoveryMu.Unlock()
	if p.discovery == nil {
		d, err := oidc.NewProvider(ctx, p.Issuer)
		if err != nil {
			return nil, errors.New(errors.TypeInternal, errors.CodeInternal, "identity provider is unavailable")
		}
		p.discovery = d
	}
	return p.discovery, nil
}

func (p *Provider) oauthConfig(d *oidc.Provider) *oauth2.Config {
	return &oauth2.Config{ClientID: p.ClientID, ClientSecret: p.secret, Endpoint: d.Endpoint(), RedirectURL: p.url(CallbackPath), Scopes: []string{oidc.ScopeOpenID, "profile", "email"}}
}

func cookie(name, value, path string, lifetime int, sameSite http.SameSite) *http.Cookie {
	return &http.Cookie{Name: name, Value: value, Path: path, MaxAge: lifetime, HttpOnly: true, Secure: true, SameSite: sameSite}
}

func (p *Provider) Begin(ctx context.Context, w http.ResponseWriter) (string, error) {
	d, err := p.discover(ctx)
	if err != nil {
		return "", err
	}
	t := transaction{state: oauth2.GenerateVerifier(), nonce: oauth2.GenerateVerifier(), verifier: oauth2.GenerateVerifier()}
	key, err := p.transactions.put(t, 5*time.Minute)
	if err != nil {
		return "", err
	}
	http.SetCookie(w, cookie(flowCookie, key, "/", 300, http.SameSiteLaxMode))
	return p.oauthConfig(d).AuthCodeURL(t.state, oidc.Nonce(t.nonce), oauth2.S256ChallengeOption(t.verifier)), nil
}

func (p *Provider) callback(ctx context.Context, r *http.Request, t transaction) (*Login, error) {
	d, err := p.discover(ctx)
	if err != nil {
		return nil, err
	}
	values := r.URL.Query()
	if subtle.ConstantTimeCompare([]byte(values.Get("state")), []byte(t.state)) != 1 || values.Get("code") == "" || values.Get("error") != "" {
		return nil, denied()
	}
	token, err := p.oauthConfig(d).Exchange(ctx, values.Get("code"), oauth2.VerifierOption(t.verifier))
	if err != nil {
		return nil, denied()
	}
	raw, ok := token.Extra("id_token").(string)
	if !ok {
		return nil, denied()
	}
	id, err := d.Verifier(&oidc.Config{ClientID: p.ClientID}).Verify(ctx, raw)
	if err != nil || subtle.ConstantTimeCompare([]byte(id.Nonce), []byte(t.nonce)) != 1 || strings.TrimSpace(id.Subject) == "" || strings.ContainsRune(id.Subject, '\x00') {
		return nil, denied()
	}
	var claims struct {
		AuthorizedParty string   `json:"azp"`
		Email           string   `json:"email"`
		Verified        bool     `json:"email_verified"`
		Name            string   `json:"name"`
		Groups          []string `json:"groups"`
	}
	if err := id.Claims(&claims); err != nil || !claims.Verified || (claims.AuthorizedParty != "" || len(id.Audience) > 1) && claims.AuthorizedParty != p.ClientID {
		return nil, denied()
	}
	email, err := valuer.NewEmail(claims.Email)
	if err != nil {
		return nil, denied()
	}
	role := p.mappedRole(claims.Groups)
	if role == "" {
		return nil, denied()
	}
	name := strings.TrimSpace(claims.Name)
	if name == "" {
		name = email.String()
	}
	deadline := time.Now().Add(p.ttl())
	if id.Expiry.Before(deadline) {
		deadline = id.Expiry
	}
	return &Login{Subject: id.Subject, Name: name, Email: email, Role: role, Deadline: deadline}, nil
}

func (p *Provider) cookiePath() string { u, _ := url.Parse(p.url(CompletePath)); return u.Path }

func (p *Provider) Callback(ctx context.Context, w http.ResponseWriter, r *http.Request) (string, error) {
	c, err := r.Cookie(flowCookie)
	if err != nil {
		return "", denied()
	}
	t, ok := p.transactions.take(c.Value)
	if !ok {
		return "", denied()
	}
	login, err := p.callback(ctx, r, t)
	if err != nil {
		return "", err
	}
	code, err := p.completions.put(handoff{login: *login, browser: c.Value}, time.Minute)
	if err != nil {
		return "", err
	}
	http.SetCookie(w, cookie(handoffCookie, code, p.cookiePath(), 60, http.SameSiteStrictMode))
	return p.url("/login#community-oidc"), nil
}

func (p *Provider) Consume(w http.ResponseWriter, r *http.Request) (*Login, error) {
	base, _ := url.Parse(p.PublicURL)
	if r.Method != http.MethodPost || r.Header.Get("Origin") != base.Scheme+"://"+base.Host {
		return nil, denied()
	}
	c, err := r.Cookie(handoffCookie)
	if err != nil {
		return nil, denied()
	}
	http.SetCookie(w, cookie(handoffCookie, "", p.cookiePath(), -1, http.SameSiteStrictMode))
	browser, err := r.Cookie(flowCookie)
	if err != nil {
		return nil, denied()
	}
	http.SetCookie(w, cookie(flowCookie, "", "/", -1, http.SameSiteLaxMode))
	handoff, ok := p.completions.take(c.Value)
	if !ok || subtle.ConstantTimeCompare([]byte(handoff.browser), []byte(browser.Value)) != 1 || !time.Now().Before(handoff.login.Deadline) {
		return nil, denied()
	}
	return &handoff.login, nil
}

func (p *Provider) ErrorURL() string {
	values := errors.AsURLValues(denied())
	values.Set("callbackauthnerr", "true")
	return p.url("/login") + "?" + values.Encode()
}
