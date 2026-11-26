package session

import (
	"context"
	"net/http"
	"net/url"
	"time"

	"github.com/SigNoz/signoz/pkg/authn/communityoidc"
	"github.com/SigNoz/signoz/pkg/types/authtypes"
	"github.com/SigNoz/signoz/pkg/valuer"
)

type Module interface {
	CommunityOIDC() *communityoidc.Provider
	CreateCommunityOIDCSession(context.Context, *communityoidc.Login) (*authtypes.Token, error)
	// Gets the session context for the user. The context contains information on what the user has to do in order to create a session.
	GetSessionContext(ctx context.Context, email valuer.Email, siteURL *url.URL) (*authtypes.SessionContext, error)

	// Create a session for a user using password authn provider.
	CreatePasswordAuthNSession(ctx context.Context, authNProvider authtypes.AuthNProvider, email valuer.Email, password string, orgID valuer.UUID) (*authtypes.Token, error)

	// Create a session for a user using callback authn providers.
	CreateCallbackAuthNSession(ctx context.Context, authNProvider authtypes.AuthNProvider, values url.Values) (string, error)

	// Rotate a token.
	RotateSession(ctx context.Context, accessToken string, refreshToken string) (*authtypes.Token, error)

	// Delete a session.
	DeleteSession(ctx context.Context, accessToken string) error

	// Get the rotation interval for the session.
	GetRotationInterval(ctx context.Context) time.Duration
}

type Handler interface {
	CommunityOIDCStatus(http.ResponseWriter, *http.Request)
	CommunityOIDCLogin(http.ResponseWriter, *http.Request)
	CommunityOIDCCallback(http.ResponseWriter, *http.Request)
	CommunityOIDCComplete(http.ResponseWriter, *http.Request)

	// Get the session context for the user.
	GetSessionContext(http.ResponseWriter, *http.Request)

	// Create a session for a user using email and password.
	CreateSessionByEmailPassword(http.ResponseWriter, *http.Request)

	// Create a session for a user using google callback.
	CreateSessionByGoogleCallback(http.ResponseWriter, *http.Request)

	// Create a session for a user using saml callback.
	CreateSessionBySAMLCallback(http.ResponseWriter, *http.Request)

	// Create a session for a user using oidc callback.
	CreateSessionByOIDCCallback(http.ResponseWriter, *http.Request)

	// Rotate a token.
	RotateSession(http.ResponseWriter, *http.Request)

	// Delete a session.
	DeleteSession(http.ResponseWriter, *http.Request)
}
