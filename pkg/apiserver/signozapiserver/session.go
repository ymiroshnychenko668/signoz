package signozapiserver

import (
	"net/http"

	"github.com/SigNoz/signoz/pkg/authn/communityoidc"
	"github.com/SigNoz/signoz/pkg/http/handler"
	"github.com/SigNoz/signoz/pkg/types/authtypes"
	"github.com/SigNoz/signoz/pkg/types/coretypes"
	"github.com/gorilla/mux"
)

func (provider *provider) addSessionRoutes(router *mux.Router) error {
	for _, route := range []struct {
		path, method, id string
		serve            http.HandlerFunc
		success          int
		response         any
	}{
		{communityoidc.StatusPath, http.MethodGet, "GetCommunityOIDCStatus", provider.sessionHandler.CommunityOIDCStatus, http.StatusOK, new(struct {
			Enabled bool `json:"enabled"`
		})},
		{communityoidc.LoginPath, http.MethodGet, "StartCommunityOIDC", provider.sessionHandler.CommunityOIDCLogin, http.StatusSeeOther, nil},
		{communityoidc.CallbackPath, http.MethodGet, "CallbackCommunityOIDC", provider.sessionHandler.CommunityOIDCCallback, http.StatusSeeOther, nil},
		{communityoidc.CompletePath, http.MethodPost, "CompleteCommunityOIDC", provider.sessionHandler.CommunityOIDCComplete, http.StatusOK, new(authtypes.GettableToken)},
	} {
		h := handler.New(provider.authzMiddleware.OpenAccess(route.serve), handler.OpenAPIDef{ID: route.id, Tags: []string{"sessions"}, Summary: route.id, SuccessStatusCode: route.success, Response: route.response, ResponseContentType: "application/json", ErrorStatusCodes: []int{http.StatusForbidden, http.StatusNotFound}})
		if err := router.Handle(route.path, h).Methods(route.method).GetError(); err != nil {
			return err
		}
	}

	if err := router.Handle("/api/v2/sessions/email_password", handler.New(provider.authzMiddleware.OpenAccess(provider.sessionHandler.CreateSessionByEmailPassword), handler.OpenAPIDef{
		ID:                  "CreateSessionByEmailPassword",
		Tags:                []string{"sessions"},
		Summary:             "Create session by email and password",
		Description:         "This endpoint creates a session for a user using email and password.",
		Request:             new(authtypes.PostableEmailPasswordSession),
		RequestContentType:  "application/json",
		Response:            new(authtypes.GettableToken),
		ResponseContentType: "application/json",
		SuccessStatusCode:   http.StatusOK,
		ErrorStatusCodes:    []int{http.StatusBadRequest, http.StatusNotFound},
		Deprecated:          false,
		SecuritySchemes:     []handler.OpenAPISecurityScheme{},
	}, handler.WithResourceDefs(handler.BasicResourceDef{
		Resource: coretypes.ResourceMetaResourceSession,
		Verb:     coretypes.VerbCreate,
		Category: coretypes.ActionCategoryAccessControl,
		Selector: coretypes.WildcardSelector,
	}))).Methods(http.MethodPost).GetError(); err != nil {
		return err
	}

	if err := router.Handle("/api/v2/sessions/context", handler.New(provider.authzMiddleware.OpenAccess(provider.sessionHandler.GetSessionContext), handler.OpenAPIDef{
		ID:                  "GetSessionContext",
		Tags:                []string{"sessions"},
		Summary:             "Get session context",
		Description:         "This endpoint returns the context for the session",
		Request:             nil,
		RequestContentType:  "",
		Response:            new(authtypes.SessionContext),
		ResponseContentType: "application/json",
		SuccessStatusCode:   http.StatusOK,
		ErrorStatusCodes:    []int{http.StatusBadRequest},
		Deprecated:          false,
		SecuritySchemes:     []handler.OpenAPISecurityScheme{},
	}, handler.WithResourceDefs(handler.BasicResourceDef{
		Resource: coretypes.ResourceMetaResourceSession,
		Verb:     coretypes.VerbRead,
		Category: coretypes.ActionCategoryAccessControl,
		Selector: coretypes.WildcardSelector,
	}))).Methods(http.MethodGet).GetError(); err != nil {
		return err
	}

	if err := router.Handle("/api/v2/sessions/rotate", handler.New(provider.authzMiddleware.OpenAccess(provider.sessionHandler.RotateSession), handler.OpenAPIDef{
		ID:                  "RotateSession",
		Tags:                []string{"sessions"},
		Summary:             "Rotate session",
		Description:         "This endpoint rotates the session",
		Request:             new(authtypes.PostableRotateToken),
		RequestContentType:  "application/json",
		Response:            new(authtypes.GettableToken),
		ResponseContentType: "application/json",
		SuccessStatusCode:   http.StatusOK,
		ErrorStatusCodes:    []int{http.StatusBadRequest},
		Deprecated:          false,
		SecuritySchemes:     []handler.OpenAPISecurityScheme{},
	}, handler.WithResourceDefs(handler.BasicResourceDef{
		Resource: coretypes.ResourceMetaResourceSession,
		Verb:     coretypes.VerbUpdate,
		Category: coretypes.ActionCategoryAccessControl,
		Selector: coretypes.WildcardSelector,
	}))).Methods(http.MethodPost).GetError(); err != nil {
		return err
	}

	if err := router.Handle("/api/v2/sessions", handler.New(provider.authzMiddleware.OpenAccess(provider.sessionHandler.DeleteSession), handler.OpenAPIDef{
		ID:                  "DeleteSession",
		Tags:                []string{"sessions"},
		Summary:             "Delete session",
		Description:         "This endpoint deletes the session",
		Request:             nil,
		RequestContentType:  "",
		Response:            nil,
		ResponseContentType: "",
		SuccessStatusCode:   http.StatusNoContent,
		ErrorStatusCodes:    []int{http.StatusBadRequest},
		Deprecated:          false,
		SecuritySchemes:     []handler.OpenAPISecurityScheme{{Name: authtypes.IdentNProviderTokenizer.StringValue()}},
	}, handler.WithResourceDefs(handler.BasicResourceDef{
		Resource: coretypes.ResourceMetaResourceSession,
		Verb:     coretypes.VerbDelete,
		Category: coretypes.ActionCategoryAccessControl,
		Selector: coretypes.WildcardSelector,
	}))).Methods(http.MethodDelete).GetError(); err != nil {
		return err
	}

	if err := router.Handle("/api/v1/complete/google", handler.New(provider.authzMiddleware.OpenAccess(provider.sessionHandler.CreateSessionByGoogleCallback), handler.OpenAPIDef{
		ID:                  "CreateSessionByGoogleCallback",
		Tags:                []string{"sessions"},
		Summary:             "Create session by google callback",
		Description:         "This endpoint creates a session for a user using google callback",
		Request:             nil,
		RequestContentType:  "",
		Response:            new(authtypes.GettableToken),
		ResponseContentType: "application/json",
		SuccessStatusCode:   http.StatusSeeOther,
		ErrorStatusCodes:    []int{http.StatusBadRequest, http.StatusNotFound},
		Deprecated:          false,
		SecuritySchemes:     []handler.OpenAPISecurityScheme{},
	}, handler.WithResourceDefs(handler.BasicResourceDef{
		Resource: coretypes.ResourceMetaResourceSession,
		Verb:     coretypes.VerbCreate,
		Category: coretypes.ActionCategoryAccessControl,
		Selector: coretypes.WildcardSelector,
	}))).Methods(http.MethodGet).GetError(); err != nil {
		return err
	}

	if err := router.Handle("/api/v1/complete/saml", handler.New(provider.authzMiddleware.OpenAccess(provider.sessionHandler.CreateSessionBySAMLCallback), handler.OpenAPIDef{
		ID:          "CreateSessionBySAMLCallback",
		Tags:        []string{"sessions"},
		Summary:     "Create session by saml callback",
		Description: "This endpoint creates a session for a user using saml callback",
		Request: struct {
			RelayState   string `form:"RelayState"`
			SAMLResponse string `form:"SAMLResponse"`
		}{},
		RequestContentType:  "application/x-www-form-urlencoded",
		Response:            new(authtypes.GettableToken),
		ResponseContentType: "application/json",
		SuccessStatusCode:   http.StatusSeeOther,
		ErrorStatusCodes:    []int{http.StatusBadRequest, http.StatusNotFound, http.StatusUnavailableForLegalReasons},
		Deprecated:          false,
		SecuritySchemes:     []handler.OpenAPISecurityScheme{},
	}, handler.WithResourceDefs(handler.BasicResourceDef{
		Resource: coretypes.ResourceMetaResourceSession,
		Verb:     coretypes.VerbCreate,
		Category: coretypes.ActionCategoryAccessControl,
		Selector: coretypes.WildcardSelector,
	}))).Methods(http.MethodPost).GetError(); err != nil {
		return err
	}

	if err := router.Handle("/api/v1/complete/oidc", handler.New(provider.authzMiddleware.OpenAccess(provider.sessionHandler.CreateSessionByOIDCCallback), handler.OpenAPIDef{
		ID:                  "CreateSessionByOIDCCallback",
		Tags:                []string{"sessions"},
		Summary:             "Create session by oidc callback",
		Description:         "This endpoint creates a session for a user using oidc callback",
		Request:             nil,
		RequestContentType:  "",
		Response:            new(authtypes.GettableToken),
		ResponseContentType: "application/json",
		SuccessStatusCode:   http.StatusSeeOther,
		ErrorStatusCodes:    []int{http.StatusBadRequest, http.StatusNotFound, http.StatusUnavailableForLegalReasons},
		Deprecated:          false,
		SecuritySchemes:     []handler.OpenAPISecurityScheme{},
	}, handler.WithResourceDefs(handler.BasicResourceDef{
		Resource: coretypes.ResourceMetaResourceSession,
		Verb:     coretypes.VerbCreate,
		Category: coretypes.ActionCategoryAccessControl,
		Selector: coretypes.WildcardSelector,
	}))).Methods(http.MethodGet).GetError(); err != nil {
		return err
	}

	return nil
}
