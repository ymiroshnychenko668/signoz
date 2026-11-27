package implsession

import (
	"context"
	"net/http"
	"strconv"
	"time"

	"github.com/SigNoz/signoz/pkg/authn/communityoidc"
	"github.com/SigNoz/signoz/pkg/errors"
	"github.com/SigNoz/signoz/pkg/http/render"
	"github.com/SigNoz/signoz/pkg/types"
	"github.com/SigNoz/signoz/pkg/types/authtypes"
	"github.com/SigNoz/signoz/pkg/types/coretypes"
	"github.com/SigNoz/signoz/pkg/valuer"
)

func (m *module) CommunityOIDC() *communityoidc.Provider {
	p, _ := m.authNs[communityoidc.ProviderID].(*communityoidc.Provider)
	return p
}

func accountDenied() error {
	return errors.New(errors.TypeForbidden, errors.CodeForbidden, "single sign-on account is not eligible")
}

func (m *module) account(ctx context.Context, p *communityoidc.Provider, login *communityoidc.Login) (*types.User, error) {
	id, linked := p.Target(login.Subject)
	account, err := m.userGetter.GetUserByOrgIDAndID(ctx, p.OrgID, id)
	if err == nil {
		if account.OrgID != p.OrgID || account.ID != id || account.IsRoot || account.Status != types.UserStatusActive {
			return nil, accountDenied()
		}
		return account, nil
	}
	if !errors.Ast(err, errors.TypeNotFound) {
		return nil, err
	}
	if linked {
		return nil, accountDenied()
	}
	// Also check historical records: a newly issued subject cannot reclaim a
	// deleted user's email. Only installation-approved links can migrate users.
	existing, err := m.userGetter.ListUsersByEmailAndOrgIDs(ctx, login.Email, []valuer.UUID{p.OrgID})
	if err != nil {
		return nil, err
	}
	if len(existing) != 0 {
		return nil, accountDenied()
	}
	account, err = types.NewUser(login.Name, login.Email, p.OrgID, types.UserStatusActive)
	if err != nil {
		return nil, err
	}
	account.ID = id
	// Create without an FGA grant. No rights are granted before SQL identity
	// uniqueness has succeeded, including on concurrent first logins.
	if err = m.userSetter.CreateUser(ctx, account); err != nil {
		return nil, err
	}
	return account, nil
}

func (m *module) CreateCommunityOIDCSession(ctx context.Context, login *communityoidc.Login) (*authtypes.Token, error) {
	p := m.CommunityOIDC()
	if p == nil || login == nil || !time.Now().Before(login.Deadline) {
		return nil, accountDenied()
	}
	m.communityLoginMu.Lock()
	defer m.communityLoginMu.Unlock()
	account, err := m.account(ctx, p, login)
	if err != nil {
		return nil, err
	}
	roles, err := m.authz.List(ctx, p.OrgID)
	if err != nil {
		return nil, err
	}
	var revoke []string
	var found bool
	for _, role := range roles {
		if role.Name == login.Role {
			found = true
		} else {
			revoke = append(revoke, role.Name)
		}
	}
	if !found {
		return nil, accountDenied()
	}
	// Reconcile both FGA grants and the SQL projection on every login.
	// Revoking all other roles also repairs interrupted prior reconciliations.
	subject := authtypes.MustNewSubject(coretypes.NewResourceUser(), account.ID.StringValue(), p.OrgID, nil)
	if err = m.authz.ModifyGrant(ctx, p.OrgID, revoke, []string{login.Role}, subject); err != nil {
		return nil, err
	}
	if err = m.userSetter.UpdateUserRoles(ctx, p.OrgID, account.ID, []string{login.Role}); err != nil {
		return nil, err
	}
	identity := authtypes.NewPrincipalUserIdentity(account.ID, p.OrgID, account.Email, authtypes.IdentNProviderTokenizer)
	return m.tokenizer.CreateToken(ctx, identity, map[string]string{authtypes.CommunityOIDCDeadline: strconv.FormatInt(login.Deadline.Unix(), 10)})
}

func (h *handler) communityProvider(w http.ResponseWriter) *communityoidc.Provider {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	p := h.module.CommunityOIDC()
	if p == nil {
		render.Error(w, errors.New(errors.TypeNotFound, errors.CodeNotFound, "single sign-on is disabled"))
	}
	return p
}

func (h *handler) CommunityOIDCStatus(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	render.Success(w, http.StatusOK, map[string]bool{"enabled": h.module.CommunityOIDC() != nil})
}

func (h *handler) CommunityOIDCLogin(w http.ResponseWriter, r *http.Request) {
	p := h.communityProvider(w)
	if p == nil {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	u, err := p.Begin(ctx, w)
	if err != nil {
		http.Redirect(w, r, p.ErrorURL(), http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, u, http.StatusSeeOther)
}

func (h *handler) CommunityOIDCCallback(w http.ResponseWriter, r *http.Request) {
	p := h.communityProvider(w)
	if p == nil {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	u, err := p.Callback(ctx, w, r)
	if err != nil {
		http.Redirect(w, r, p.ErrorURL(), http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, u, http.StatusSeeOther)
}

func (h *handler) CommunityOIDCComplete(w http.ResponseWriter, r *http.Request) {
	p := h.communityProvider(w)
	if p == nil {
		return
	}
	login, err := p.Consume(w, r)
	if err != nil {
		render.Error(w, err)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	token, err := h.module.CreateCommunityOIDCSession(ctx, login)
	if err != nil {
		render.Error(w, accountDenied())
		return
	}
	render.Success(w, http.StatusOK, authtypes.NewGettableTokenFromToken(token, h.module.GetRotationInterval(ctx)))
}
