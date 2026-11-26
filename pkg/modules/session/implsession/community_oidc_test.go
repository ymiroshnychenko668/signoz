package implsession

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/SigNoz/signoz/pkg/authn"
	"github.com/SigNoz/signoz/pkg/authn/communityoidc"
	"github.com/SigNoz/signoz/pkg/authz"
	"github.com/SigNoz/signoz/pkg/errors"
	"github.com/SigNoz/signoz/pkg/modules/user"
	"github.com/SigNoz/signoz/pkg/tokenizer"
	"github.com/SigNoz/signoz/pkg/types"
	"github.com/SigNoz/signoz/pkg/types/authtypes"
	"github.com/SigNoz/signoz/pkg/valuer"
)

type accountDirectory struct {
	user.Getter
	accounts map[valuer.UUID]*types.User
	root     *types.User
}

func (d *accountDirectory) GetUserByOrgIDAndID(_ context.Context, org, id valuer.UUID) (*types.User, error) {
	u := d.accounts[id]
	if u == nil || u.OrgID != org {
		return nil, errors.New(errors.TypeNotFound, errors.CodeNotFound, "missing")
	}
	return u, nil
}
func (d *accountDirectory) ListUsersByEmailAndOrgIDs(_ context.Context, email valuer.Email, orgs []valuer.UUID) ([]*types.User, error) {
	var matches []*types.User
	for _, u := range d.accounts {
		if u.Email == email && u.OrgID == orgs[0] {
			matches = append(matches, u)
		}
	}
	return matches, nil
}
func (d *accountDirectory) GetRootUserByOrgID(context.Context, valuer.UUID) (*types.User, []*authtypes.UserRole, error) {
	return d.root, nil, nil
}

type userRoles struct {
	user.Setter
	directory *accountDirectory
	role      string
}

func (d *userRoles) CreateUser(_ context.Context, u *types.User, opts ...user.CreateUserOption) error {
	d.directory.accounts[u.ID] = u
	return nil
}
func (d *userRoles) UpdateUserRoles(_ context.Context, org, id valuer.UUID, names []string) error {
	d.role = names[0]
	return nil
}

type grants struct {
	authz.AuthZ
	granted string
	revoked []string
}

func (g *grants) List(context.Context, valuer.UUID) ([]*authtypes.Role, error) {
	return []*authtypes.Role{{Name: "signoz-viewer"}, {Name: "signoz-admin"}}, nil
}
func (g *grants) ModifyGrant(_ context.Context, _ valuer.UUID, remove, add []string, _ string) error {
	g.revoked = remove
	g.granted = add[0]
	return nil
}

type sessionTokens struct {
	tokenizer.Tokenizer
	count int
}

func (s *sessionTokens) CreateToken(_ context.Context, id *authtypes.Identity, meta map[string]string) (*authtypes.Token, error) {
	s.count++
	return authtypes.NewToken(meta, id.UserID)
}

type testPassword struct{ i *authtypes.Identity }

func (p testPassword) Authenticate(context.Context, string, string, valuer.UUID) (*authtypes.Identity, error) {
	return p.i, nil
}

func TestOrganizationIdentityAndSSOPolicy(t *testing.T) {
	org := valuer.GenerateUUID()
	p := &communityoidc.Provider{Config: communityoidc.Config{OrgID: org, Issuer: "https://sso.example.org", Links: map[string]valuer.UUID{}}}
	d := &accountDirectory{accounts: map[valuer.UUID]*types.User{}}
	setter := &userRoles{directory: d}
	g := &grants{}
	tokens := &sessionTokens{}
	m := &module{authNs: map[authtypes.AuthNProvider]authn.AuthN{communityoidc.ProviderID: p}, userGetter: d, userSetter: setter, authz: g, tokenizer: tokens}
	ctx := context.Background()
	login := &communityoidc.Login{Subject: "subject-a", Name: "Reader", Role: "signoz-admin", Email: valuer.MustNewEmail("reader@example.org"), Deadline: time.Now().Add(5 * time.Minute)}
	first, err := m.CreateCommunityOIDCSession(ctx, login)
	require.NoError(t, err)
	require.Equal(t, "signoz-admin", setter.role)
	require.Equal(t, "signoz-admin", g.granted)
	require.Equal(t, []string{"signoz-viewer"}, g.revoked)
	require.NotEmpty(t, first.Meta[authtypes.CommunityOIDCDeadline])
	login.Role = "signoz-viewer"
	second, err := m.CreateCommunityOIDCSession(ctx, login)
	require.NoError(t, err)
	require.Equal(t, first.UserID, second.UserID)
	require.Equal(t, "signoz-viewer", setter.role)
	require.Equal(t, []string{"signoz-admin"}, g.revoked)
	login.Subject = "different"
	_, err = m.CreateCommunityOIDCSession(ctx, login)
	require.Error(t, err)
	login.Subject = "subject-a"
	d.accounts[first.UserID].Status = types.UserStatusDeleted
	_, err = m.CreateCommunityOIDCSession(ctx, login)
	require.Error(t, err)
	login.Subject = "different"
	_, err = m.CreateCommunityOIDCSession(ctx, login)
	require.Error(t, err)
	legacy, err := types.NewUser("Existing", valuer.MustNewEmail("existing@example.org"), org, types.UserStatusActive)
	require.NoError(t, err)
	d.accounts[legacy.ID] = legacy
	p.Links["legacy"] = legacy.ID
	login.Subject = "legacy"
	token, err := m.CreateCommunityOIDCSession(ctx, login)
	require.NoError(t, err)
	require.Equal(t, legacy.ID, token.UserID)
	legacy.OrgID = valuer.GenerateUUID()
	_, err = m.CreateCommunityOIDCSession(ctx, login)
	require.Error(t, err)
	legacy.OrgID = org
	d.root, err = types.NewRootUser("Recovery", valuer.MustNewEmail("recovery@example.org"), org)
	require.NoError(t, err)
	d.accounts[d.root.ID] = d.root
	p.Links["root"] = d.root.ID
	login.Subject = "root"
	_, err = m.CreateCommunityOIDCSession(ctx, login)
	require.Error(t, err)
	m.authNs[authtypes.AuthNProviderEmailPassword] = testPassword{authtypes.NewPrincipalUserIdentity(legacy.ID, org, legacy.Email, authtypes.IdentNProviderTokenizer)}
	_, err = m.CreatePasswordAuthNSession(ctx, authtypes.AuthNProviderEmailPassword, legacy.Email, "test", org)
	require.Error(t, err)
	m.authNs[authtypes.AuthNProviderEmailPassword] = testPassword{authtypes.NewPrincipalUserIdentity(d.root.ID, org, d.root.Email, authtypes.IdentNProviderTokenizer)}
	token, err = m.CreatePasswordAuthNSession(ctx, authtypes.AuthNProviderEmailPassword, d.root.Email, "test", org)
	require.NoError(t, err)
	require.Equal(t, "true", token.Meta[authtypes.CommunityOIDCRoot])
	require.Equal(t, 4, tokens.count)
}
