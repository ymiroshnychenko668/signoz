package communityoidc

import (
	"encoding/json"
	"errors"
	"io"
	"net/url"
	"os"
	"path"
	"strings"
	"time"

	"github.com/SigNoz/signoz/pkg/types/authtypes"
	"github.com/SigNoz/signoz/pkg/valuer"
	"github.com/google/uuid"
)

var ProviderID = authtypes.AuthNProvider{String: valuer.NewString("community_oidc")}

// Config is private installation configuration. Links maps an explicitly approved
// subject to the ID of a pre-existing account in this issuer's organization.
type Config struct {
	Issuer            string                 `json:"issuer"`
	PublicURL         string                 `json:"publicURL"`
	ClientID          string                 `json:"clientId"`
	ClientSecretFile  string                 `json:"clientSecretFile"`
	OrgID             valuer.UUID            `json:"orgId"`
	GroupRoles        map[string]string      `json:"groupRoles"`
	Links             map[string]valuer.UUID `json:"links"`
	MaxSessionSeconds int                    `json:"maxSessionSeconds"`
}

func Load(filename string) (*Provider, error) {
	if filename == "" {
		return nil, nil
	}
	f, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var cfg Config
	decoder := json.NewDecoder(f)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&cfg); err != nil {
		return nil, errors.New("invalid community OIDC configuration file")
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return nil, errors.New("trailing data in community OIDC configuration file")
	}
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	secret, err := os.ReadFile(cfg.ClientSecretFile)
	if err != nil {
		return nil, err
	}
	clientSecret := strings.TrimSpace(string(secret))
	if clientSecret == "" {
		return nil, errors.New("empty community OIDC client secret")
	}
	return &Provider{Config: cfg, secret: clientSecret}, nil
}

func (c Config) validate() error {
	for _, value := range []string{c.Issuer, c.PublicURL} {
		u, err := url.Parse(value)
		if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.RawPath != "" || strings.Contains(value, "\\") || u.Path != "" && path.Clean(u.Path) != u.Path {
			return errors.New("community OIDC issuer and publicURL must be canonical HTTPS URLs")
		}
	}
	if c.ClientID == "" || c.ClientSecretFile == "" || c.OrgID.IsZero() || c.MaxSessionSeconds < 60 || c.MaxSessionSeconds > 3600 || len(c.GroupRoles) == 0 {
		return errors.New("community OIDC requires clientId, clientSecretFile, orgId, groupRoles and maxSessionSeconds between 60 and 3600")
	}
	for group, role := range c.GroupRoles {
		if strings.TrimSpace(group) == "" || (role != authtypes.SigNozViewerRoleName && role != authtypes.SigNozEditorRoleName && role != authtypes.SigNozAdminRoleName) {
			return errors.New("invalid community OIDC group or managed role")
		}
	}
	seen := map[valuer.UUID]bool{}
	for subject, id := range c.Links {
		// Upstream creates UUIDv7 accounts. UUIDv5 is reserved here for
		// automatically provisioned identities and cannot be reassigned.
		parsed, _ := uuid.Parse(id.String())
		if strings.TrimSpace(subject) == "" || id.IsZero() || parsed.Version() == 5 || seen[id] {
			return errors.New("invalid or duplicate community OIDC account link")
		}
		seen[id] = true
	}
	return nil
}

func (c Config) Target(subject string) (valuer.UUID, bool) {
	if existing, ok := c.Links[subject]; ok {
		return existing, true
	}
	// A NUL separator makes the issuer and subject pair unambiguous.
	namespace := uuid.MustParse(c.OrgID.String())
	return valuer.MustNewUUID(uuid.NewSHA1(namespace, []byte(c.Issuer+"\x00"+subject)).String()), false
}

func (c Config) url(suffix string) string { return strings.TrimRight(c.PublicURL, "/") + suffix }

func (c Config) ttl() time.Duration { return time.Duration(c.MaxSessionSeconds) * time.Second }

func (c Config) mappedRole(groups []string) string {
	rank := map[string]int{authtypes.SigNozViewerRoleName: 1, authtypes.SigNozEditorRoleName: 2, authtypes.SigNozAdminRoleName: 3}
	role := ""
	for _, group := range groups {
		if candidate := c.GroupRoles[group]; rank[candidate] > rank[role] {
			role = candidate
		}
	}
	return role
}
