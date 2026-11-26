package opaquetokenizer

import (
	"testing"

	"github.com/SigNoz/signoz/pkg/tokenizer"
	"github.com/SigNoz/signoz/pkg/types/authtypes"
	"github.com/SigNoz/signoz/pkg/valuer"
	"github.com/stretchr/testify/require"
)

func TestCutoverRejectsPreexistingBrowserSessionsForEnforcedOrg(t *testing.T) {
	org := valuer.GenerateUUID()
	p := provider{config: tokenizer.Config{EnforcedBrowserOrg: org}}
	id := &authtypes.Identity{OrgID: org}
	legacy := &authtypes.Token{}
	require.Error(t, p.checkBrowserSession(legacy, id))
	require.NoError(t, p.checkBrowserSession(legacy, &authtypes.Identity{OrgID: valuer.GenerateUUID()}))
	require.NoError(t, p.checkBrowserSession(&authtypes.Token{Meta: map[string]string{authtypes.CommunityOIDCRoot: "true"}}, id))
	require.NoError(t, p.checkBrowserSession(&authtypes.Token{Meta: map[string]string{authtypes.CommunityOIDCDeadline: "123456"}}, id))
}
