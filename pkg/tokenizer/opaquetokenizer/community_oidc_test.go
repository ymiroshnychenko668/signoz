package opaquetokenizer

import (
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/SigNoz/signoz/pkg/cache"
	"github.com/SigNoz/signoz/pkg/cache/cachetest"
	"github.com/SigNoz/signoz/pkg/factory/factorytest"
	"github.com/SigNoz/signoz/pkg/sqlstore"
	"github.com/SigNoz/signoz/pkg/sqlstore/communitypostgres"
	"github.com/SigNoz/signoz/pkg/sqlstore/sqlitesqlstore"
	"github.com/SigNoz/signoz/pkg/tokenizer/tokenizerstore/sqltokenizerstore"

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

func TestEnforcedSessionsRequireAnActiveCurrentRow(t *testing.T) {
	t.Run("SQLite", func(t *testing.T) {
		db, err := sqlitesqlstore.New(t.Context(), factorytest.NewSettings(), sqlstore.Config{
			Connection: sqlstore.ConnectionConfig{MaxOpenConns: 1},
			Sqlite:     sqlstore.SqliteConfig{Path: filepath.Join(t.TempDir(), "tokens.db"), Mode: "wal", TransactionMode: "immediate", BusyTimeout: 5 * time.Second},
		})
		require.NoError(t, err)
		t.Cleanup(func() { _ = db.SQLDB().Close() })
		checkSessionRevocation(t, db)
	})
	t.Run("Postgres", func(t *testing.T) {
		dsn := os.Getenv("SIGNOZ_TEST_POSTGRES_DSN")
		if dsn == "" {
			t.Skip("set SIGNOZ_TEST_POSTGRES_DSN for PostgreSQL integration")
		}
		db, err := communitypostgres.NewFactory().New(t.Context(), factorytest.NewSettings(), sqlstore.Config{Postgres: sqlstore.PostgresConfig{DSN: dsn}})
		require.NoError(t, err)
		t.Cleanup(db.(*communitypostgres.Store).Pool().Close)
		t.Cleanup(func() { _ = db.SQLDB().Close() })
		// Keep the temporary token table on one connection, including transactions.
		db.SQLDB().SetMaxOpenConns(1)
		db.SQLDB().SetMaxIdleConns(1)
		checkSessionRevocation(t, db)
	})
}

func checkSessionRevocation(t *testing.T, db sqlstore.SQLStore) {
	t.Helper()
	ctx, settings := t.Context(), factorytest.NewSettings()
	// Migration 050 stores account identifiers and metadata as text.
	_, err := db.BunDB().ExecContext(ctx, `CREATE TEMP TABLE auth_token (
		id TEXT PRIMARY KEY, meta TEXT NOT NULL, user_id TEXT NOT NULL,
		access_token TEXT NOT NULL UNIQUE, refresh_token TEXT NOT NULL UNIQUE,
		prev_access_token TEXT, prev_refresh_token TEXT,
		last_observed_at TIMESTAMP, rotated_at TIMESTAMP,
		created_at TIMESTAMP NOT NULL, updated_at TIMESTAMP NOT NULL
	)`)
	require.NoError(t, err)
	kv, err := cachetest.New(cache.Config{Memory: cache.Memory{NumCounters: 1000, MaxCost: 1 << 20}})
	require.NoError(t, err)
	org := valuer.GenerateUUID()
	sessions, err := New(ctx, settings, tokenizer.Config{
		EnforcedBrowserOrg: org,
		Rotation:           tokenizer.RotationConfig{Interval: 30 * time.Minute, Duration: time.Minute},
		Lifetime:           tokenizer.LifetimeConfig{Idle: time.Hour, Max: 24 * time.Hour},
		Opaque:             tokenizer.OpaqueConfig{Token: tokenizer.TokenConfig{MaxPerUser: 5}},
	}, kv, sqltokenizerstore.NewStore(db), nil)
	require.NoError(t, err)
	id := authtypes.NewPrincipalUserIdentity(valuer.GenerateUUID(), org, valuer.MustNewEmail("viewer@example.test"), authtypes.IdentNProviderTokenizer)
	create := func() *authtypes.Token {
		t.Helper()
		token, err := sessions.CreateToken(ctx, id, map[string]string{authtypes.CommunityOIDCDeadline: strconv.FormatInt(time.Now().Add(time.Hour).Unix(), 10)})
		require.NoError(t, err)
		return token
	}
	first := create()
	other := create()
	rotated, err := sessions.RotateToken(ctx, first.AccessToken, first.RefreshToken)
	require.NoError(t, err)
	_, err = sessions.GetIdentity(ctx, rotated.AccessToken)
	require.NoError(t, err)
	// A normal refresh can finish just before the logout request reaches storage.
	require.NoError(t, sessions.DeleteToken(ctx, first.AccessToken))
	require.NoError(t, sessions.DeleteToken(ctx, first.AccessToken))
	// A delayed cache write from another worker must never restore a removed session.
	for _, old := range []*authtypes.Token{first, rotated} {
		require.NoError(t, kv.Set(ctx, emptyOrgID, accessTokenCacheKey(old.AccessToken), old, time.Hour))
		require.NoError(t, sessions.SetLastObservedAt(ctx, old.AccessToken, time.Now()))
		_, err := sessions.GetIdentity(ctx, old.AccessToken)
		require.Error(t, err)
		_, err = sessions.RotateToken(ctx, old.AccessToken, old.RefreshToken)
		require.Error(t, err)
	}
	// Buffered activity belongs only to an active row. An idle session cannot
	// be restarted by a post-request timestamp arriving late.
	idle := create()
	require.NoError(t, sessions.SetLastObservedAt(ctx, other.AccessToken, time.Now()))
	for _, token := range []*authtypes.Token{other, idle} {
		_, err = db.BunDB().NewUpdate().Model((*authtypes.Token)(nil)).Set("last_observed_at = ?", time.Now().Add(-2*time.Hour)).Where("id = ?", token.ID).Exec(ctx)
		require.NoError(t, err)
	}
	require.NoError(t, sessions.SetLastObservedAt(ctx, idle.AccessToken, time.Now()))
	_, err = sessions.GetIdentity(ctx, idle.AccessToken)
	require.Error(t, err)
	_, err = sessions.GetIdentity(ctx, other.AccessToken)
	require.NoError(t, err)
	require.NoError(t, sessions.DeleteTokensByUserID(ctx, id.UserID))
	require.NoError(t, kv.Set(ctx, emptyOrgID, accessTokenCacheKey(other.AccessToken), other, time.Hour))
	_, err = sessions.GetIdentity(ctx, other.AccessToken)
	require.Error(t, err)
}
