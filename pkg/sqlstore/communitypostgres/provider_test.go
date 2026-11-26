package communitypostgres

import (
	"context"
	"os"
	"testing"

	"github.com/SigNoz/signoz/pkg/errors"
	"github.com/SigNoz/signoz/pkg/factory/factorytest"
	"github.com/SigNoz/signoz/pkg/sqlstore"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/require"
)

func TestConflictClassification(t *testing.T) {
	s := &Store{}
	for _, code := range []string{"23503", "23505"} {
		err := s.WrapAlreadyExistsErrf(&pgconn.PgError{Code: code}, errors.CodeAlreadyExists, "conflict")
		require.Equal(t, code == "23505", errors.Ast(err, errors.TypeAlreadyExists))
	}
}

func TestPostgresJSONExpressionsAndLegacyConversion(t *testing.T) {
	dsn := os.Getenv("SIGNOZ_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("set SIGNOZ_TEST_POSTGRES_DSN for a PostgreSQL integration test")
	}
	ctx := context.Background()
	s, err := NewFactory().New(ctx, factorytest.NewSettings(), sqlstore.Config{Postgres: sqlstore.PostgresConfig{DSN: dsn}})
	require.NoError(t, err)
	defer s.(*Store).Pool().Close()
	defer s.SQLDB().Close()
	require.NoError(t, s.RunInTxCtx(ctx, nil, func(ctx context.Context) error {
		db := s.BunDBCtx(ctx)
		_, err := db.ExecContext(ctx, `CREATE TEMP TABLE oidc_pg_contract (data text, legacy bigint NOT NULL DEFAULT 0) ON COMMIT DROP`)
		require.NoError(t, err)
		_, err = db.ExecContext(ctx, `INSERT INTO oidc_pg_contract VALUES ('{"tags":["one","two"],"labels":{"a.b":"literal","team":"test"}}',1700000000)`)
		require.NoError(t, err)
		f := s.Formatter()
		var found string
		require.NoError(t, db.NewRaw("SELECT "+string(f.JSONExtractMapValue("data", "labels", "a.b"))+" FROM oidc_pg_contract").Scan(ctx, &found))
		require.Equal(t, "literal", found)
		require.NoError(t, db.NewRaw("SELECT "+string(f.JSONExtractString("data", "$.labels.team"))+" FROM oidc_pg_contract").Scan(ctx, &found))
		require.Equal(t, "test", found)
		from, value := f.JSONArrayOfStrings("data", "$.tags", "item")
		var items []string
		require.NoError(t, db.NewRaw("SELECT "+string(value)+" FROM oidc_pg_contract, "+string(from)+" ORDER BY 1").Scan(ctx, &items))
		require.Equal(t, []string{"one", "two"}, items)
		_, err = db.ExecContext(ctx, "SET LOCAL search_path TO pg_temp")
		require.NoError(t, err)
		require.NoError(t, s.Dialect().IntToTimestamp(ctx, db, "oidc_pg_contract", "legacy"))
		require.NoError(t, db.NewRaw("SELECT data_type || ':' || is_nullable FROM information_schema.columns WHERE table_schema=current_schema() AND table_name='oidc_pg_contract' AND column_name='legacy'").Scan(ctx, &found))
		require.Equal(t, "timestamp without time zone:YES", found)
		require.NoError(t, db.NewRaw("SELECT to_char(legacy,'YYYY-MM-DD HH24:MI:SS') FROM oidc_pg_contract").Scan(ctx, &found))
		require.Equal(t, "2023-11-14 22:13:20", found)
		return nil
	}))
}
