package communitypostgres

import (
	"context"
	"database/sql"
	"os"
	"testing"

	"github.com/SigNoz/signoz/pkg/errors"
	"github.com/SigNoz/signoz/pkg/sqlschema"
	"github.com/SigNoz/signoz/pkg/sqlstore"
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/stretchr/testify/require"
	"github.com/uptrace/bun"
	"github.com/uptrace/bun/dialect/pgdialect"
)

// Catalog reads must use the same connection as the migration transaction.
type testStore struct {
	sqlstore.SQLStore
	db *bun.DB
	tx bun.Tx
}

func (s testStore) BunDB() *bun.DB                   { return s.db }
func (s testStore) BunDBCtx(context.Context) bun.IDB { return s.tx }

func TestPostgresCatalog(t *testing.T) {
	dsn := os.Getenv("SIGNOZ_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("set SIGNOZ_TEST_POSTGRES_DSN to run against PostgreSQL")
	}
	raw, err := sql.Open("pgx", dsn)
	require.NoError(t, err)
	db := bun.NewDB(raw, pgdialect.New())
	t.Cleanup(func() { _ = db.Close() })
	ctx := context.Background()
	tx, err := db.BeginTx(ctx, nil)
	require.NoError(t, err)
	t.Cleanup(func() { _ = tx.Rollback() })
	p := newProvider(testStore{db: db, tx: tx})

	for _, ddl := range []string{
		"CREATE TEMP TABLE oidc_parent (id text PRIMARY KEY)",
		"CREATE TEMP TABLE oidc_catalog (id text NOT NULL, parent_id text REFERENCES oidc_parent(id), body bytea, at timestamptz DEFAULT CURRENT_TIMESTAMP, email text, CONSTRAINT composite_key PRIMARY KEY (id, parent_id), CONSTRAINT email_and_parent UNIQUE (email, parent_id))",
		"CREATE UNIQUE INDEX functional_idx ON oidc_catalog (lower(email), parent_id)",
		"CREATE UNIQUE INDEX partial_idx ON oidc_catalog (email) WHERE body IS NOT NULL",
		"CREATE UNIQUE INDEX ordinary_idx ON oidc_catalog (parent_id, id)",
	} {
		_, err = tx.ExecContext(ctx, ddl)
		require.NoError(t, err)
	}

	table, constraints, err := p.GetTable(ctx, "oidc_catalog")
	require.NoError(t, err)
	require.Len(t, table.Columns, 5)
	require.Equal(t, sqlschema.DataTypeBytea, table.Columns[2].DataType)
	require.Equal(t, sqlschema.DataTypeTimestamp, table.Columns[3].DataType)
	require.Equal(t, "CURRENT_TIMESTAMP", table.Columns[3].Default)
	require.False(t, table.Columns[0].Nullable)
	require.Equal(t, []sqlschema.ColumnName{"id", "parent_id"}, table.PrimaryKeyConstraint.Columns())
	require.Equal(t, "composite_key", table.PrimaryKeyConstraint.Name(table.Name))
	require.Len(t, constraints, 1)
	require.Equal(t, []sqlschema.ColumnName{"email", "parent_id"}, constraints[0].Columns())
	require.Len(t, table.ForeignKeyConstraints, 1)
	require.Equal(t, sqlschema.TableName("oidc_parent"), table.ForeignKeyConstraints[0].ReferencedTableName)

	indices, err := p.GetIndices(ctx, table.Name)
	require.NoError(t, err)
	byName := make(map[string]sqlschema.Index)
	for _, index := range indices {
		byName[index.Name()] = index
	}
	require.Len(t, byName, 3)
	require.Equal(t, []string{"lower(email)", "parent_id"}, byName["functional_idx"].(*sqlschema.UniqueIndexWithExpressions).Expressions)
	require.Equal(t, []sqlschema.ColumnName{"parent_id", "id"}, byName["ordinary_idx"].Columns())
	require.Contains(t, byName["partial_idx"].(*sqlschema.PartialUniqueIndex).Where, "body IS NOT NULL")

	c := &sqlschema.Column{Name: "enabled", DataType: sqlschema.DataTypeBoolean, Nullable: false}
	for _, ddl := range p.Operator().AddColumn(table, constraints, c, true) {
		_, err = tx.ExecContext(ctx, string(ddl))
		require.NoError(t, err)
	}
	updated, _, err := p.GetTable(ctx, table.Name)
	require.NoError(t, err)
	require.False(t, updated.Columns[5].Nullable)
	_, _, err = p.GetTable(ctx, "oidc_no_such_table")
	require.True(t, errors.Ast(err, errors.TypeNotFound))
}
