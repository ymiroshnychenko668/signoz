package communitypostgres

import (
	"context"
	"fmt"
	"reflect"

	"github.com/SigNoz/signoz/pkg/sqlstore/sqlitesqlstore"
	"github.com/uptrace/bun"
)

type dialect struct{}

func tableName(db bun.IDB, model any) string {
	return db.Dialect().Tables().Get(reflect.TypeOf(model)).Name
}
func (dialect) GetColumnType(ctx context.Context, db bun.IDB, table, column string) (string, error) {
	var typ string
	err := db.NewRaw("SELECT data_type FROM information_schema.columns WHERE table_schema=current_schema() AND table_name=? AND column_name=?", table, column).Scan(ctx, &typ)
	return typ, err
}
func (dialect) ColumnExists(ctx context.Context, db bun.IDB, table, column string) (bool, error) {
	var exists bool
	err := db.NewRaw("SELECT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema=current_schema() AND table_name=? AND column_name=?)", table, column).Scan(ctx, &exists)
	return exists, err
}
func (dialect) TableExists(ctx context.Context, db bun.IDB, model any) (bool, error) {
	var exists bool
	err := db.NewRaw("SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_schema=current_schema() AND table_name=?)", tableName(db, model)).Scan(ctx, &exists)
	return exists, err
}
func (d dialect) IntToTimestamp(ctx context.Context, db bun.IDB, t, c string) error {
	return d.convertIntegral(ctx, db, t, c, "timestamp without time zone", "to_timestamp(?) AT TIME ZONE 'UTC'")
}
func (d dialect) IntToBoolean(ctx context.Context, db bun.IDB, t, c string) error {
	ok, err := d.ColumnExists(ctx, db, t, c)
	if err != nil || !ok {
		return err
	}
	return d.convertIntegral(ctx, db, t, c, "boolean", "(? = 1)")
}
func (d dialect) convertIntegral(ctx context.Context, db bun.IDB, t, c, target, using string) error {
	typ, err := d.GetColumnType(ctx, db, t, c)
	if err != nil {
		return err
	}
	if typ != "smallint" && typ != "integer" && typ != "bigint" {
		return nil
	}
	col := bun.Ident(c)
	// Old numeric defaults cannot be cast implicitly to timestamp or boolean.
	_, err = db.ExecContext(ctx, "ALTER TABLE ? ALTER COLUMN ? DROP DEFAULT, ALTER COLUMN ? DROP NOT NULL, ALTER COLUMN ? TYPE "+target+" USING "+using, bun.Ident(t), col, col, col, col)
	return err
}
func (dialect) AddNotNullDefaultToColumn(ctx context.Context, db bun.IDB, t, c, typ, defaultSQL string) error {
	_, err := db.ExecContext(ctx, "ALTER TABLE ? ALTER COLUMN ? SET DEFAULT ?, ALTER COLUMN ? SET NOT NULL", bun.Ident(t), bun.Ident(c), bun.Safe(defaultSQL), bun.Ident(c))
	return err
}
func (dialect) AddColumn(ctx context.Context, db bun.IDB, t, c, typ string) error {
	_, err := db.ExecContext(ctx, "ALTER TABLE ? ADD COLUMN IF NOT EXISTS ? ?", bun.Ident(t), bun.Ident(c), bun.Safe(typ))
	return err
}
func (dialect) DropColumn(ctx context.Context, db bun.IDB, t, c string) error {
	_, err := db.ExecContext(ctx, "ALTER TABLE ? DROP COLUMN IF EXISTS ?", bun.Ident(t), bun.Ident(c))
	return err
}
func (d dialect) RenameColumn(ctx context.Context, db bun.IDB, t, old, current string) (bool, error) {
	exists, err := d.ColumnExists(ctx, db, t, current)
	if err != nil || exists {
		return exists, err
	}
	_, err = db.ExecContext(ctx, "ALTER TABLE ? RENAME COLUMN ? TO ?", bun.Ident(t), bun.Ident(old), bun.Ident(current))
	return err == nil, err
}
func (d dialect) DropColumnWithForeignKeyConstraint(ctx context.Context, db bun.IDB, m any, c string) error {
	return d.DropColumn(ctx, db, tableName(db, m), c)
}

// PostgreSQL drops constraints belonging to a dropped column automatically.
func (dialect) ToggleForeignKeyConstraint(context.Context, *bun.DB, bool) error { return nil }

var references = map[string]string{
	sqlitesqlstore.Org: sqlitesqlstore.OrgReference, sqlitesqlstore.User: sqlitesqlstore.UserReference,
	sqlitesqlstore.UserNoCascade: sqlitesqlstore.UserNoCascadeReference, sqlitesqlstore.FactorPassword: sqlitesqlstore.FactorPasswordReference,
	sqlitesqlstore.CloudIntegration: sqlitesqlstore.CloudIntegrationReference, sqlitesqlstore.AgentConfigVersion: sqlitesqlstore.AgentConfigVersionReference,
}

func (d dialect) RenameTableAndModifyModel(ctx context.Context, db bun.IDB, old, current any, refs []string, copyRows func(context.Context) error) error {
	exists, err := d.TableExists(ctx, db, current)
	if err != nil || exists {
		return err
	}
	return d.copyModel(ctx, db, old, current, refs, copyRows, false)
}
func (d dialect) UpdatePrimaryKey(ctx context.Context, db bun.IDB, old, current any, ref string, copyRows func(context.Context) error) error {
	typ, err := d.GetColumnType(ctx, db, tableName(db, old), "id")
	if err != nil || typ == "text" || typ == "uuid" || typ == "character varying" {
		return err
	}
	return d.copyModel(ctx, db, old, current, []string{ref}, copyRows, true)
}
func (d dialect) AddPrimaryKey(ctx context.Context, db bun.IDB, old, current any, ref string, copyRows func(context.Context) error) error {
	exists, err := d.ColumnExists(ctx, db, tableName(db, old), "id")
	if err != nil || exists {
		return err
	}
	return d.copyModel(ctx, db, old, current, []string{ref}, copyRows, true)
}
func (dialect) copyModel(ctx context.Context, db bun.IDB, old, current any, refs []string, copyRows func(context.Context) error, keepName bool) error {
	create := db.NewCreateTable().Model(current)
	for _, ref := range refs {
		foreignKey, ok := references[ref]
		if !ok {
			return fmt.Errorf("unrecognized migration reference %q", ref)
		}
		create.ForeignKey(foreignKey)
	}
	if _, err := create.Exec(ctx); err != nil {
		return err
	}
	if err := copyRows(ctx); err != nil {
		return err
	}
	if _, err := db.NewDropTable().Model(old).Exec(ctx); err != nil {
		return err
	}
	if keepName {
		_, err := db.ExecContext(ctx, "ALTER TABLE ? RENAME TO ?", bun.Ident(tableName(db, current)), bun.Ident(tableName(db, old)))
		return err
	}
	return nil
}
