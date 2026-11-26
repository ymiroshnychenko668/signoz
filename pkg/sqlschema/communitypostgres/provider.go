// Package communitypostgres implements the Community migration catalog for PostgreSQL.
package communitypostgres

import (
	"context"
	"fmt"
	"strings"

	"github.com/SigNoz/signoz/pkg/errors"
	"github.com/SigNoz/signoz/pkg/factory"
	"github.com/SigNoz/signoz/pkg/sqlschema"
	"github.com/SigNoz/signoz/pkg/sqlstore"
	"github.com/uptrace/bun"
)

type formatter struct{ sqlschema.Formatter }

func (f formatter) SQLDataTypeOf(t sqlschema.DataType) string {
	switch t {
	case sqlschema.DataTypeTimestamp:
		return "TIMESTAMPTZ"
	case sqlschema.DataTypeBytea:
		return "BYTEA"
	default:
		return f.Formatter.SQLDataTypeOf(t)
	}
}

func (f formatter) DataTypeOf(s string) sqlschema.DataType {
	switch strings.ToLower(s) {
	case "timestamp with time zone", "timestamp without time zone", "timestamptz":
		return sqlschema.DataTypeTimestamp
	case "bytea":
		return sqlschema.DataTypeBytea
	default:
		return f.Formatter.DataTypeOf(s)
	}
}

type provider struct {
	store sqlstore.SQLStore
	fmter formatter
}

func NewFactory(store sqlstore.SQLStore) factory.ProviderFactory[sqlschema.SQLSchema, sqlschema.Config] {
	return factory.NewProviderFactory(factory.MustNewName("postgres"), func(context.Context, factory.ProviderSettings, sqlschema.Config) (sqlschema.SQLSchema, error) {
		return newProvider(store), nil
	})
}

func newProvider(store sqlstore.SQLStore) *provider {
	return &provider{store: store, fmter: formatter{sqlschema.NewFormatter(store.BunDB().Dialect())}}
}

func (p *provider) Formatter() sqlschema.SQLFormatter { return p.fmter }

func (p *provider) Operator() sqlschema.SQLOperator {
	return sqlschema.NewOperator(p.fmter, sqlschema.OperatorSupport{
		SCreateAndDropConstraint:                        true,
		SAlterTableAddAndDropColumnIfNotExistsAndExists: true,
		SAlterTableAlterColumnSetAndDrop:                true,
	})
}

// PostgreSQL changes columns and constraints in place. The SQLite-specific
// disable/re-enable window around table rebuilds is unnecessary here. Keep
// foreign keys enforced for application sessions and throughout migrations.
func (*provider) ToggleFKEnforcement(context.Context, bun.IDB, bool) error { return nil }

func (p *provider) GetTable(ctx context.Context, name sqlschema.TableName) (*sqlschema.Table, []*sqlschema.UniqueConstraint, error) {
	db := p.store.BunDBCtx(ctx)
	var cols []struct {
		Name       string
		Type       string
		Nullable   bool
		DefaultSQL string
	}
	err := db.NewRaw(`
		SELECT a.attname AS name, format_type(a.atttypid, a.atttypmod) AS type,
		       NOT a.attnotnull AS nullable, coalesce(pg_get_expr(d.adbin, d.adrelid), '') AS default_sql
		  FROM pg_catalog.pg_class t
		  JOIN pg_catalog.pg_attribute a ON a.attrelid = t.oid
		  LEFT JOIN pg_catalog.pg_attrdef d ON d.adrelid = t.oid AND d.adnum = a.attnum
		 WHERE t.relname = ? AND pg_table_is_visible(t.oid) AND t.relkind IN ('r','p')
		   AND a.attnum > 0 AND NOT a.attisdropped ORDER BY a.attnum`, string(name)).Scan(ctx, &cols)
	if err != nil {
		return nil, nil, err
	}
	if len(cols) == 0 {
		return nil, nil, errors.NewNotFoundf(errors.CodeNotFound, "table %q not found", name)
	}
	table := &sqlschema.Table{Name: name}
	for _, c := range cols {
		table.Columns = append(table.Columns, &sqlschema.Column{Name: sqlschema.ColumnName(c.Name), DataType: p.fmter.DataTypeOf(c.Type), Nullable: c.Nullable, Default: c.DefaultSQL})
	}

	var keys []struct {
		Name         string
		Kind         string
		ColumnName   string
		TargetTable  string
		TargetColumn string
		KeySize      int
	}
	err = db.NewRaw(`
		SELECT c.conname AS name, c.contype::text AS kind, a.attname AS column_name,
		       coalesce(rt.relname,'') AS target_table, coalesce(ra.attname,'') AS target_column,
		       cardinality(c.conkey) AS key_size
		  FROM pg_catalog.pg_class t
		  JOIN pg_catalog.pg_constraint c ON c.conrelid = t.oid
		  CROSS JOIN LATERAL unnest(c.conkey) WITH ORDINALITY AS k(attnum, pos)
		  JOIN pg_catalog.pg_attribute a ON a.attrelid = t.oid AND a.attnum = k.attnum
		  LEFT JOIN pg_catalog.pg_class rt ON rt.oid = c.confrelid
		  LEFT JOIN pg_catalog.pg_attribute ra ON ra.attrelid = c.confrelid AND ra.attnum = c.confkey[k.pos]
		 WHERE t.relname = ? AND pg_table_is_visible(t.oid) AND c.contype IN ('p','u','f')
		 ORDER BY c.oid, k.pos`, string(name)).Scan(ctx, &keys)
	if err != nil {
		return nil, nil, err
	}
	var unique []*sqlschema.UniqueConstraint
	for _, k := range keys {
		col := sqlschema.ColumnName(k.ColumnName)
		switch k.Kind {
		case "p":
			if table.PrimaryKeyConstraint == nil {
				table.PrimaryKeyConstraint = (&sqlschema.PrimaryKeyConstraint{}).Named(k.Name).(*sqlschema.PrimaryKeyConstraint)
			}
			table.PrimaryKeyConstraint.ColumnNames = append(table.PrimaryKeyConstraint.ColumnNames, col)
		case "u":
			if len(unique) == 0 || unique[len(unique)-1].Name(name) != k.Name {
				u := (&sqlschema.UniqueConstraint{}).Named(k.Name).(*sqlschema.UniqueConstraint)
				unique = append(unique, u)
			}
			u := unique[len(unique)-1]
			u.ColumnNames = append(u.ColumnNames, col)
		case "f":
			if k.KeySize != 1 {
				return nil, nil, fmt.Errorf("composite foreign key %q on %q cannot be represented", k.Name, name)
			}
			fk := &sqlschema.ForeignKeyConstraint{ReferencingColumnName: col, ReferencedTableName: sqlschema.TableName(k.TargetTable), ReferencedColumnName: sqlschema.ColumnName(k.TargetColumn)}
			table.ForeignKeyConstraints = append(table.ForeignKeyConstraints, fk.Named(k.Name).(*sqlschema.ForeignKeyConstraint))
		}
	}
	return table, unique, nil
}

func (p *provider) GetIndices(ctx context.Context, table sqlschema.TableName) ([]sqlschema.Index, error) {
	var keys []struct {
		Name           string
		Position       int
		ColumnName     string
		Expression     string
		Predicate      string
		HasExpressions bool
	}
	err := p.store.BunDBCtx(ctx).NewRaw(`
		SELECT idx.relname AS name, pos AS position, coalesce(a.attname, '') AS column_name,
		       pg_get_indexdef(i.indexrelid, pos, true) AS expression,
		       coalesce(pg_get_expr(i.indpred, i.indrelid), '') AS predicate, i.indexprs IS NOT NULL AS has_expressions
		  FROM pg_catalog.pg_class t
		  JOIN pg_catalog.pg_index i ON i.indrelid = t.oid
		  JOIN pg_catalog.pg_class idx ON idx.oid = i.indexrelid
		  CROSS JOIN LATERAL generate_series(1, i.indnkeyatts) AS pos
		  LEFT JOIN pg_catalog.pg_attribute a ON a.attrelid = t.oid AND a.attnum = i.indkey[pos-1]
		 WHERE t.relname = ? AND pg_table_is_visible(t.oid) AND i.indisunique AND i.indisvalid
		   AND NOT EXISTS (SELECT 1 FROM pg_catalog.pg_constraint c WHERE c.conindid = idx.oid AND c.conrelid = t.oid AND c.contype IN ('p','u','x'))
		 ORDER BY i.indexrelid, pos`, string(table)).Scan(ctx, &keys)
	if err != nil {
		return nil, err
	}
	var indices []sqlschema.Index
	for start := 0; start < len(keys); {
		first := keys[start]
		var columns []sqlschema.ColumnName
		var expressions []string
		for start < len(keys) && keys[start].Name == first.Name {
			columns = append(columns, sqlschema.ColumnName(keys[start].ColumnName))
			expressions = append(expressions, keys[start].Expression)
			start++
		}
		var idx sqlschema.Index
		switch {
		case first.HasExpressions && first.Predicate != "":
			// The shared migration model does not own partial functional indexes.
			continue
		case first.HasExpressions:
			idx = &sqlschema.UniqueIndexWithExpressions{TableName: table, Expressions: expressions}
		case first.Predicate != "":
			idx = &sqlschema.PartialUniqueIndex{TableName: table, ColumnNames: columns, Where: first.Predicate}
		default:
			idx = &sqlschema.UniqueIndex{TableName: table, ColumnNames: columns}
		}
		if idx.Name() != first.Name {
			idx = idx.Named(first.Name)
		}
		indices = append(indices, idx)
	}
	return indices, nil
}
