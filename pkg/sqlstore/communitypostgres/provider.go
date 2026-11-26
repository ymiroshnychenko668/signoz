// Package communitypostgres implements the Community metastore contract using pgx and Bun.
package communitypostgres

import (
	"context"
	"database/sql"
	"math"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/uptrace/bun"
	"github.com/uptrace/bun/dialect/pgdialect"

	"github.com/SigNoz/signoz/pkg/errors"
	"github.com/SigNoz/signoz/pkg/factory"
	"github.com/SigNoz/signoz/pkg/sqlstore"
)

type Store struct {
	db   *sqlstore.BunDB
	pool *pgxpool.Pool
	fmt  formatter
}

func NewFactory(factories ...factory.ProviderFactory[sqlstore.SQLStoreHook, sqlstore.Config]) factory.ProviderFactory[sqlstore.SQLStore, sqlstore.Config] {
	return factory.NewProviderFactory(factory.MustNewName("postgres"), func(ctx context.Context, ps factory.ProviderSettings, cfg sqlstore.Config) (sqlstore.SQLStore, error) {
		hooks := make([]sqlstore.SQLStoreHook, 0, len(factories))
		for _, f := range factories {
			h, err := f.New(ctx, ps, cfg)
			if err != nil {
				return nil, err
			}
			hooks = append(hooks, h)
		}
		opts, err := pgxpool.ParseConfig(cfg.Postgres.DSN)
		if err != nil || cfg.Postgres.DSN == "" {
			return nil, errors.New(errors.TypeInvalidInput, errors.CodeInvalidInput, "invalid postgres connection configuration")
		}
		if cfg.Connection.MaxOpenConns > 0 && cfg.Connection.MaxOpenConns <= math.MaxInt32 {
			opts.MaxConns = int32(cfg.Connection.MaxOpenConns)
		}
		opts.MaxConnLifetime = cfg.Connection.MaxConnLifetime
		pool, err := pgxpool.NewWithConfig(ctx, opts)
		if err != nil {
			return nil, errors.New(errors.TypeInternal, errors.CodeInternal, "could not initialize postgres pool")
		}
		if err = pool.Ping(ctx); err != nil {
			pool.Close()
			return nil, errors.New(errors.TypeInternal, errors.CodeInternal, "could not connect to postgres")
		}
		settings := factory.NewScopedProviderSettings(ps, "github.com/SigNoz/signoz/pkg/sqlstore/communitypostgres")
		db := sqlstore.NewBunDB(settings, stdlib.OpenDBFromPool(pool), pgdialect.New(), hooks)
		return &Store{db: db, pool: pool, fmt: formatter{db.Formatter()}}, nil
	})
}

func (s *Store) Pool() *pgxpool.Pool                  { return s.pool }
func (s *Store) BunDB() *bun.DB                       { return s.db.DB }
func (s *Store) SQLDB() *sql.DB                       { return s.db.DB.DB }
func (s *Store) BunDBCtx(ctx context.Context) bun.IDB { return s.db.BunDBCtx(ctx) }
func (s *Store) RunInTxCtx(ctx context.Context, o *sql.TxOptions, cb func(context.Context) error) error {
	return s.db.RunInTxCtx(ctx, o, cb)
}
func (s *Store) Dialect() sqlstore.SQLDialect     { return dialect{} }
func (s *Store) Formatter() sqlstore.SQLFormatter { return s.fmt }
func (s *Store) WrapNotFoundErrf(err error, code errors.Code, format string, args ...any) error {
	if errors.Is(err, sql.ErrNoRows) {
		return errors.Wrapf(err, errors.TypeNotFound, code, format, args...)
	}
	return err
}
func (s *Store) WrapAlreadyExistsErrf(err error, code errors.Code, format string, args ...any) error {
	var pgerr *pgconn.PgError
	if errors.As(err, &pgerr) && pgerr.Code == "23505" {
		return errors.Wrapf(err, errors.TypeAlreadyExists, code, format, args...)
	}
	return err
}
