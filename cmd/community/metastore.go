package main

import (
	"github.com/SigNoz/signoz/pkg/authz"
	"github.com/SigNoz/signoz/pkg/authz/openfgaserver"
	"github.com/SigNoz/signoz/pkg/factory"
	"github.com/SigNoz/signoz/pkg/signoz"
	"github.com/SigNoz/signoz/pkg/sqlschema"
	schemapg "github.com/SigNoz/signoz/pkg/sqlschema/communitypostgres"
	"github.com/SigNoz/signoz/pkg/sqlstore"
	storagepg "github.com/SigNoz/signoz/pkg/sqlstore/communitypostgres"
	"github.com/SigNoz/signoz/pkg/sqlstore/sqlstorehook"
	"github.com/openfga/openfga/pkg/storage"
	fgapg "github.com/openfga/openfga/pkg/storage/postgres"
	"github.com/openfga/openfga/pkg/storage/sqlcommon"
)

func sqlstoreProviderFactories() factory.NamedMap[factory.ProviderFactory[sqlstore.SQLStore, sqlstore.Config]] {
	factories := signoz.NewSQLStoreProviderFactories()
	return factory.MustNewNamedMap(append(factories.GetInOrder(), storagepg.NewFactory(sqlstorehook.NewLoggingFactory(), sqlstorehook.NewInstrumentationFactory()))...)
}

func sqlschemaProviderFactories(sqlstore sqlstore.SQLStore) factory.NamedMap[factory.ProviderFactory[sqlschema.SQLSchema, sqlschema.Config]] {
	factories := signoz.NewSQLSchemaProviderFactories(sqlstore)
	return factory.MustNewNamedMap(append(factories.GetInOrder(), schemapg.NewFactory(sqlstore))...)
}

func accessDatastore(store sqlstore.SQLStore, cfg authz.Config) (storage.OpenFGADatastore, error) {
	if pg, ok := store.(*storagepg.Store); ok {
		opts := sqlcommon.NewConfig()
		opts.MaxTypesPerModelField = 100
		opts.MaxTuplesPerWriteField = cfg.OpenFGA.MaxTuplesPerWrite
		return fgapg.NewWithDB(pg.Pool(), nil, opts)
	}
	return openfgaserver.NewSQLStore(store, cfg)
}
