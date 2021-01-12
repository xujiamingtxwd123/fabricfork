package statedb

type VersionedDBProvider interface {
	// GetDBHandle returns a handle to a VersionedDB
	GetDBHandle(id string, namespaceProvider NamespaceProvider) (VersionedDB, error)
	// Close closes all the VersionedDB instances and releases any resources held by VersionedDBProvider
	Close()
}

type NamespaceProvider interface {
	// PossibleNamespaces returns all possible namespaces for the statedb. Note that it is a superset
	// of the actual namespaces. Therefore, the caller should compare with the existing databases to
	// filter out the namespaces that have no matched databases.
	PossibleNamespaces(vdb VersionedDB) ([]string, error)
}

type VersionedDB interface {
}
