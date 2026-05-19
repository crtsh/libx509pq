# libx509pq
X.509 certificate parsing library for PostgreSQL

## Tests

A minimal pg_regress smoke test lives under `test/sql/` with expected output in
`test/expected/`. Run it against a running cluster with:

```sh
make installcheck
```

Note: pg_regress runs as the PostgreSQL OS user (typically `postgres`), so the
checkout must be in a directory that user can read and write. If your repo is
under `/home/<you>/...` (not traversable by `postgres`), copy the tree to a
shared location first, e.g.:

```sh
cp -r . /tmp/libx509pq && cd /tmp/libx509pq && sudo -u postgres make installcheck
```
