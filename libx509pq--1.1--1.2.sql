-- Upgrade libx509pq from 1.1 to 1.2.
--
-- 1.2 is a C-only change: OpenSSL 4.0 compatibility (opaque ASN1_STRING
-- types, ENGINE API removal, const-correctness).  No SQL API changes.

\echo Use "ALTER EXTENSION libx509pq UPDATE TO '1.2'" to load this file. \quit
