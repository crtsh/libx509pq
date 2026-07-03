-- Upgrade libx509pq from 1.2 to 1.3.
--
-- 1.3 is a build-system-only change: fix OPENSSL_HOME library linking
-- so the correct libcrypto soname is recorded.  No SQL API changes.

\echo Use "ALTER EXTENSION libx509pq UPDATE TO '1.3'" to load this file. \quit
