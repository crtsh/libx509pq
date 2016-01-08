CREATE OR REPLACE FUNCTION x509_issuerName(bytea,integer DEFAULT NULL) RETURNS text
	AS '$libdir/libx509pq.so' LANGUAGE c IMMUTABLE;

CREATE OR REPLACE FUNCTION x509_keyAlgorithm(bytea) RETURNS text
	AS '$libdir/libx509pq.so' LANGUAGE c IMMUTABLE;

CREATE OR REPLACE FUNCTION x509_keySize(bytea) RETURNS integer
	AS '$libdir/libx509pq.so' LANGUAGE c IMMUTABLE;

CREATE OR REPLACE FUNCTION x509_notAfter(bytea) RETURNS timestamp
	AS '$libdir/libx509pq.so' LANGUAGE c IMMUTABLE;

CREATE OR REPLACE FUNCTION x509_notBefore(bytea) RETURNS timestamp
	AS '$libdir/libx509pq.so' LANGUAGE c IMMUTABLE;

CREATE OR REPLACE FUNCTION x509_publicKeyMD5(bytea) RETURNS bytea
	AS '$libdir/libx509pq.so' LANGUAGE c IMMUTABLE;

CREATE OR REPLACE FUNCTION x509_publicKey(bytea) RETURNS bytea
	AS '$libdir/libx509pq.so' LANGUAGE c IMMUTABLE;

CREATE OR REPLACE FUNCTION x509_serialNumber(bytea) RETURNS bytea
	AS '$libdir/libx509pq.so' LANGUAGE c IMMUTABLE;

CREATE OR REPLACE FUNCTION x509_signatureHashAlgorithm(bytea) RETURNS text
	AS '$libdir/libx509pq.so' LANGUAGE c IMMUTABLE;

CREATE OR REPLACE FUNCTION x509_signatureKeyAlgorithm(bytea) RETURNS text
	AS '$libdir/libx509pq.so' LANGUAGE c IMMUTABLE;

CREATE OR REPLACE FUNCTION x509_subjectName(bytea,integer DEFAULT NULL) RETURNS text
	AS '$libdir/libx509pq.so' LANGUAGE c IMMUTABLE;

CREATE OR REPLACE FUNCTION x509_name(bytea,boolean DEFAULT TRUE) RETURNS bytea
	AS '$libdir/libx509pq.so' LANGUAGE c IMMUTABLE;

CREATE OR REPLACE FUNCTION x509_commonName(bytea) RETURNS text
	AS '$libdir/libx509pq.so' LANGUAGE c IMMUTABLE;

CREATE OR REPLACE FUNCTION x509_extKeyUsages(bytea) RETURNS SETOF text
	AS '$libdir/libx509pq.so' LANGUAGE c IMMUTABLE;

CREATE OR REPLACE FUNCTION x509_isEKUPermitted(bytea,text) RETURNS boolean
	AS '$libdir/libx509pq.so' LANGUAGE c IMMUTABLE;

CREATE OR REPLACE FUNCTION x509_certPolicies(bytea) RETURNS SETOF text
	AS '$libdir/libx509pq.so' LANGUAGE c IMMUTABLE;

CREATE OR REPLACE FUNCTION x509_isPolicyPermitted(bytea,text) RETURNS boolean
	AS '$libdir/libx509pq.so' LANGUAGE c IMMUTABLE;

CREATE OR REPLACE FUNCTION x509_canIssueCerts(bytea) RETURNS boolean
	AS '$libdir/libx509pq.so' LANGUAGE c IMMUTABLE;

CREATE OR REPLACE FUNCTION x509_getPathLenConstraint(bytea) RETURNS integer
	AS '$libdir/libx509pq.so' LANGUAGE c IMMUTABLE;

CREATE OR REPLACE FUNCTION x509_nameAttributes(bytea,text,boolean) RETURNS SETOF text
	AS '$libdir/libx509pq.so' LANGUAGE c IMMUTABLE;

CREATE OR REPLACE FUNCTION x509_altNames(bytea,integer DEFAULT NULL,boolean DEFAULT TRUE) RETURNS SETOF text
	AS '$libdir/libx509pq.so' LANGUAGE c IMMUTABLE;

CREATE OR REPLACE FUNCTION x509_cRLDistributionPoints(bytea) RETURNS SETOF text
	AS '$libdir/libx509pq.so' LANGUAGE c IMMUTABLE;

CREATE OR REPLACE FUNCTION x509_authorityInfoAccess(bytea,integer DEFAULT NULL) RETURNS SETOF text
	AS '$libdir/libx509pq.so' LANGUAGE c IMMUTABLE;

CREATE OR REPLACE FUNCTION x509_print(bytea,integer DEFAULT NULL,integer DEFAULT NULL) RETURNS text
	AS '$libdir/libx509pq.so' LANGUAGE c IMMUTABLE;

CREATE OR REPLACE FUNCTION x509_verify(bytea,bytea) RETURNS boolean
	AS '$libdir/libx509pq.so' LANGUAGE c IMMUTABLE;

CREATE OR REPLACE FUNCTION urlEncode(text) RETURNS text
	AS '$libdir/libx509pq.so' LANGUAGE C IMMUTABLE STRICT;

CREATE OR REPLACE FUNCTION urlDecode(text) RETURNS text
	AS '$libdir/libx509pq.so' LANGUAGE C IMMUTABLE STRICT;

CREATE OR REPLACE FUNCTION x509pq_opensslVersion() RETURNS text
	AS '$libdir/libx509pq.so' LANGUAGE C IMMUTABLE;
