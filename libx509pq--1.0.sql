-- complain if script is sourced in psql, rather than via CREATE EXTENSION
\echo Use "CREATE EXTENSION libx509pq" to load this file. \quit

CREATE OR REPLACE FUNCTION x509_issuerName(bytea,integer DEFAULT NULL) RETURNS text
	AS 'MODULE_PATHNAME' LANGUAGE c IMMUTABLE;

CREATE OR REPLACE FUNCTION x509_keyAlgorithm(bytea) RETURNS text
	AS 'MODULE_PATHNAME' LANGUAGE c IMMUTABLE;

CREATE OR REPLACE FUNCTION x509_keySize(bytea) RETURNS integer
	AS 'MODULE_PATHNAME' LANGUAGE c IMMUTABLE;

CREATE OR REPLACE FUNCTION x509_notAfter(bytea) RETURNS timestamp
	AS 'MODULE_PATHNAME' LANGUAGE c IMMUTABLE;

CREATE OR REPLACE FUNCTION x509_notBefore(bytea) RETURNS timestamp
	AS 'MODULE_PATHNAME' LANGUAGE c IMMUTABLE;

CREATE OR REPLACE FUNCTION x509_publicKeyMD5(bytea) RETURNS bytea
	AS 'MODULE_PATHNAME' LANGUAGE c IMMUTABLE;

CREATE OR REPLACE FUNCTION x509_publicKey(bytea) RETURNS bytea
	AS 'MODULE_PATHNAME' LANGUAGE c IMMUTABLE;

CREATE OR REPLACE FUNCTION x509_rsaModulus(bytea) RETURNS bytea
	AS 'MODULE_PATHNAME' LANGUAGE c IMMUTABLE;

CREATE OR REPLACE FUNCTION x509_serialNumber(bytea) RETURNS bytea
	AS 'MODULE_PATHNAME' LANGUAGE c IMMUTABLE;

CREATE OR REPLACE FUNCTION x509_signatureHashAlgorithm(bytea) RETURNS text
	AS 'MODULE_PATHNAME' LANGUAGE c IMMUTABLE;

CREATE OR REPLACE FUNCTION x509_signatureKeyAlgorithm(bytea) RETURNS text
	AS 'MODULE_PATHNAME' LANGUAGE c IMMUTABLE;

CREATE OR REPLACE FUNCTION x509_subjectName(bytea,integer DEFAULT NULL) RETURNS text
	AS 'MODULE_PATHNAME' LANGUAGE c IMMUTABLE;

CREATE OR REPLACE FUNCTION x509_name(bytea,boolean DEFAULT TRUE) RETURNS bytea
	AS 'MODULE_PATHNAME' LANGUAGE c IMMUTABLE;

CREATE OR REPLACE FUNCTION x509_name_print(bytea,integer DEFAULT NULL) RETURNS text
	AS 'MODULE_PATHNAME' LANGUAGE c IMMUTABLE;

CREATE OR REPLACE FUNCTION x509_commonName(bytea) RETURNS text
	AS 'MODULE_PATHNAME' LANGUAGE c IMMUTABLE;

CREATE OR REPLACE FUNCTION x509_subjectKeyIdentifier(bytea) RETURNS bytea
	AS 'MODULE_PATHNAME' LANGUAGE c IMMUTABLE;

CREATE OR REPLACE FUNCTION x509_authorityKeyId(bytea) RETURNS bytea
	AS 'MODULE_PATHNAME' LANGUAGE c IMMUTABLE;

CREATE OR REPLACE FUNCTION x509_extKeyUsages(bytea,boolean DEFAULT TRUE) RETURNS SETOF text
	AS 'MODULE_PATHNAME' LANGUAGE c IMMUTABLE;

CREATE OR REPLACE FUNCTION x509_isEKUPermitted(bytea,text) RETURNS boolean
	AS 'MODULE_PATHNAME' LANGUAGE c IMMUTABLE;

CREATE OR REPLACE FUNCTION x509_certPolicies(bytea) RETURNS SETOF text
	AS 'MODULE_PATHNAME' LANGUAGE c IMMUTABLE;

CREATE OR REPLACE FUNCTION x509_isPolicyPermitted(bytea,text) RETURNS boolean
	AS 'MODULE_PATHNAME' LANGUAGE c IMMUTABLE;

CREATE OR REPLACE FUNCTION x509_canIssueCerts(bytea) RETURNS boolean
	AS 'MODULE_PATHNAME' LANGUAGE c IMMUTABLE;

CREATE OR REPLACE FUNCTION x509_getPathLenConstraint(bytea) RETURNS integer
	AS 'MODULE_PATHNAME' LANGUAGE c IMMUTABLE;

CREATE OR REPLACE FUNCTION x509_nameAttributes(bytea,text,boolean,boolean DEFAULT TRUE) RETURNS SETOF text
	AS 'MODULE_PATHNAME' LANGUAGE c IMMUTABLE;

CREATE TYPE name_raw_type AS (
	ATTRIBUTE_OID		text,
	RAW_VALUE		bytea
);

CREATE OR REPLACE FUNCTION x509_nameAttributes_raw(bytea,boolean DEFAULT TRUE) RETURNS SETOF name_raw_type
	AS 'MODULE_PATHNAME' LANGUAGE c IMMUTABLE;

CREATE OR REPLACE FUNCTION x509_altNames(bytea,integer DEFAULT NULL,boolean DEFAULT TRUE,boolean DEFAULT TRUE) RETURNS SETOF text
	AS 'MODULE_PATHNAME' LANGUAGE c IMMUTABLE;

CREATE TYPE altname_raw_type AS (
	TYPE_NUM		integer,
	RAW_VALUE		bytea,
	OTHER_NAME_OID	text
);

CREATE OR REPLACE FUNCTION x509_altNames_raw(bytea,boolean DEFAULT TRUE) RETURNS SETOF altname_raw_type
	AS 'MODULE_PATHNAME' LANGUAGE c IMMUTABLE;

CREATE OR REPLACE FUNCTION x509_cRLDistributionPoints(bytea) RETURNS SETOF text
	AS 'MODULE_PATHNAME' LANGUAGE c IMMUTABLE;

CREATE OR REPLACE FUNCTION x509_authorityInfoAccess(bytea,integer DEFAULT NULL) RETURNS SETOF text
	AS 'MODULE_PATHNAME' LANGUAGE c IMMUTABLE;

CREATE OR REPLACE FUNCTION x509_print(bytea,integer DEFAULT NULL,integer DEFAULT NULL) RETURNS text
	AS 'MODULE_PATHNAME' LANGUAGE c IMMUTABLE;

CREATE OR REPLACE FUNCTION x509_verify(bytea,bytea) RETURNS boolean
	AS 'MODULE_PATHNAME' LANGUAGE c IMMUTABLE;

CREATE OR REPLACE FUNCTION x509_anyNamesWithNULs(bytea) RETURNS boolean
	AS 'MODULE_PATHNAME' LANGUAGE c IMMUTABLE;

CREATE OR REPLACE FUNCTION x509_extensions(bytea,boolean DEFAULT TRUE) RETURNS SETOF text
	AS 'MODULE_PATHNAME' LANGUAGE c IMMUTABLE;

CREATE OR REPLACE FUNCTION x509_hasExtension(bytea,text,boolean DEFAULT NULL) RETURNS boolean
	AS 'MODULE_PATHNAME' LANGUAGE c IMMUTABLE;

CREATE OR REPLACE FUNCTION x509_tbscert_strip_ct_ext(bytea) RETURNS bytea
	AS 'MODULE_PATHNAME' LANGUAGE c IMMUTABLE;

CREATE OR REPLACE FUNCTION x509_hasROCAFingerprint(bytea) RETURNS boolean
	AS 'MODULE_PATHNAME' LANGUAGE c IMMUTABLE;

CREATE OR REPLACE FUNCTION x509_hasClosePrimes(bytea,smallint DEFAULT 100) RETURNS boolean
	AS 'MODULE_PATHNAME' LANGUAGE c IMMUTABLE;

CREATE OR REPLACE FUNCTION urlEncode(text) RETURNS text
	AS 'MODULE_PATHNAME' LANGUAGE C IMMUTABLE STRICT;

CREATE OR REPLACE FUNCTION urlDecode(text) RETURNS text
	AS 'MODULE_PATHNAME' LANGUAGE C IMMUTABLE STRICT;

CREATE OR REPLACE FUNCTION x509pq_opensslVersion() RETURNS text
	AS 'MODULE_PATHNAME' LANGUAGE C IMMUTABLE;
