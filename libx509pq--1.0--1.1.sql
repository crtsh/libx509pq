-- Upgrade libx509pq from 1.0 to 1.1.
--
-- 1.1 only changes function attributes (adds PARALLEL SAFE everywhere, and
-- STRICT to every function whose arguments have no NULL-as-sentinel default).
-- No C ABI changes; the existing shared library continues to work.

\echo Use "ALTER EXTENSION libx509pq UPDATE TO '1.1'" to load this file. \quit

-- PARALLEL SAFE for every function (pure, no shared state, no SPI).

ALTER FUNCTION x509_issuerName(bytea, integer)              PARALLEL SAFE;
ALTER FUNCTION x509_keyAlgorithm(bytea)                     PARALLEL SAFE STRICT;
ALTER FUNCTION x509_keySize(bytea)                          PARALLEL SAFE STRICT;
ALTER FUNCTION x509_notAfter(bytea)                         PARALLEL SAFE STRICT;
ALTER FUNCTION x509_notBefore(bytea)                        PARALLEL SAFE STRICT;
ALTER FUNCTION x509_publicKeyMD5(bytea)                     PARALLEL SAFE STRICT;
ALTER FUNCTION x509_publicKey(bytea)                        PARALLEL SAFE STRICT;
ALTER FUNCTION x509_rsaModulus(bytea)                       PARALLEL SAFE STRICT;
ALTER FUNCTION x509_serialNumber(bytea)                     PARALLEL SAFE STRICT;
ALTER FUNCTION x509_signatureHashAlgorithm(bytea)           PARALLEL SAFE STRICT;
ALTER FUNCTION x509_signatureKeyAlgorithm(bytea)            PARALLEL SAFE STRICT;
ALTER FUNCTION x509_subjectName(bytea, integer)             PARALLEL SAFE;
ALTER FUNCTION x509_name(bytea, boolean)                    PARALLEL SAFE STRICT;
ALTER FUNCTION x509_name_print(bytea, integer)              PARALLEL SAFE;
ALTER FUNCTION x509_commonName(bytea)                       PARALLEL SAFE STRICT;
ALTER FUNCTION x509_subjectKeyIdentifier(bytea)             PARALLEL SAFE STRICT;
ALTER FUNCTION x509_authorityKeyId(bytea)                   PARALLEL SAFE STRICT;
ALTER FUNCTION x509_extKeyUsages(bytea, boolean)            PARALLEL SAFE STRICT;
ALTER FUNCTION x509_isEKUPermitted(bytea, text)             PARALLEL SAFE STRICT;
ALTER FUNCTION x509_certPolicies(bytea)                     PARALLEL SAFE STRICT;
ALTER FUNCTION x509_isPolicyPermitted(bytea, text)          PARALLEL SAFE STRICT;
ALTER FUNCTION x509_canIssueCerts(bytea)                    PARALLEL SAFE STRICT;
ALTER FUNCTION x509_getPathLenConstraint(bytea)             PARALLEL SAFE STRICT;
ALTER FUNCTION x509_nameAttributes(bytea, text, boolean, boolean)
                                                            PARALLEL SAFE STRICT;
ALTER FUNCTION x509_nameAttributes_raw(bytea, boolean)      PARALLEL SAFE STRICT;
ALTER FUNCTION x509_altNames(bytea, integer, boolean, boolean)
                                                            PARALLEL SAFE;
ALTER FUNCTION x509_altNames_raw(bytea, boolean)            PARALLEL SAFE STRICT;
ALTER FUNCTION x509_cRLDistributionPoints(bytea)            PARALLEL SAFE STRICT;
ALTER FUNCTION x509_authorityInfoAccess(bytea, integer)     PARALLEL SAFE;
ALTER FUNCTION x509_print(bytea, integer, integer)          PARALLEL SAFE;
ALTER FUNCTION x509_verify(bytea, bytea)                    PARALLEL SAFE STRICT;
ALTER FUNCTION x509_anyNamesWithNULs(bytea)                 PARALLEL SAFE STRICT;
ALTER FUNCTION x509_extensions(bytea, boolean)              PARALLEL SAFE STRICT;
ALTER FUNCTION x509_hasExtension(bytea, text, boolean)      PARALLEL SAFE;
ALTER FUNCTION x509_tbscert_strip_ct_ext(bytea)             PARALLEL SAFE STRICT;
ALTER FUNCTION x509_hasROCAFingerprint(bytea)               PARALLEL SAFE STRICT;
ALTER FUNCTION x509_hasClosePrimes(bytea, smallint)         PARALLEL SAFE STRICT;
ALTER FUNCTION urlEncode(text)                              PARALLEL SAFE;
ALTER FUNCTION urlDecode(text)                              PARALLEL SAFE;
ALTER FUNCTION x509pq_opensslVersion()                      PARALLEL SAFE;
