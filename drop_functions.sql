DROP FUNCTION x509_issuerName(bytea,integer);

DROP FUNCTION x509_keyAlgorithm(bytea);

DROP FUNCTION x509_keySize(bytea);

DROP FUNCTION x509_notAfter(bytea);

DROP FUNCTION x509_notBefore(bytea);

DROP FUNCTION x509_publicKeyMD5(bytea);

DROP FUNCTION x509_publicKey(bytea);

DROP FUNCTION x509_serialNumber(bytea);

DROP FUNCTION x509_signatureHashAlgorithm(bytea);

DROP FUNCTION x509_signatureKeyAlgorithm(bytea);

DROP FUNCTION x509_subjectName(bytea,integer);

DROP FUNCTION x509_name(bytea,boolean);

DROP FUNCTION x509_commonName(bytea);

DROP FUNCTION x509_extKeyUsages(bytea);

DROP FUNCTION x509_isEKUPermitted(bytea,text);

DROP FUNCTION x509_certPolicies(bytea);

DROP FUNCTION x509_isPolicyPermitted(bytea,text);

DROP FUNCTION x509_canIssueCerts(bytea);

DROP FUNCTION x509_getPathLenConstraint(bytea);

DROP FUNCTION x509_nameAttributes(bytea,text,boolean);

DROP FUNCTION x509_altNames(bytea,integer,boolean);

DROP FUNCTION x509_cRLDistributionPoints(bytea);

DROP FUNCTION x509_authorityInfoAccess(bytea,integer);

DROP FUNCTION x509_print(bytea,integer,integer);

DROP FUNCTION x509_verify(bytea,bytea);

DROP FUNCTION urlEncode(text);

DROP FUNCTION urlDecode(text);

DROP FUNCTION x509pq_opensslVersion();
