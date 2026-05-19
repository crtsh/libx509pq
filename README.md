# libx509pq

A PostgreSQL extension that exposes [OpenSSL](https://www.openssl.org/)'s X.509
certificate parser as a set of SQL functions. Pass in a DER-encoded
certificate as `bytea` and get back issuer/subject names, validity dates, key
material, extensions, fingerprints, and more — without leaving the database.

This is the parsing engine that powers [crt.sh](https://crt.sh/), Sectigo's
public Certificate Transparency log search.

## Requirements

- PostgreSQL 12 or later (developed and tested against PG 18)
- OpenSSL 1.1.1 or later (3.x supported)
- A C toolchain plus the PostgreSQL server headers
  (`postgresql-server-dev-<n>` on Debian/Ubuntu, `postgresql<n>-devel` on
  RHEL/Fedora)

## Build & install

```sh
make
sudo make install
```

The build uses [PGXS](https://www.postgresql.org/docs/current/extend-pgxs.html);
point it at a non-default cluster with `PG_CONFIG`:

```sh
make PG_CONFIG=/path/to/pg_config
sudo make install PG_CONFIG=/path/to/pg_config
```

Then, in a database:

```sql
CREATE EXTENSION libx509pq;
```

Upgrading from an older install:

```sql
ALTER EXTENSION libx509pq UPDATE;
```

## Quick start

```sql
CREATE EXTENSION libx509pq;

-- Load a DER-encoded certificate (e.g. produced by
--   openssl x509 -in cert.pem -outform der | xxd -p | tr -d '\n'
-- and pasted as a hex literal):
WITH c(der) AS (VALUES (decode('3082...', 'hex')))
SELECT x509_commonName(der)                  AS cn,
       x509_issuerName(der)                  AS issuer,
       x509_notBefore(der)                   AS not_before,
       x509_notAfter(der)                    AS not_after,
       x509_keyAlgorithm(der)                AS key_alg,
       x509_keySize(der)                     AS key_bits,
       encode(x509_serialNumber(der), 'hex') AS serial_hex
FROM c;
```

See [test/sql/basic.sql](test/sql/basic.sql) for a runnable example using two
well-known root certificates.

## Function reference

All functions are `IMMUTABLE PARALLEL SAFE`. Functions that take only a
`bytea` argument are `STRICT` (NULL in → NULL out); functions that accept an
optional flags argument cannot be `STRICT` because they treat NULL as "use
the default flags".

When a function's job is to return text and the input cannot be parsed as a
certificate, it returns a short error sentinel (e.g. the string `(error)`)
rather than NULL — this matches the long-standing crt.sh behaviour. The pure
binary/numeric extractors (`x509_publicKey`, `x509_serialNumber`, the
timestamps, `x509_keySize`, etc.) return NULL on parse failure.

### Single-value certificate extractors

| Function | Returns | Notes |
| --- | --- | --- |
| `x509_commonName(bytea)` | `text` | First `CN` RDN in the subject, UTF-8 decoded. NULL if no `CN` is present. |
| `x509_subjectName(bytea, integer DEFAULT NULL)` | `text` | One-line Distinguished Name via `X509_NAME_print_ex`. Default flags are RFC 2253 with `ESC_QUOTE`, comma-space separators and short field names (`~ESC_MSB`). Pass any `XN_FLAG_*` bitmask to override. |
| `x509_issuerName(bytea, integer DEFAULT NULL)` | `text` | Same flag handling as `x509_subjectName`. |
| `x509_notBefore(bytea)` | `timestamp` | Parsed via `ASN1_TIME_parse`, returned as UTC. |
| `x509_notAfter(bytea)` | `timestamp` | As above. |
| `x509_serialNumber(bytea)` | `bytea` | DER `INTEGER` body with the tag+length stripped, i.e. the raw two's-complement big-endian bytes. |
| `x509_keyAlgorithm(bytea)` | `text` | One of `RSA`, `DSA`, `DH`, `EC`, `NONE`. |
| `x509_keySize(bytea)` | `integer` | `EVP_PKEY_bits`; `-1` on failure. |
| `x509_signatureHashAlgorithm(bytea)` | `text` | Looked up from the signature OID's hash component, e.g. `SHA-256`, `SHA-1`. |
| `x509_signatureKeyAlgorithm(bytea)` | `text` | Looked up from the signature OID's key component, e.g. `RSA`, `ECDSA`. |
| `x509_publicKey(bytea)` | `bytea` | DER-encoded `SubjectPublicKeyInfo` (i.e. the form `x509_verify` expects). |
| `x509_publicKeyMD5(bytea)` | `bytea` | MD5 of the raw `subjectPublicKey` BIT STRING contents. |
| `x509_rsaModulus(bytea)` | `bytea` | Big-endian RSA modulus. NULL for non-RSA keys. |
| `x509_subjectKeyIdentifier(bytea)` | `bytea` | NULL if the extension is absent. |
| `x509_authorityKeyId(bytea)` | `bytea` | The `keyIdentifier` field only; NULL if absent. |
| `x509_canIssueCerts(bytea)` | `boolean` | True iff the cert may sign other certs. Honours `BasicConstraints.cA`, then requires `keyCertSign` in `KeyUsage` (if present). Recognises the legacy `BasicConstraints` draft extension, treats self-signed v1/v2 certs as issuers, and special-cases the "Root SGC Authority" CA. |
| `x509_getPathLenConstraint(bytea)` | `integer` | Pathlen integer if specified; NULL if the cert is a CA without a `pathLenConstraint`; `-3` if `BasicConstraints.cA = FALSE`; `-4` if a v3 cert has no `BasicConstraints` extension. |
| `x509_anyNamesWithNULs(bytea)` | `boolean` | True if any subject/issuer RDN value or any `subjectAltName`/`issuerAltName` IA5 string contains an embedded NUL. |
| `x509_hasROCAFingerprint(bytea)` | `boolean` | RSA modulus matches the ROCA fingerprint set (CVE-2017-15361). NULL for non-RSA keys. |
| `x509_hasClosePrimes(bytea, smallint DEFAULT 100)` | `boolean` | True if Fermat's factorisation finds the RSA modulus's two primes within the given number of iterations. NULL for non-RSA keys. |
| `x509_verify(cert bytea, pubkey bytea)` | `boolean` | Verifies `cert`'s signature using the given DER `SubjectPublicKeyInfo`. |
| `x509_tbscert_strip_ct_ext(bytea)` | `bytea` | Re-encoded TBSCertificate with both the SCT list (`1.3.6.1.4.1.11129.2.4.2`) and the precertificate poison (`1.3.6.1.4.1.11129.2.4.3`) extensions removed — the form whose hash a CT log signs. |

### Single-parse composite helper

To avoid re-parsing the certificate once per field, `x509_basic_info()`
returns the cheap-to-extract fields as a single composite row:

```sql
SELECT (x509_basic_info(der)).*
FROM   certs
WHERE  id = $1;
```

The composite type:

```sql
x509_basic_info_type(
    issuer_name              text,
    subject_name             text,
    common_name              text,
    serial_number            bytea,
    not_before               timestamp,
    not_after                timestamp,
    key_algorithm            text,
    key_size                 integer,
    signature_hash_algorithm text,
    signature_key_algorithm  text,
    subject_key_identifier   bytea,
    authority_key_identifier bytea
)
```

### Set-returning extractors

Note: in the boolean arguments below that pick between numeric OID strings
and long names, **TRUE selects the numeric OID** (`OBJ_obj2txt(..., 1)`) and
FALSE selects the long name. The defaults are `TRUE`, so by default these
functions return dotted-decimal OIDs.

| Function | Returns | Notes |
| --- | --- | --- |
| `x509_extensions(bytea, boolean DEFAULT TRUE)` | `SETOF text` | Extension OIDs in declared order. Boolean: TRUE = numeric OID, FALSE = long name. |
| `x509_hasExtension(bytea, text, boolean DEFAULT NULL)` | `boolean` | Match by OID (short, long, or dotted-decimal). Optional `critical` argument: when non-NULL, also requires the matching extension's `critical` bit to equal it. |
| `x509_extKeyUsages(bytea, boolean DEFAULT TRUE)` | `SETOF text` | EKU OIDs. Same numeric-vs-long-name boolean as `x509_extensions`. |
| `x509_isEKUPermitted(bytea, text)` | `boolean` | True iff the cert has no EKU extension, or its EKU set contains the given OID (or `anyExtendedKeyUsage`). |
| `x509_certPolicies(bytea)` | `SETOF text` | Numeric OID of each certificate policy. |
| `x509_isPolicyPermitted(bytea, text)` | `boolean` | True iff the cert has no `certificatePolicies` extension, or its policy set contains the given OID (or `anyPolicy`). |
| `x509_altNames(bytea, integer DEFAULT NULL, boolean DEFAULT TRUE, boolean DEFAULT TRUE)` | `SETOF text` | GeneralNames from `subjectAltName` / `issuerAltName`. Args: (1) `GEN_*` type filter — `NULL` = all, otherwise one of `1`=email, `2`=DNS, `4`=dirName, `6`=URI, `7`=IP (any other value yields a single `Unsupported GeneralName` row); (2) TRUE = subjectAltName, FALSE = issuerAltName; (3) TRUE = print the name value, FALSE = emit only `otherName` type OIDs and skip the IA5/dirName/IP entries. |
| `x509_altNames_raw(bytea, boolean DEFAULT TRUE)` | `SETOF (type_num int, raw_value bytea, other_name_oid text)` | Boolean selects subject vs. issuer altName. Only emits `email`, `DNS`, `URI`, `IP` and `otherName` entries; `raw_value` is the UTF-8 decoded string for IA5 types or a printable form for IPs. |
| `x509_nameAttributes(bytea, text, boolean, boolean DEFAULT TRUE)` | `SETOF text` | RDN values from one name. Args: (1) attribute selector — short name, long name, or OID; pass `X509` to get all attributes; an unrecognised name yields a single `Unsupported Attribute` row; (2) TRUE = subject, FALSE = issuer; (3) TRUE = return the decoded UTF-8 value, FALSE = return the matching attribute's numeric OID. |
| `x509_nameAttributes_raw(bytea, boolean DEFAULT TRUE)` | `SETOF (attribute_oid text, raw_value bytea)` | All RDN attributes of subject (boolean TRUE) or issuer (FALSE). `attribute_oid` is the numeric OID; `raw_value` is the UTF-8 decoded value (not the raw DER, despite the name). |
| `x509_cRLDistributionPoints(bytea)` | `SETOF text` | URIs from each `DistributionPoint.fullName` GeneralName. |
| `x509_authorityInfoAccess(bytea, integer DEFAULT NULL)` | `SETOF text` | URIs from `AccessDescription` entries. Argument: `NULL` = all, `1` = OCSP, `2` = caIssuers. Only `URI`-typed access locations are emitted. |

### Name handling

| Function | Returns | Notes |
| --- | --- | --- |
| `x509_name(bytea, boolean DEFAULT TRUE)` | `bytea` | DER-encoded `Name`. Boolean: TRUE = subject (default), FALSE = issuer. |
| `x509_name_print(bytea, integer DEFAULT NULL)` | `text` | Pretty-prints a DER `Name` (the inverse of `x509_name`). Same default flag handling as `x509_subjectName`. |

### Pretty-printing and miscellaneous

| Function | Returns | Notes |
| --- | --- | --- |
| `x509_print(bytea, integer DEFAULT NULL, integer DEFAULT NULL)` | `text` | `X509_print_ex` output. Arg 2 is the `XN_FLAG_*`/`ASN1_STRFLGS_*` bitmask used to render the names (defaults match `openssl x509 -text -nameopt multiline`); arg 3 is the `X509_FLAG_*` bitmask that selects which sections to print (default 0 = everything). |
| `urlEncode(text)` | `text` | Helper used by crt.sh. Percent-encodes everything outside `A-Z a-z 0-9 - . _ ~ ! ' ( ) *`, encodes space as `+`. Stops at the first NUL byte. |
| `urlDecode(text)` | `text` | Inverse of `urlEncode` (decodes `+` as space and `%XX` escapes). |
| `x509pq_opensslVersion()` | `text` | The OpenSSL library version string this binary is linked against (`SSLeay_version(SSLEAY_VERSION)`). |

## Tests

A minimal pg_regress smoke test lives under `test/sql/` with expected output
in `test/expected/`. Run it against a running cluster with:

```sh
make installcheck
```

Note: pg_regress runs as the PostgreSQL OS user (typically `postgres`), so
the checkout must be in a directory that user can read and write. If your
repo is under `/home/<you>/...` (not traversable by `postgres`), copy the
tree to a shared location first, e.g.:

```sh
cp -r . /tmp/libx509pq && cd /tmp/libx509pq && sudo -u postgres make installcheck
```

## License

GNU GPL v3. See [LICENSE](LICENSE).
