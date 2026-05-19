-- Basic smoke tests for libx509pq using two well-known root certificates.
--
-- Fixtures (DER-encoded, hex):
--   * ISRG Root X1                (RSA 4096, /etc/ssl/certs/ISRG_Root_X1.pem)
--   * DigiCert Global Root CA     (RSA 2048, /etc/ssl/certs/DigiCert_Global_Root_CA.pem)
--
-- Regenerate the hex blobs with:
--   openssl x509 -in <cert.pem> -outform der | xxd -p | tr -d '\n'

CREATE EXTENSION IF NOT EXISTS libx509pq;

CREATE TEMP TABLE certs (name text PRIMARY KEY, der bytea);

INSERT INTO certs VALUES ('isrg_root_x1', decode(
    '3082056b30820353a0030201020211008210cfb0d240e3594463e0bb63828b00300d06092a864886'
||  'f70d01010b0500304f310b300906035504061302555331293027060355040a1320496e7465726e65'
||  '742053656375726974792052657365617263682047726f7570311530130603550403130c49535247'
||  '20526f6f74205831301e170d3135303630343131303433385a170d3335303630343131303433385a'
||  '304f310b300906035504061302555331293027060355040a1320496e7465726e6574205365637572'
||  '6974792052657365617263682047726f7570311530130603550403130c4953524720526f6f742058'
||  '3130820222300d06092a864886f70d01010105000382020f003082020a0282020100ade82473f414'
||  '37f39b9e2b57281c87bedcb7df38908c6e3ce657a078f775c2a2fef56a6ef6004f28dbde68866c44'
||  '93b6b163fd14126bbf1fd2ea319b217ed1333cba48f5dd79dfb3b8ff12f1219a4bc18a8671694a66'
||  '666c8f7e3c70bfad292206f3e4c0e680aee24b8fb7997e94039fd347977c99482353e838ae4f0a6f'
||  '832ed149578c8074b6da2fd0388d7b0370211b75f2303cfa8faeddda63abeb164fc28e114b7ecf0b'
||  'e8ffb5772ef4b27b4ae04c12250c708d0329a0e15324ec13d9ee19bf10b34a8c3f89a36151deac87'
||  '0794f46371ec2ee26f5b9881e1895c34796c76ef3b906279e6dba49a2f26c5d010e10eded9108e16'
||  'fbb7f7a8f7c7e50207988f360895e7e237960d36759efb0e72b11d9bbc03f94905d881dd05b42ad6'
||  '41e9ac0176950a0fd8dfd5bd121f352f28176cd298c1a80964776e4737baceac595e689d7f72d689'
||  'c50641293e593edd26f524c911a75aa34c401f46a199b5a73a516e863b9e7d72a712057859ed3e51'
||  '78150b038f8dd02f05b23e7b4a1c4b730512fcc6eae050137c439374b3ca74e78e1f0108d030d45b'
||  '7136b407bac130305c48b7823b98a67d608aa2a32982ccbabd83041ba2830341a1d605f11bc2b6f0'
||  'a87c863b46a8482a88dc769a76bf1f6aa53d198feb38f364dec82b0d0a28fff7dbe21542d422d027'
||  '5de179fe18e77088ad4ee6d98b3ac6dd27516effbc64f533434f0203010001a3423040300e060355'
||  '1d0f0101ff040403020106300f0603551d130101ff040530030101ff301d0603551d0e0416041479'
||  'b459e67bb6e5e40173800888c81a58f6e99b6e300d06092a864886f70d01010b0500038202010055'
||  '1f58a9bcb2a850d00cb1d81a6920272908ac61755c8a6ef882e5692fd5f6564bb9b8731059d32197'
||  '7ee74c71fbb2d260ad39a80bea17215685f1500e59ebcee059e9bac915ef869d8f8480f6e4e99190'
||  'dc179b621b45f06695d27c6fc2ea3bef1fcfcbd6ae27f1a9b0c8aefd7d7e9afa2204ebffd97fea91'
||  '2b22b1170e8ff28a345b58d8fc01c954b9b826cc8a8833894c2d843c82dfee965705ba2cbbf7c4b7'
||  'c74e3b82be31c822737392d1c280a43939103323824c3c9f86b255981dbe29868c229b9ee26b3b57'
||  '3a82704ddc09c789cb0a074d6ce85d8ec9efceabc7bbb52b4e45d64ad026cce572ca086aa595e315'
||  'a1f7a4edc92c5fa5fbffac28022ebed77bbbe3717b9016d3075e46537c3707428cd3c4969cd599b5'
||  '2ae0951a8048ae4c3907cecc47a452952bbab8fbadd233537de51d4d6dd5a1b1c7426fe64027355c'
||  'a328b7078de78d3390e7239ffb509c796c46d5b415b3966e7e9b0c963ab8522d3fd65be1fb08c284'
||  'fe24a8a389daac6ae1182ab1a843615bd31fdc3b8d76f22de88d75df17336c3d53fb7bcb415fffdc'
||  'a2d06138e196b8ac5d8b37d775d533c09911ae9d41c1727584be0241425f67244894d19b27be073f'
||  'b9b84f817451e17ab7ed9d23e2bee0d52804133c31039edd7a6c8fc60718c67fde478e3f289e0406'
||  'cfa5543477bdec899be91743df5bdb5ffe8e1e57a2cd409d7e6222dade1827',
    'hex'));

INSERT INTO certs VALUES ('digicert_global_root_ca', decode(
    '308203af30820297a0030201020210083be056904246b1a1756ac95991c74a300d06092a864886f7'
||  '0d01010505003061310b300906035504061302555331153013060355040a130c4469676943657274'
||  '20496e6331193017060355040b13107777772e64696769636572742e636f6d3120301e0603550403'
||  '1317446967694365727420476c6f62616c20526f6f74204341301e170d3036313131303030303030'
||  '305a170d3331313131303030303030305a3061310b30090603550406130255533115301306035504'
||  '0a130c446967694365727420496e6331193017060355040b13107777772e64696769636572742e63'
||  '6f6d3120301e06035504031317446967694365727420476c6f62616c20526f6f7420434130820122'
||  '300d06092a864886f70d01010105000382010f003082010a0282010100e23be11172dea8a4d3a357'
||  'aa50a28f0b7790c9a2a5ee12ce965b010920cc0193a74e30b753f743c46900579de28d22dd870640'
||  '008109cece1b83bfdfcd3b7146e2d666c705b37627168f7b9e1e957deeb748a308dad6af7a0c3906'
||  '657f4a5d1fbc17f8abbeee28d7747f7a78995985686e5c23324bbf4ec0e85a6de370bf7710bffc01'
||  'f685d9a844105832a97518d5d1a2be47e2276af49a33f84908608bd45fb43a84bfa1aa4a4c7d3ecf'
||  '4f5f6c765ea04b37919edc22e66dce141a8e6acbfecdb3146417c75b299e32bff2eefad30b42d4ab'
||  'b74132da0cd4eff881d5bb8d583fb51be84928a270da3104ddf7b216f24c0a4e07a8ed4a3d5eb57f'
||  'a390c3af270203010001a3633061300e0603551d0f0101ff040403020186300f0603551d130101ff'
||  '040530030101ff301d0603551d0e0416041403de503556d14cbb66f0a3e21b1bc397b23dd155301f'
||  '0603551d2304183016801403de503556d14cbb66f0a3e21b1bc397b23dd155300d06092a864886f7'
||  '0d01010505000382010100cb9c37aa4813120afadd449c4f52b0f4dfae04f5797908a32418fc4b2b'
||  '84c02db9d5c7fef4c11f58cbb86d9c7a74e79829ab11b5e370a0a1cd4c8899938c9170e2ab0f1cbe'
||  '93a9ff63d5e40760d3a3bf9d5b09f1d58ee353f48e63fa3fa7dbb466df6266d6d16e418df22db5ea'
||  '774a9f9d58e22b59c04023ed2d2882453e7954922698e08048a837eff0d6796016deace80ecd6eac'
||  '4417382f49dae1453e2ab93653cf3a5006f72ee8c457496c612118d504ad783c2c3a806ba7ebaf15'
||  '14e9d889c1b9386ce2916c8aff64b977255730c01b24a3e1dce9df477cb5b424080530ec2dbd0bbf'
||  '45bf50b9a9f3eb980112adc888c698345f8d0a3cc6e9d595956dde',
    'hex'));

-- Single-value extractors
SELECT name,
       x509_commonName(der)               AS common_name,
       x509_issuerName(der)               AS issuer_name,
       x509_subjectName(der)              AS subject_name,
       x509_keyAlgorithm(der)             AS key_algorithm,
       x509_keySize(der)                  AS key_size,
       x509_signatureHashAlgorithm(der)   AS sig_hash_alg,
       x509_signatureKeyAlgorithm(der)    AS sig_key_alg,
       x509_notBefore(der)                AS not_before,
       x509_notAfter(der)                 AS not_after,
       encode(x509_serialNumber(der), 'hex')           AS serial_hex,
       encode(x509_publicKeyMD5(der), 'hex')           AS pubkey_md5,
       encode(x509_subjectKeyIdentifier(der), 'hex')   AS ski_hex,
       encode(x509_authorityKeyId(der), 'hex')         AS akid_hex
FROM certs ORDER BY name;

-- A self-issued root verifies against its own public key
SELECT name, x509_verify(der, x509_publicKey(der)) AS self_verify
FROM certs ORDER BY name;

-- RSA modulus length (in bytes) should match keySize / 8
SELECT name, octet_length(x509_rsaModulus(der)) * 8 = x509_keySize(der) AS modulus_matches_keysize
FROM certs ORDER BY name;

-- Extended key usages (none expected for these roots, which carry no EKU extension)
SELECT name, x509_extKeyUsages(der) AS eku
FROM certs ORDER BY name;

-- Roots can issue certs and have no pathlen constraint (-1 = unspecified)
SELECT name,
       x509_canIssueCerts(der)         AS can_issue,
       x509_getPathLenConstraint(der)  AS pathlen
FROM certs ORDER BY name;

-- x509_name(der) returns the DER-encoded subject Name; round-trip via x509_name_print
SELECT name, x509_name_print(x509_name(der)) AS subject_via_name
FROM certs ORDER BY name;

-- Neither root has embedded NULs in its names
SELECT name, x509_anyNamesWithNULs(der) AS any_names_with_nuls
FROM certs ORDER BY name;

-- Roots do not have the ROCA fingerprint
SELECT name, x509_hasROCAFingerprint(der) AS has_roca
FROM certs ORDER BY name;

-- NULL input handling: STRICT functions return NULL
SELECT x509_keyAlgorithm(NULL) IS NULL AS null_in_null_out;

DROP TABLE certs;
