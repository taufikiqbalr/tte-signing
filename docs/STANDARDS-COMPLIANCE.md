# Standards and Technical Compliance

This document maps the implementation to its technical standards. It is a technical conformance map, not a claim that a deployment has obtained formal certification.

## 1. Standards baseline

| Concern | Standard | Implementation |
|---|---|---|
| X.509 certificate and CRL profile | RFC 5280 | Bouncy Castle X.509 v3 |
| ASN.1 / DER | X.509 / RFC 5280 | Native ASN.1 objects and DER output |
| PKCS#12 / PFX | RFC 7292 | Signer key + chain bundle |
| CMS SignedData | RFC 5652 | DSS/Bouncy Castle |
| OCSP | RFC 6960 | Delegated responder |
| Time-Stamp Protocol | RFC 3161 | Dedicated TSA |
| Document Signing EKU | RFC 9336 | OID 1.3.6.1.5.5.7.3.36 |
| PAdES Baseline | ETSI EN 319 142-1 | DSS 6.5 |
| Validation lifecycle | ETSI EN 319 102-1 | DSS 6.5 |
| PAdES implementation | EU DSS 6.5 | PDFBox backend |

Primary references:

- RFC 5280: https://www.rfc-editor.org/rfc/rfc5280
- RFC 6960: https://www.rfc-editor.org/rfc/rfc6960
- RFC 3161: https://www.rfc-editor.org/rfc/rfc3161
- RFC 7292: https://www.rfc-editor.org/rfc/rfc7292
- RFC 5652: https://www.rfc-editor.org/rfc/rfc5652
- RFC 9336: https://www.rfc-editor.org/rfc/rfc9336
- ETSI EN 319 142-1: https://www.etsi.org/deliver/etsi_en/319100_319199/31914201/
- ETSI EN 319 102-1: https://www.etsi.org/deliver/etsi_en/319100_319199/31910201/
- EU DSS: https://ec.europa.eu/digital-building-blocks/DSS/

## 2. X.509 and ASN.1

X.509 certificates are ASN.1 structures serialized using DER. This service creates X.509 v3 objects directly rather than treating a JSON object or arbitrary payload as a certificate.

The generated certificate includes the standard TBSCertificate fields: v3 version, positive serial number, signature algorithm, issuer X.500 name, validity, subject X.500 name, SubjectPublicKeyInfo, and profile-specific extensions.

Default certificate signature algorithm is SHA-384 with RSA and generated RSA keys are 3072 bits.

### Certificate profile matrix

| Property | Root CA | Issuing CA | OCSP responder | TSA | Document signer |
|---|---|---|---|---|---|
| BasicConstraints | CA=true, pathLen=1 | CA=true, pathLen=0 | CA=false | CA=false | CA=false |
| BasicConstraints critical | Yes | Yes | Yes | Yes | Yes |
| KeyUsage | keyCertSign, cRLSign | keyCertSign, cRLSign | digitalSignature | digitalSignature, contentCommitment | digitalSignature, contentCommitment |
| KeyUsage critical | Yes | Yes | Yes | Yes | Yes |
| EKU | none | none | id-kp-OCSPSigning | only id-kp-timeStamping | id-kp-documentSigning |
| EKU critical | n/a | n/a | No | **Yes** | No |
| SKI | Yes | Yes | Yes | Yes | Yes |
| AKI | self | Root | Issuing | Issuing | Issuing |
| AIA caIssuers | n/a | Root cert | Issuing cert | Issuing cert | Issuing cert |
| AIA OCSP | n/a | n/a | /ocsp | /ocsp | /ocsp |
| CRL Distribution Point | n/a | n/a | Issuing CRL | Issuing CRL | Issuing CRL |
| OCSP no-check | n/a | n/a | Yes | No | No |
| SAN rfc822Name | No | No | No | No | If email is supplied |

The document-signing EKU is 1.3.6.1.5.5.7.3.36 as defined by RFC 9336.

## 3. PKCS#12

The issuance endpoint returns a PKCS#12 object containing:

1. the end-entity private key;
2. the end-entity signing certificate;
3. the Issuing CA certificate;
4. the Root CA certificate.

The container is protected using the password supplied by the API caller. Production deployments should strongly prefer non-exportable keys held in an HSM instead of transferring private keys through PKCS#12.

PKCS#12 is only a key/certificate container. It does not supply revocation checking, trusted time, or LTV.

## 4. OCSP - RFC 6960

Endpoint:

~~~text
POST /ocsp
Content-Type: application/ocsp-request
Accept: application/ocsp-response
~~~

Behavior:

- parses OCSPRequest and all SingleRequest entries;
- verifies that each CertID refers to this Issuing CA;
- returns GOOD for a known active certificate;
- returns REVOKED with revocation time and reason for a revoked certificate;
- returns UNKNOWN for an unknown serial or another issuer;
- includes thisUpdate and nextUpdate;
- signs BasicOCSPResponse with a dedicated delegated responder key;
- includes the responder certificate in the response;
- the responder certificate is directly issued by the Issuing CA and contains id-kp-OCSPSigning;
- the responder certificate includes id-pkix-ocsp-nocheck;
- an incoming OCSP nonce extension is echoed in the response.

Production additionally needs responder HA, rate limiting, HSM key custody, revocation database replication, response freshness monitoring, rollover procedures, and immutable revocation audit.

## 5. CRL - RFC 5280

Endpoint:

~~~text
GET /pki/crl/issuing-ca.crl
Content-Type: application/pkix-crl
~~~

The CRL contains issuer, thisUpdate, nextUpdate, revoked serial, revocationTime, CRLReason, Authority Key Identifier, CRL Number, and the Issuing CA signature.

OCSP and CRL are generated from the same authoritative revocation records.

## 6. TSA - RFC 3161

Endpoint:

~~~text
POST /tsa
Content-Type: application/timestamp-query
Accept: application/timestamp-reply
~~~

Implementation:

- accepts SHA-256, SHA-384 and SHA-512 message imprints;
- uses a dedicated TSA signing key;
- TSA certificate has a **critical EKU containing only id-kp-timeStamping**;
- includes the TSA certificate chain in the TimeStampToken;
- emits CMS SignedData carrying TSTInfo;
- handles request nonce through the RFC 3161 processing path;
- allocates unique, monotonically increasing TSA serials from PostgreSQL;
- applies the configured TSA policy OID.

### TSA policy OID

The OID in .env.example is a development placeholder. A production operator must replace it with an OID under an arc the organization legitimately controls.

### Trustworthy time

RFC 3161 requires a trustworthy time source. Java Instant.now() reflects the host operating-system clock; application code alone cannot make that clock trustworthy.

Production therefore needs:

- multiple authenticated/redundant time sources;
- NTP with NTS, PTP, secure time appliance, GNSS-backed infrastructure, or an equivalent control selected by policy;
- drift monitoring and alerting;
- fail-closed behavior when drift exceeds TSA policy;
- published accuracy/uncertainty;
- audit evidence for time source and clock health;
- no uncontrolled/manual clock adjustment.

TSA_ACCURACY_SECONDS must represent actual infrastructure accuracy, not merely a desired number.

## 7. PAdES and LTV

The application uses EU DSS 6.5 with its PDFBox implementation.

### PAdES B-B

Basic PAdES signature.

### PAdES B-T

Adds a trusted signature timestamp from the RFC 3161 TSA. Initial signing defaults to T.

### PAdES B-LT

Adds the certificate and revocation evidence needed for long-term validation into PDF validation structures.

The implementation intentionally treats LT as augmentation:

~~~text
B-T -> obtain valid/fresh revocation evidence -> B-LT
~~~

This avoids pretending that a just-created online response necessarily supplies all evidence needed at the required validation time.

### PAdES B-LTA

Adds archive/document timestamp protection over the long-term validation material.

LTA is not a one-time forever guarantee. Archive policy must schedule re-timestamping before certificate/evidence expiry or cryptographic deprecation.

## 8. Validation

POST /api/v1/signatures/pdf/validate uses DSS SignedDocumentValidator with:

- the local Root CA as trust anchor;
- online OCSP source with nonce;
- online CRL source;
- DSS signature validation engine.

The endpoint returns DSS Simple Report XML.

For a production evidence store, also retain the signed document digest, validation time, policy/version, library version, detailed report/diagnostic data where required, and all relevant certificate/revocation/timestamp evidence.

## 9. Algorithm defaults

| Function | Default |
|---|---|
| Key generation | RSA 3072 |
| Certificate signatures | SHA384withRSA |
| OCSP response signature | SHA384withRSA |
| TSA token signature | SHA384withRSA |
| PAdES document digest | SHA-384 |
| TSA message imprint accepted | SHA-256, SHA-384, SHA-512 |
| TSA ESSCertIDv2 certificate digest | SHA-256 |

Production requires algorithm agility, an algorithm retirement process, and periodic review of approved key sizes/hash functions.

## 10. Technical acceptance checklist

### Certificate and ASN.1

- [ ] OpenSSL parses every DER certificate.
- [ ] BasicConstraints is critical and correct for each profile.
- [ ] KeyUsage is critical and profile-appropriate.
- [ ] TSA EKU is critical and contains only timeStamping.
- [ ] OCSP responder EKU contains OCSP signing.
- [ ] Signer EKU contains document signing.
- [ ] SKI/AKI chain is consistent.
- [ ] Signer AIA contains OCSP and caIssuers.
- [ ] Signer CRL DP resolves to the current CRL.

### PKCS#12

- [ ] OpenSSL parses the P12/PFX.
- [ ] Private key matches signer public key.
- [ ] Signer -> Issuing -> Root chain is complete.

### OCSP

- [ ] GOOD before revocation.
- [ ] REVOKED after revocation.
- [ ] UNKNOWN for non-issued serial.
- [ ] Nonce is echoed.
- [ ] Responder signature validates to Issuing CA.
- [ ] thisUpdate/nextUpdate meet freshness policy.

### TSA

- [ ] OpenSSL ts command parses response.
- [ ] Message imprint matches request.
- [ ] Nonce matches.
- [ ] Policy OID is correct.
- [ ] Serial is unique.
- [ ] genTime is within the published accuracy.
- [ ] TSA chain and token signature validate.

### PAdES

- [ ] B-T contains signature timestamp.
- [ ] LT contains validation material.
- [ ] LT remains verifiable from embedded evidence when live OCSP/CRL are unavailable.
- [ ] LTA contains document/archive timestamp.
- [ ] DSS validation reports the expected indication under the chosen validation policy.

## 11. What source code cannot certify

Source code alone cannot provide CA accreditation, legal recognition, CP/CPS governance, personnel controls, trusted-role separation, key ceremonies, qualified HSM status, physical security, audited trustworthy time, legal identity proofing, or formal ETSI/regulatory conformity assessment.
