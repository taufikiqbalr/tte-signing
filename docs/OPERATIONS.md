# Production Operations Runbook

## 1. Development mode vs production

Development bootstrap exists only to make local testing reproducible. With PKI_BOOTSTRAP_ENABLED=true the application creates Root CA, Issuing CA, OCSP, and TSA keys as local PKCS#12 files.

Do **not** use that mode as a production CA.

Production target:

~~~text
Offline Root CA
     |
     +---- signs Issuing CA certificate
                    |
          +---------+----------+
          |                    |
    Issuing CA HSM        Service certificates
          |                 OCSP / TSA
          |
    End-entity certs

Application:
- administrative API
- certificate metadata/revocation DB
- PAdES engine
- OCSP frontend
- TSA frontend

Private keys:
- held by HSM / PKCS#11 / remote key service
- never committed to Git
- never placed in normal container layers
~~~

## 2. Key hierarchy

Recommended separation:

- Root CA key: offline, rarely activated.
- Issuing CA key: online only where issuance is required; HSM protected.
- OCSP key: dedicated delegated responder key.
- TSA key: dedicated timestamp-only key.
- signer keys: per subscriber/user/device or approved remote-signing model.

Never reuse the TSA key as the CA, OCSP, web TLS, or end-user signing key.

## 3. Root CA ceremony

A production root ceremony should define:

1. authorized attendees/trusted roles;
2. clean-room or controlled environment;
3. HSM initialization;
4. entropy/key generation;
5. Root certificate profile review;
6. backup shares/M-of-N controls;
7. signing of Issuing CA certificate;
8. verification by an independent operator;
9. ceremony log and evidence;
10. secure shutdown/storage of Root CA.

The application should receive only public Root CA material in normal operation.

## 4. HSM integration

The current repository uses PKCS#12 to demonstrate the complete protocol flow.

Production refactor target:

- keep DSS PAdES service;
- replace exportable Pkcs12SignatureToken with a PKCS#11-backed or remote-signing token;
- move CA/OCSP/TSA signing operations behind an HSM adapter;
- keep certificate/status metadata in the application database;
- never export CA/TSA private keys.

HSM operational policy should cover:

- initialization;
- operator cards/credentials;
- backup/restore;
- HA;
- firmware changes;
- zeroization;
- key rotation;
- disaster recovery;
- audit log integration.

## 5. Public URL stability

Certificates contain AIA and CRL Distribution Point URLs. These become part of the certificate for its lifetime.

Set PKI_PUBLIC_BASE_URL to the final stable public service address **before** issuing production certificates.

Changing the application hostname later does not change already-issued certificate extensions.

Recommended patterns:

~~~text
https://pki.example.id/ocsp
https://pki.example.id/pki/issuing-ca.cer
https://pki.example.id/pki/crl/issuing-ca.crl
https://pki.example.id/tsa
~~~

Use load balancing and HA behind stable DNS.

## 6. OCSP operations

Monitor:

- availability;
- response latency;
- DB replication lag;
- thisUpdate/nextUpdate;
- responder certificate expiry;
- response-signature verification;
- UNKNOWN response rate;
- request volume/abuse.

Security controls:

- responder key in HSM;
- rate limiting;
- WAF/DoS controls where appropriate;
- immutable revocation audit;
- dual control for exceptional revocation administration;
- responder rollover before expiry.

## 7. CRL operations

The CRL is generated from the same revocation database used by OCSP.

Production enhancements may include:

- scheduled CRL publication;
- CRL Number stored as a monotonic persistent counter;
- cached/static CRL distribution via CDN/object storage;
- delta CRLs if required by policy;
- Root/Issuing-CA revocation publication strategy;
- historical CRL retention.

Do not make certificate validation depend on a single application instance.

## 8. TSA operations

RFC 3161 timestamp validity depends on trustworthy time.

Required controls:

- at least two/three independent time references as defined by policy;
- authenticated NTP/NTS or controlled PTP/time appliance;
- continuous drift measurement;
- alarms before maximum policy error;
- fail closed when the clock is outside accepted bounds;
- audit every clock-source/state transition;
- protect TSA private key in HSM;
- ensure TSA cert EKU remains timestamping-only;
- maintain unique TSA serials;
- define TSA policy OID and publish its policy.

The application-level accuracy field is evidence about the service policy. It is not a substitute for time infrastructure.

## 9. Certificate issuance

Before issuance:

1. authenticate the requesting actor;
2. perform identity proofing at the required assurance level;
3. authorize requested subject attributes;
4. ensure correct certificate profile;
5. generate key in the approved boundary;
6. issue certificate;
7. record issuance transaction and approver;
8. deliver certificate/key securely;
9. publish/activate status.

For production, do not return an exportable P12 if the assurance model requires non-exportable keys.

## 10. Revocation

Supported reason codes include:

- unspecified;
- keyCompromise;
- affiliationChanged;
- superseded;
- cessationOfOperation;
- certificateHold;
- privilegeWithdrawn.

Workflow should normally require:

- authenticated revocation request;
- authorization;
- reason selection;
- immutable audit record;
- status commit;
- OCSP/CRL freshness verification;
- subscriber/relying-party notification if policy requires it.

## 11. PAdES LTV workflow

Recommended lifecycle:

~~~text
PDF
 |
 +-- Sign -> B-T
 |
 +-- acquire/verify fresh revocation material
 |
 +-- augment -> B-LT
 |
 +-- archive timestamp -> B-LTA
 |
 +-- periodic preservation cycle
       |
       +-- re-validate
       +-- obtain new trusted timestamp
       +-- append new archive timestamp before obsolescence
~~~

Do not treat B-LTA as permanent without preservation.

Create an archival scheduler outside the request path for bulk revalidation/re-timestamping.

## 12. Backup and disaster recovery

Back up separately:

- CA metadata;
- certificate issuance DB;
- revocation DB;
- TSA serial state;
- application configuration;
- policy versions;
- audit logs;
- public certificates and CRLs;
- signed/validation evidence if the service is responsible for archival.

HSM key backup must follow the HSM vendor and security policy, not ordinary database backup.

Regularly test restore procedures.

## 13. Secrets

Secrets that must not be committed:

- keystore/P12 passwords;
- signer P12 files;
- HSM PIN/operator secrets;
- database passwords;
- API credentials;
- TLS private keys.

Use a secret manager/orchestrator secret facility.

Rotate the development defaults immediately.

## 14. Authentication and network security

The Basic Auth configuration is a development baseline.

Production administrative plane should use an enterprise IdP/OIDC and/or mTLS with RBAC and strong audit.

Recommended segmentation:

- public plane: OCSP, CRL/cert publication, TSA as required;
- signing API: authenticated application/service clients;
- issuance/revocation administration: restricted management network;
- database: private network only;
- HSM: restricted crypto network/interface.

Serve production endpoints over TLS.

## 15. Observability

Minimum metrics:

- certificate issuance count/failure;
- revocation count/failure;
- OCSP GOOD/REVOKED/UNKNOWN count;
- OCSP latency;
- TSA count/failure;
- TSA clock drift/health;
- PAdES sign/augment/validate latency and failure;
- certificate expiries;
- OCSP/TSA signer certificate expiries;
- DB connection/replication health;
- HSM availability.

Never log private key material, PKCS#12 bytes, passwords, HSM PINs, or document contents by default.

## 16. Rollover

Maintain documented runbooks for:

- Issuing CA rollover;
- delegated OCSP responder rollover;
- TSA certificate/key rollover;
- subscriber certificate renewal/re-key;
- algorithm migration.

LTV preservation must retain historical certificates/revocation evidence even after operational key rollover.

## 17. Go-live gates

Do not go live until:

- [ ] Root is offline.
- [ ] CA/TSA/OCSP keys are HSM-protected.
- [ ] AIA/CDP/TSA public URLs are final and highly available.
- [ ] trustworthy-time controls are tested.
- [ ] identity proofing and authorization are defined.
- [ ] CP/CPS/TSA policy are approved.
- [ ] issuance/revocation audit is immutable.
- [ ] backup and restore have been tested.
- [ ] responder/TSA rollover is tested.
- [ ] PAdES B-T/LT/LTA acceptance tests pass.
- [ ] offline validation of LT/LTA evidence is tested.
- [ ] legal/regulatory operating model has been reviewed.
