# Indonesia Compliance Boundary

## Executive point

Private PKI plus X.509, OCSP, TSA, and PAdES compliance does **not by itself** make a deployment an Indonesian PSrE and does not automatically make its signatures **Tanda Tangan Elektronik Tersertifikasi**.

This project separates:

1. technical cryptographic/protocol compliance, which software can implement; and
2. legal/regulatory status, which also depends on the operator, licensing/recognition, identity proofing, governance, audited facilities, certified devices, operational procedures, and other obligations.

This document is an engineering checklist, not legal advice.

## Regulatory references to review

Before production, confirm the current text and amendments in official JDIH, including at minimum:

- Indonesian legislation governing electronic information/transactions and electronic signatures;
- the implementing government regulations for electronic systems/transactions;
- Peraturan Menteri Kominfo No. 11 Tahun 2022 tentang Tata Kelola Penyelenggaraan Sertifikasi Elektronik;
- current Komdigi licensing and operational rules, including Peraturan Menteri Komdigi No. 15 Tahun 2025 where applicable;
- BSSN/Komdigi technical, audit, certification, accreditation, and sector-specific requirements applicable to the deployment.

Official source:

https://jdih.komdigi.go.id/

## Why OCSP, CRL, and TSA are implemented

Even for a private CA, revocation and trusted time are essential for sound PKI operation and long-term validation.

The reference implementation therefore supplies:

- certificate lifecycle and revocation records;
- OCSP validation service;
- CRL publication;
- RFC 3161 timestamp service;
- PAdES B-T timestamping;
- LT validation-evidence embedding;
- LTA archive timestamping.

The existence of these endpoints does not establish regulatory recognition. Production conformity can additionally require certified hardware, audits, operational availability, identity controls, trusted roles, service policies, facility controls, and formal approval.

## Two target operating models

### A. Internal/private digital-signature trust domain

Typical examples:

- enterprise internal workflow;
- development/test;
- closed B2B trust community;
- a contractual trust framework where participants explicitly trust a private CA.

The private PKI in this repository can be the basis for this model, subject to applicable law and organizational risk controls.

### B. Tanda Tangan Elektronik Tersertifikasi

If the business requirement is TTE Tersertifikasi, do not assume that a certificate from the self-operated Root CA is sufficient.

The solution must be aligned with the Indonesian PSrE framework and the current requirements that apply to the operator/service. If the organization is not operating as the required recognized/authorized PSrE, a safer architecture is generally to integrate the document-signing layer with an appropriate Indonesian PSrE rather than presenting the private Root CA as a certified public trust anchor.

## Recommended dual-provider architecture

~~~text
                        +--------------------------+
                        |   Signing Application    |
                        | PAdES / LTV / Validation |
                        +------------+-------------+
                                     |
                          signer/token abstraction
                                     |
                 +-------------------+--------------------+
                 |                                        |
                 v                                        v
      +-----------------------+                 +-----------------------+
      | PRIVATE PKI MODE      |                 | PSrE MODE             |
      | P12 or HSM            |                 | remote signing API    |
      | local OCSP/CRL/TSA    |                 | PSrE cert/status/TSA  |
      +-----------------------+                 +-----------------------+
~~~

DSS provides token/signing abstractions, so the PAdES/LTV layer can later be connected to PKCS#11/HSM or a remote-signature provider without rewriting the document-format layer.

## Compliance work package before go-live

### Governance

- Certificate Policy (CP);
- Certification Practice Statement (CPS);
- TSA Policy and TSA Practice Statement;
- trusted roles and role separation;
- dual control for sensitive operations;
- subscriber/relying-party terms;
- incident, compromise, suspension, revocation, and disaster procedures.

### Identity and enrollment

- define identity-proofing assurance;
- authenticate certificate applicants;
- bind verified identity to certificate fields;
- preserve authorization/evidence of issuance;
- define renewal, re-key, replacement, and revocation.

### Crypto and key custody

- production-qualified HSM;
- non-exportable CA/TSA private keys;
- offline Root CA;
- documented key ceremonies;
- M-of-N or equivalent controls where required;
- crypto-agility and algorithm-retirement plan.

### Validation

- stable public AIA/CDP endpoints;
- documented OCSP/CRL availability;
- defined response freshness;
- responder rollover;
- historical evidence preservation;
- protection against unauthorized status changes.

### TSA

- trustworthy time source;
- drift monitoring;
- defined accuracy;
- TSA key in HSM;
- timestamp policy OID controlled by the organization;
- TSA certificate rollover;
- timestamp audit retention.

### Long-term validation

- define when B-T is augmented to LT;
- define when LT becomes LTA;
- periodically re-timestamp LTA before cryptographic/evidence obsolescence;
- preserve signed originals and validation evidence immutably.

### Audit and assurance

- immutable security/audit logs;
- certificate issuance/revocation audit;
- configuration/admin change audit;
- key ceremony evidence;
- vulnerability and patch management;
- independent assessment required by the applicable scheme.

## Avoid false trust assertions

Do not place a regulated certificate policy OID, QC statement, PSrE identity, or other trust claim into a certificate simply to make it look certified. Such identifiers should only be asserted when the operator is legitimately entitled to do so and the associated policy/process is actually implemented.

An OID identifies a policy or object; it does not itself grant legal status.
