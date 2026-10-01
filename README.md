# TTE Signing - Private PKI, OCSP, TSA and PAdES LTV

Reference implementation sistem tanda tangan digital berbasis **private PKI** dengan sertifikat X.509 yang diterbitkan sendiri. Proyek ini menyediakan lifecycle lengkap untuk penerbitan sertifikat, revocation checking, trusted timestamp, dan PDF signature dengan dukungan Long-Term Validation (LTV).

## Kapabilitas

- Private Root CA dan Issuing CA.
- X.509 v3 certificate issuance dengan struktur ASN.1/DER dan extension RFC 5280.
- End-entity document-signing certificate dengan EKU `id-kp-documentSigning` (1.3.6.1.5.5.7.3.36).
- Export signer certificate + private key sebagai PKCS#12/PFX.
- Certificate revocation dan CRL.
- OCSP responder RFC 6960, termasuk delegated OCSP signing certificate dan nonce echo.
- RFC 3161 Time-Stamp Authority (TSA).
- PAdES Baseline B/T/LT/LTA menggunakan EU DSS 6.5.
- PDF signature verification dan DSS Simple Report.
- Docker Compose + PostgreSQL + Flyway.
- Basic authentication untuk administrative/signing API; endpoint OCSP, TSA, CA certificate dan CRL dibuat publik.
- Production-hardening guidance untuk offline Root CA, HSM/PKCS#11, trustworthy time, key ceremony, audit, HA, TLS/mTLS, dan CP/CPS.

## Arsitektur

~~~text
                                 +--------------------------+
                                 |      Offline Root CA     |
                                 |  (DEV: local PKCS#12)    |
                                 +------------+-------------+
                                              |
                                              | issues
                                              v
                                 +--------------------------+
                                 |        Issuing CA        |
                                 +-----+-----------+--------+
                                       |           |
                               issues  |           | issues
                                       v           v
                           +-----------+--+    +---+----------------+
                           | OCSP Responder|    | RFC 3161 TSA      |
                           | delegated cert|    | timestamp-only cert|
                           +-------+------+    +---------+----------+
                                   |                     |
                           revocation status             | timestamp token
                                   |                     |
                                   v                     v
+-----------+ issue P12 +------------------+ sign/extend +-----------------+
| Admin/API |----------->| End-user signer |----------->| PAdES B/T/LT/LTA|
+-----------+            +------------------+            +-----------------+
        |                         |
        | revoke                  | validation data
        v                         v
+----------------+       +------------------------------+
| PostgreSQL     |<----->| CRL + OCSP + cert chain     |
+----------------+       +------------------------------+
~~~

## LTV model

LTV bukan sekadar menambahkan sebuah timestamp saat signing. Implementasi ini mengikuti lifecycle PAdES:

1. **PAdES B-B** - basic PDF signature.
2. **PAdES B-T** - B-B + trusted signature timestamp dari TSA.
3. **PAdES B-LT** - memasukkan certificate chain dan revocation evidence (OCSP/CRL) yang dibutuhkan untuk validasi jangka panjang ke PDF DSS.
4. **PAdES B-LTA** - B-LT + document/archive timestamp untuk mempertahankan evidentiary validity ketika algoritma, sertifikat, atau evidence lama mendekati akhir masa aman.

Untuk workflow produksi, buat signature pada level **T**, lalu augment ke **LT** setelah revocation evidence tersedia/fresh, dan ke **LTA** setelahnya. Jangan memalsukan LTV dengan hanya memberi label LT/LTA tanpa memasukkan validation material.

## Quick start

### 1. Jalankan service

~~~bash
cp .env.example .env
# Ganti seluruh password default di .env
docker compose up --build
~~~

Default application port is `8088`. PostgreSQL remains internal to the Compose network on port `5432`.

Service: `http://localhost:8088`

Jika sebelumnya pernah menjalankan versi Compose yang memakai mount PostgreSQL lama dan masih mengalami error volume, jalankan `docker compose down -v` **hanya jika data development boleh dihapus**, lalu jalankan ulang. Compose terbaru memakai volume baru `postgres18-data` dengan layout PostgreSQL 18 yang benar.

Development bootstrap akan membuat Root CA, Issuing CA, delegated OCSP responder, dan TSA certificate ketika storage masih kosong. **Mode ini tidak untuk production.**

### 2. Issue document-signing certificate + PKCS#12

~~~bash
curl -u admin:change-this-admin-password \
  -H "Content-Type: application/json" \
  -d '{
    "commonName":"Taufik Iqbal Ramdhani",
    "organization":"Example Organization",
    "organizationalUnit":"Digital Signature",
    "country":"ID",
    "email":"signer@example.org",
    "validityDays":365,
    "pkcs12Password":"a-strong-p12-password"
  }' \
  http://localhost:8088/api/v1/certificates/issue \
  -o signer.p12 -D issue-headers.txt
~~~

Serial certificate terdapat pada response header `X-Certificate-Serial`.

Inspect PKCS#12:

~~~bash
openssl pkcs12 -in signer.p12 -info -noout
~~~

### 3. Sign PDF menjadi PAdES B-T

~~~bash
curl -u admin:change-this-admin-password \
  -F document=@document.pdf \
  -F pkcs12=@signer.p12 \
  -F password=a-strong-p12-password \
  -F level=T \
  -F reason="Approval" \
  http://localhost:8088/api/v1/signatures/pdf/sign \
  -o document-bt.pdf
~~~

Level `B` juga didukung. Untuk signature yang ingin dibuat LTV, gunakan `T`.

### 4. Augment B-T menjadi B-LT

~~~bash
curl -u admin:change-this-admin-password \
  -F document=@document-bt.pdf \
  "http://localhost:8088/api/v1/signatures/pdf/extend?level=LT" \
  -o document-lt.pdf
~~~

### 5. Augment B-LT menjadi B-LTA

~~~bash
curl -u admin:change-this-admin-password \
  -F document=@document-lt.pdf \
  "http://localhost:8088/api/v1/signatures/pdf/extend?level=LTA" \
  -o document-lta.pdf
~~~

### 6. Validate

~~~bash
curl -u admin:change-this-admin-password \
  -F document=@document-lta.pdf \
  http://localhost:8088/api/v1/signatures/pdf/validate
~~~

Output berupa DSS Simple Report XML.

## Endpoint utama

| Method | Endpoint | Auth | Fungsi |
|---|---|---:|---|
| POST | `/api/v1/certificates/issue` | Basic | Issue X.509 signer + PKCS#12 |
| GET | `/api/v1/certificates/{serial}` | Basic | Certificate metadata |
| POST | `/api/v1/certificates/{serial}/revoke` | Basic | Revoke certificate |
| POST | `/api/v1/signatures/pdf/sign` | Basic | PAdES B-B / B-T |
| POST | `/api/v1/signatures/pdf/extend?level=LT|LTA` | Basic | LTV augmentation |
| POST | `/api/v1/signatures/pdf/validate` | Basic | Validate signed PDF |
| POST | `/ocsp` | Public | RFC 6960 OCSP responder |
| POST | `/tsa` | Public | RFC 3161 TSA |
| GET | `/pki/root-ca.cer` | Public | Root CA DER |
| GET | `/pki/issuing-ca.cer` | Public | Issuing CA DER |
| GET | `/pki/ocsp-responder.cer` | Public | OCSP cert DER |
| GET | `/pki/tsa.cer` | Public | TSA cert DER |
| GET | `/pki/crl/issuing-ca.crl` | Public | Issuing CA CRL |
| GET | `/actuator/health` | Public | Health check |

## Standards

| Area | Standard/profile |
|---|---|
| X.509 certificate + CRL | RFC 5280 |
| ASN.1 / DER certificate structure | X.509 / RFC 5280 |
| PKCS#12/PFX | RFC 7292 |
| CMS SignedData | RFC 5652 |
| OCSP | RFC 6960 |
| Time Stamp Protocol | RFC 3161 |
| Document Signing EKU | RFC 9336 |
| PAdES Baseline | ETSI EN 319 142-1 |
| Signature validation lifecycle | ETSI EN 319 102-1 |
| PAdES implementation | EU DSS 6.5 |

Detail mapping ada di [docs/STANDARDS-COMPLIANCE.md](docs/STANDARDS-COMPLIANCE.md).

## Indonesia: technical compliance vs legal status

Sistem ini adalah **private/self-operated PKI reference implementation**. Memenuhi format/protocol RFC/ETSI secara teknis **tidak otomatis** menjadikan operator sebagai **PSrE Indonesia** atau signature yang dihasilkan sebagai **Tanda Tangan Elektronik Tersertifikasi**.

Untuk penggunaan yang membutuhkan status TTE Tersertifikasi di Indonesia, tinjau regulasi Komdigi yang berlaku dan kewajiban PSrE, termasuk pengakuan/izin, tata kelola, audit/sertifikasi, perangkat pembuat tanda tangan, validation authority, timestamp, dan kewajiban lain. Lihat [docs/INDONESIA-COMPLIANCE.md](docs/INDONESIA-COMPLIANCE.md).

## Production requirements

Default project sengaja nyaman untuk development. Sebelum production:

- root private key harus offline dan tidak berada di application container;
- gunakan HSM/KMS yang mendukung operasi signing; prefer PKCS#11;
- pisahkan keys untuk Issuing CA, OCSP dan TSA;
- TSA wajib memakai trustworthy time source dan time-monitoring;
- semua public URLs pada AIA/CDP harus stabil, HTTPS bila sesuai deployment, dan highly available;
- gunakan TLS untuk API, mTLS/OIDC untuk administrative plane;
- jangan simpan password P12/keystore di source control;
- implementasikan CP/CPS, key ceremony, dual control/M-of-N, separation of duties dan immutable audit;
- buat backup/restore dan disaster-recovery procedure untuk CA metadata dan audit data;
- lakukan rate limiting dan monitoring pada OCSP/TSA;
- siapkan certificate rollover, CRL/OCSP continuity, TSA renewal dan LTA re-timestamping policy.

Lihat [docs/OPERATIONS.md](docs/OPERATIONS.md).

## Technology

- Java 21
- Spring Boot 4.1.x
- Bouncy Castle 1.84
- EU DSS 6.5 + PDFBox implementation
- PostgreSQL
- Flyway
- Docker Compose

## Security note

Jangan gunakan credentials contoh. Jangan menjalankan dev bootstrap yang membuat Root CA online pada production. Source code ini memberi building blocks protocol/crypto dan bukan pengganti PKI governance, HSM, audited operating procedures, atau legal certification.


## Troubleshooting dan Docker logs

Setiap HTTP request diberi correlation ID. Response menyertakan header `X-Request-ID`, dan log aplikasi memasukkan nilai yang sama sebagai `requestId`. Gunakan ID tersebut untuk menghubungkan error client dengan stack trace di container.

Lihat log aplikasi secara live:

~~~bash
docker compose logs -f --tail=300 tte-signing
~~~

Cari error penting:

~~~bash
docker compose logs --since=10m tte-signing \
  | grep -i -E "ERROR|WARN|PAdES|PKCS12|RFC3161|OCSP|requestId"
~~~

Logging yang tersedia mencakup:

- HTTP request start/completion/failure dan duration;
- PAdES signing B/B-T;
- LTV augmentation LT/LTA;
- signed-PDF validation;
- PKCS#12 signer/key-store loading;
- certificate issuance;
- RFC 3161 TSA request/rejection/failure;
- OCSP status GOOD/REVOKED/UNKNOWN dan responder failure.

Password, private-key material, dan isi dokumen tidak ditulis ke log.

Jika client menerima error JSON, simpan nilai `requestId`, kemudian cari:

~~~bash
docker compose logs tte-signing | grep "<requestId>"
~~~

Untuk memastikan image menggunakan source terbaru setelah perubahan dependency:

~~~bash
git pull
docker compose down
docker compose build --no-cache tte-signing
docker compose up -d
docker compose logs -f --tail=200 tte-signing
~~~
