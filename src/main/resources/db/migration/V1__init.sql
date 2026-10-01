CREATE TABLE issued_certificate (
    serial_hex          VARCHAR(80) PRIMARY KEY,
    subject_dn          TEXT NOT NULL,
    certificate_der     BYTEA NOT NULL,
    not_before          TIMESTAMPTZ NOT NULL,
    not_after           TIMESTAMPTZ NOT NULL,
    status              VARCHAR(16) NOT NULL DEFAULT 'GOOD',
    revocation_time     TIMESTAMPTZ NULL,
    revocation_reason   INTEGER NULL,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT issued_certificate_status_ck CHECK (status IN ('GOOD', 'REVOKED'))
);

CREATE INDEX idx_issued_certificate_status
    ON issued_certificate(status);

CREATE INDEX idx_issued_certificate_not_after
    ON issued_certificate(not_after);

CREATE SEQUENCE tsa_serial_seq
    AS BIGINT
    START WITH 1
    INCREMENT BY 1
    NO CYCLE;
