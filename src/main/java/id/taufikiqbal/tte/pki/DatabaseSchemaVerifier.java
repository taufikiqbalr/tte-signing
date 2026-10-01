package id.taufikiqbal.tte.pki;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Component;

@Component
@Order(Ordered.HIGHEST_PRECEDENCE)
public class DatabaseSchemaVerifier implements ApplicationRunner {

    private static final Logger log =
            LoggerFactory.getLogger(DatabaseSchemaVerifier.class);

    private final JdbcTemplate jdbcTemplate;

    public DatabaseSchemaVerifier(JdbcTemplate jdbcTemplate) {
        this.jdbcTemplate = jdbcTemplate;
    }

    @Override
    public void run(ApplicationArguments args) {
        Boolean certificateTableExists = jdbcTemplate.queryForObject(
                "SELECT to_regclass('public.issued_certificate') IS NOT NULL",
                Boolean.class);
        Boolean tsaSequenceExists = jdbcTemplate.queryForObject(
                "SELECT to_regclass('public.tsa_serial_seq') IS NOT NULL",
                Boolean.class);

        if (!Boolean.TRUE.equals(certificateTableExists)
                || !Boolean.TRUE.equals(tsaSequenceExists)) {
            log.error(
                    "PKI database schema verification failed issuedCertificateTable={} tsaSerialSequence={}. "
                    + "Flyway migration V1__init.sql was not applied.",
                    certificateTableExists,
                    tsaSequenceExists);
            throw new IllegalStateException(
                    "PKI database schema is not initialized. "
                    + "Verify Spring Boot Flyway configuration and migration logs.");
        }

        log.info(
                "PKI database schema verified issuedCertificateTable=true tsaSerialSequence=true");
    }
}
