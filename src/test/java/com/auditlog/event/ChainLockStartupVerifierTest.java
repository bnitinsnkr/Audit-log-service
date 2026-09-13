package com.auditlog.event;

import org.junit.jupiter.api.Test;
import org.springframework.boot.WebApplicationType;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.context.ConfigurableApplicationContext;

import com.auditlog.AuditLogServiceApplication;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Boots the real {@link AuditLogServiceApplication} (no web server) against isolated,
 * in-memory H2 databases to prove two things about production startup:
 * <ul>
 *   <li>if the {@code audit_chain_lock} seed row was never created, the application refuses
 *       to start rather than accepting writes it cannot safely serialize;</li>
 *   <li>the real {@code chain-lock-schema.sql} / {@code chain-lock-data.sql} scripts, run the
 *       same way they run in production, are sufficient on their own (no manual steps) to make
 *       startup succeed against a completely blank database.</li>
 * </ul>
 * <p>
 * Overrides are passed as command-line-style {@code --arg} values to {@code run(...)}, not
 * {@code SpringApplicationBuilder.properties(...)}: the latter sets low-priority defaults that
 * the ambient {@code src/test/resources/application.properties} (also on the test classpath)
 * silently wins over for any key it already defines, such as the datasource URL - which would
 * make these tests validate the wrong database. Command-line args are the highest-precedence
 * Spring property source, so they reliably override it.
 */
class ChainLockStartupVerifierTest {

    @Test
    void applicationFailsToStartWhenTheChainLockRowWasNeverSeeded() {
        String jdbcUrl = "jdbc:h2:mem:chainlock-missing-" + System.nanoTime() + ";DB_CLOSE_DELAY=-1";

        assertThatThrownBy(() -> new SpringApplicationBuilder(AuditLogServiceApplication.class)
                .web(WebApplicationType.NONE)
                .run(
                        "--spring.datasource.url=" + jdbcUrl,
                        "--spring.datasource.driver-class-name=org.h2.Driver",
                        "--spring.datasource.username=sa",
                        "--spring.datasource.password=",
                        // Table exists (as if a schema migration ran), but the seed row does not
                        // (as if the seeding step was skipped) - the gap this slice must catch.
                        "--spring.jpa.hibernate.ddl-auto=create-drop",
                        "--spring.sql.init.mode=never"))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("Audit chain lock row");
    }

    @Test
    void applicationStartsWithNoManualStepsWhenTheRealInitScriptsRun() {
        String jdbcUrl = "jdbc:h2:mem:chainlock-seeded-" + System.nanoTime() + ";DB_CLOSE_DELAY=-1";

        ConfigurableApplicationContext context = new SpringApplicationBuilder(AuditLogServiceApplication.class)
                .web(WebApplicationType.NONE)
                .run(
                        "--spring.datasource.url=" + jdbcUrl,
                        "--spring.datasource.driver-class-name=org.h2.Driver",
                        "--spring.datasource.username=sa",
                        "--spring.datasource.password=",
                        // Mirrors real production config exactly (this test's own classpath
                        // application.properties shadows main's, so the shipped chain-lock
                        // SQL-init settings must be declared here to prove they, on their own,
                        // are sufficient): Hibernate creates nothing, and the real
                        // chain-lock-schema.sql / chain-lock-data.sql are the only thing
                        // standing up the lock row.
                        "--spring.jpa.hibernate.ddl-auto=none",
                        "--spring.sql.init.mode=always",
                        "--spring.sql.init.schema-locations=classpath:chain-lock-schema.sql",
                        "--spring.sql.init.data-locations=classpath:chain-lock-data.sql");

        try {
            ChainLockRepository chainLockRepository = context.getBean(ChainLockRepository.class);
            assertThat(chainLockRepository.existsById(AuditEventService.CHAIN_LOCK_ID)).isTrue();
        } finally {
            context.close();
        }
    }
}
