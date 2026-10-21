package org.freedonia.bloodhound.worker.ruleit;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.concurrent.TimeUnit;
import org.freedonia.bloodhound.common.findings.RawFinding;
import org.freedonia.bloodhound.common.scanmodule.ModuleResult;
import org.freedonia.bloodhound.worker.modules.exposure.ExposedPathModule;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.extension.ExtendWith;

/** Alt ports and Redis stay up only for this class so a port scan does not see them. */
@ExtendWith(RuleFixture.class)
@Timeout(value = 180, unit = TimeUnit.SECONDS)
class ExposureRulesIT {

    @BeforeAll
    static void openAltPorts() throws Exception {
        RuleFixture.ensureStarted();
        PortListeners.startExposurePorts();
    }

    @AfterAll
    static void closeAltPorts() {
        PortListeners.stopExposurePorts();
    }

    @Test
    void catalogPathsAltPortsRedisSourceMapAndSecrets() throws Exception {
        ModuleResult result = ScanSupport.run(new ExposedPathModule(), FixtureHosts.EXPOSURE);
        ScanSupport.assertRules(
                result,
                "EXPOSURE_ACTUATOR_HEAPDUMP",
                "EXPOSURE_ACTUATOR_ENV",
                "EXPOSURE_ACTUATOR_BEANS",
                "EXPOSURE_ACTUATOR_MAPPINGS",
                "EXPOSURE_ACTUATOR_CONFIGPROPS",
                "EXPOSURE_ACTUATOR_THREADDUMP",
                "EXPOSURE_ACTUATOR_LOGGERS",
                "EXPOSURE_ACTUATOR_HEALTH_DETAILS",
                "EXPOSURE_ACTUATOR_INFO",
                "EXPOSURE_GIT_CONFIG",
                "EXPOSURE_ENV_FILE",
                "EXPOSURE_AWS_CREDENTIALS",
                "EXPOSURE_SWAGGER_UI",
                "EXPOSURE_GRAPHQL_INTROSPECTION",
                "EXPOSURE_PHPMYADMIN",
                "EXPOSURE_JENKINS_SCRIPT",
                "EXPOSURE_KIBANA_UNAUTH",
                "EXPOSURE_SECURITY_TXT_PRESENT",
                "EXPOSURE_SECURITY_TXT_EXPIRED",
                "EXPOSURE_DS_STORE",
                "EXPOSURE_DIRECTORY_LISTING",
                "EXPOSURE_BACKUP_ARCHIVE",
                "EXPOSURE_SQL_DUMP_FILE",
                "EXPOSURE_PHP_INFO",
                "EXPOSURE_SSH_PRIVATE_KEY",
                "EXPOSURE_PROMETHEUS_METRICS",
                "EXPOSURE_SPRING_BOOT_H2_CONSOLE",
                "EXPOSURE_LARAVEL_TELESCOPE",
                "EXPOSURE_ASPNET_TRACE_AXD",
                "EXPOSURE_ASPNET_ELMAH",
                "EXPOSURE_ADMINER",
                "EXPOSURE_LARAVEL_DEBUG_MODE",
                "EXPOSURE_DOCKER_API",
                "EXPOSURE_ELASTICSEARCH_UNAUTH",
                "EXPOSURE_CONSUL_UNAUTH",
                "EXPOSURE_GRAFANA_UNAUTH",
                "EXPOSURE_MONGO_EXPRESS_UNAUTH",
                "EXPOSURE_TRAEFIK_DASHBOARD_UNAUTH",
                "EXPOSURE_REDIS_UNAUTH",
                "EXPOSURE_JS_SOURCE_MAP",
                "EXPOSURE_LIVE_SECRET_DETECTED");
        ScanSupport.assertAbsent(result, "EXPOSURE_ACTUATOR_INDEX", "EXPOSURE_ACTUATOR_HEALTH");
        ScanSupport.assertAsset(result, "EXPOSURE_DOCKER_API", FixtureHosts.EXPOSURE + ":2375");
        ScanSupport.assertAsset(result, "EXPOSURE_ELASTICSEARCH_UNAUTH", FixtureHosts.EXPOSURE + ":9200");
        ScanSupport.assertAsset(result, "EXPOSURE_CONSUL_UNAUTH", FixtureHosts.EXPOSURE + ":8500");
        ScanSupport.assertAsset(result, "EXPOSURE_GRAFANA_UNAUTH", FixtureHosts.EXPOSURE + ":3000");
        ScanSupport.assertAsset(result, "EXPOSURE_MONGO_EXPRESS_UNAUTH", FixtureHosts.EXPOSURE + ":8081");
        ScanSupport.assertAsset(result, "EXPOSURE_TRAEFIK_DASHBOARD_UNAUTH", FixtureHosts.EXPOSURE + ":8080");
        ScanSupport.assertAsset(result, "EXPOSURE_REDIS_UNAUTH", FixtureHosts.EXPOSURE + ":6379");
        ScanSupport.assertAsset(result, "EXPOSURE_LIVE_SECRET_DETECTED", FixtureHosts.EXPOSURE + " (.git/config)");
        ScanSupport.assertAsset(result, "EXPOSURE_LIVE_SECRET_DETECTED", FixtureHosts.EXPOSURE + " (.env)");
        ScanSupport.assertAsset(result, "EXPOSURE_LIVE_SECRET_DETECTED", FixtureHosts.EXPOSURE + " (.aws/credentials)");
        assertThat(result.findings())
                .filteredOn(finding -> "EXPOSURE_JS_SOURCE_MAP".equals(finding.ruleId()))
                .extracting(RawFinding::affectedAsset)
                .anyMatch(asset -> asset.endsWith("/app.js.map"));
    }

    @Test
    void actuatorIndexAndBareHealthAreSeparateFromSubpaths() throws Exception {
        ModuleResult result = ScanSupport.run(new ExposedPathModule(), FixtureHosts.EXPOSURE_INDEX);
        ScanSupport.assertRules(result, "EXPOSURE_ACTUATOR_INDEX", "EXPOSURE_ACTUATOR_HEALTH");
        ScanSupport.assertAbsent(
                result,
                "EXPOSURE_ACTUATOR_HEALTH_DETAILS",
                "EXPOSURE_ACTUATOR_HEAPDUMP",
                "EXPOSURE_ACTUATOR_ENV",
                "EXPOSURE_LARAVEL_DEBUG_MODE",
                "EXPOSURE_JS_SOURCE_MAP");
    }
}
