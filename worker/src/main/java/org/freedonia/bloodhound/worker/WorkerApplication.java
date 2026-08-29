package org.freedonia.bloodhound.worker;

import jakarta.annotation.PostConstruct;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.UUID;
import org.freedonia.bloodhound.worker.jobpoll.JobLogCaptureInstaller;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClient;

@SpringBootApplication
@EnableScheduling
public class WorkerApplication {

    public static void main(String[] args) {
        SpringApplication.run(WorkerApplication.class, args);
    }

    /**
     * Installing JobLogCaptureInstaller from main() (before SpringApplication.run()) doesn't
     * work: Spring Boot's own LoggingSystem resets/reconfigures the Logback context as part of
     * its early startup, wiping out any appender added before that point - confirmed live
     * (log_output stayed NULL on every attempt despite the installer running). A @PostConstruct
     * bean runs after the application context - and therefore LoggingSystem - has already
     * finished initializing, which is the actual safe point to add a programmatic appender.
     */
    @Component
    static class LogCaptureInstallerBean {
        @PostConstruct
        void install() {
            JobLogCaptureInstaller.install();
        }
    }

    @Bean
    public RestClient centralServerClient(
            @Value("${bloodhound.central-server-url}") String baseUrl,
            @Value("${bloodhound.worker.api-key}") String apiKey) {
        return RestClient.builder().baseUrl(baseUrl).defaultHeader("X-Worker-Api-Key", apiKey).build();
    }

    /** Stable for the life of the process; unique enough across replicas to identify a job's owner in claimed_by. */
    @Bean
    public String workerId() {
        String host;
        try {
            host = InetAddress.getLocalHost().getHostName();
        } catch (UnknownHostException e) {
            host = "worker";
        }
        return host + "-" + UUID.randomUUID().toString().substring(0, 8);
    }
}
