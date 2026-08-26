package org.freedonia.bloodhound.worker;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.UUID;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.web.client.RestClient;

@SpringBootApplication
@EnableScheduling
public class WorkerApplication {

    public static void main(String[] args) {
        SpringApplication.run(WorkerApplication.class, args);
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
