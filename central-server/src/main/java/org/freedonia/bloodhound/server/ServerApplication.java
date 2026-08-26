package org.freedonia.bloodhound.server;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.scheduling.annotation.EnableAsync;
import org.springframework.scheduling.annotation.EnableScheduling;

@SpringBootApplication
@EnableScheduling
// Slack webhook delivery (notification.SlackNotifier) is fire-and-forget: a slow or
// unreachable Slack endpoint must never block the scan/finding pipeline that
// triggered it.
@EnableAsync
public class ServerApplication {

    public static void main(String[] args) {
        SpringApplication.run(ServerApplication.class, args);
    }
}
