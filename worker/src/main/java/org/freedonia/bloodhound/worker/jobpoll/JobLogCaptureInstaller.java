package org.freedonia.bloodhound.worker.jobpoll;

import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.LoggerContext;
import org.slf4j.LoggerFactory;

/**
 * Registers {@link JobLogCaptureAppender} on the root logger - called once from {@code
 * WorkerApplication.main} before the Spring context starts, so every logger in the JVM (not just
 * ones under a specific package) feeds it. Programmatic, not a logback-spring.xml entry: this
 * worker has no existing logback config file, and adding one just to attach one extra appender
 * would risk silently overriding Spring Boot's own default console pattern/levels instead of
 * layering on top of them.
 */
public final class JobLogCaptureInstaller {

    private JobLogCaptureInstaller() {}

    public static void install() {
        LoggerContext context = (LoggerContext) LoggerFactory.getILoggerFactory();
        JobLogCaptureAppender appender = new JobLogCaptureAppender();
        appender.setContext(context);
        appender.start();
        context.getLogger(Logger.ROOT_LOGGER_NAME).addAppender(appender);
    }
}
