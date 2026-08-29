package org.freedonia.bloodhound.worker.jobpoll;

import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.AppenderBase;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;

/**
 * Feeds every log event this worker JVM produces through {@link JobLogCapture#record}, which is
 * a no-op unless a job is currently executing on the emitting thread. Registered by {@link
 * JobLogCaptureInstaller} alongside Spring Boot's own default console appender - this doesn't
 * replace or filter console output, it's purely an additional sink.
 */
public class JobLogCaptureAppender extends AppenderBase<ILoggingEvent> {

    private static final DateTimeFormatter TIME_FORMAT =
            DateTimeFormatter.ofPattern("HH:mm:ss.SSS").withZone(ZoneOffset.UTC);

    @Override
    protected void append(ILoggingEvent event) {
        String line = TIME_FORMAT.format(Instant.ofEpochMilli(event.getTimeStamp()))
                + " " + event.getLevel()
                + " " + event.getLoggerName().substring(event.getLoggerName().lastIndexOf('.') + 1)
                + " - " + event.getFormattedMessage();
        JobLogCapture.record(line);
    }
}
