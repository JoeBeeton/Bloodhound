package org.freedonia.bloodhound.worker.jobpoll;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Thread-local buffer of log lines emitted while a job is executing on this thread - paired with
 * {@link JobLogCaptureAppender} (a Logback appender registered alongside the default console one,
 * see {@link JobLogCaptureInstaller}) which feeds every log event this JVM produces through
 * {@link #record}. {@link JobPollingLoop} executes jobs strictly sequentially, one at a time, on
 * its own single polling thread (see its own class javadoc) - a thread-local is sufficient here,
 * no cross-thread coordination needed, and other threads (the heartbeat sender, Spring's own
 * scheduling infrastructure) simply have no active buffer, so their log lines are correctly
 * ignored rather than bleeding into a job's captured output.
 *
 * <p>Added specifically to close a real diagnosability gap found live: a scan module failure's
 * persisted error_detail was often a terse wrapper message with no way to see what actually
 * happened during execution (e.g. ZAP's spider/active-scan progress) without shelling into the
 * worker container and grepping its stdout for the right time window.
 */
public final class JobLogCapture {

    /** Bounds a single job's captured log - a runaway/looping module logging thousands of lines
     * shouldn't turn one job's report into an unbounded payload. Oldest lines drop first, since a
     * diagnostic read cares most about what happened right before the job ended. */
    private static final int MAX_LINES = 500;

    private static final ThreadLocal<List<String>> BUFFER = new ThreadLocal<>();

    private JobLogCapture() {}

    public static void begin() {
        BUFFER.set(new ArrayList<>());
    }

    public static void record(String line) {
        List<String> buffer = BUFFER.get();
        if (buffer == null) {
            return;
        }
        if (buffer.size() >= MAX_LINES) {
            buffer.remove(0);
        }
        buffer.add(line);
    }

    /** Clears the thread-local buffer regardless of outcome - callers must not leak a stale buffer into whatever this thread does next. */
    public static List<String> end() {
        List<String> buffer = BUFFER.get();
        BUFFER.remove();
        return buffer == null ? Collections.emptyList() : buffer;
    }
}
