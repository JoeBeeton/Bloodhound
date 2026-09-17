package org.freedonia.bloodhound.common.scanmodule;

/**
 * Signals that a scan module confirmed the target host does not exist (DNS resolution
 * failure), as opposed to some other error (timeout, crash, bad response). Kept distinct
 * from the plain {@link ScanModuleException} so the worker's job-reporting path can flag
 * this outcome to central-server without parsing error text - a confirmed-dead host is a
 * correct scan result, not a failure, and central-server uses this signal to avoid
 * counting it toward a scan run's PARTIAL_FAILURE status.
 */
public class HostUnreachableException extends ScanModuleException {

    public HostUnreachableException(String message) {
        super(message);
    }

    public HostUnreachableException(String message, Throwable cause) {
        super(message, cause);
    }
}
