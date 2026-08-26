package org.freedonia.bloodhound.common.scanmodule;

public class ScanModuleException extends Exception {

    public ScanModuleException(String message) {
        super(message);
    }

    public ScanModuleException(String message, Throwable cause) {
        super(message, cause);
    }
}
