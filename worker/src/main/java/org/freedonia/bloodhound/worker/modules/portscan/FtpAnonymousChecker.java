package org.freedonia.bloodhound.worker.modules.portscan;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;

/**
 * A direct, minimal FTP anonymous-login probe - RFC 959's USER/PASS
 * exchange - standing in for the anonymous-login script a prior revision's
 * CLI-based scanner used to run. Only ever called by DeepPortScanModule
 * against a host with port 21 already confirmed open by naabu.
 */
final class FtpAnonymousChecker {

    private static final int TIMEOUT_MS = 5000;
    private static final int FTP_PORT = 21;

    private FtpAnonymousChecker() {}

    /** Returns the server's success response line if anonymous login worked, otherwise null. */
    static String checkAnonymousLogin(InetAddress address) {
        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress(address, FTP_PORT), TIMEOUT_MS);
            socket.setSoTimeout(TIMEOUT_MS);
            BufferedReader in =
                    new BufferedReader(new InputStreamReader(socket.getInputStream(), StandardCharsets.US_ASCII));
            PrintWriter out =
                    new PrintWriter(new OutputStreamWriter(socket.getOutputStream(), StandardCharsets.US_ASCII), true);

            in.readLine(); // 220 banner - not needed, just clears it off the wire

            out.print("USER anonymous\r\n");
            out.flush();
            String userResponse = in.readLine();
            if (userResponse == null || !userResponse.startsWith("331")) {
                return null; // server didn't even prompt for a password the normal way
            }

            out.print("PASS anonymous@example.com\r\n");
            out.flush();
            String passResponse = in.readLine();
            if (passResponse != null && passResponse.startsWith("230")) {
                return "Anonymous FTP login succeeded: " + passResponse;
            }
            return null;
        } catch (Exception e) {
            return null;
        }
    }
}
