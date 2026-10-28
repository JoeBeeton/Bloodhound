package org.freedonia.bloodhound.worker.modules.portscan;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.util.Set;

/**
 * Confirms a protocol actually answers on an open SMB (445) or MSRPC endpoint-mapper (135) port,
 * rather than treating any successful bare TCP connect as proof a real service is behind it - see
 * PortScanDecisionLogic's {@code SMB_NETBIOS_RPC_PORTS} doc for the live false positive this
 * closes: a host that answered the TCP handshake on 135 and 445 exactly once, then refused both
 * ports on every one of five later re-tests across two protocols and two address families -
 * almost certainly a transient listener or a stateful firewall/load balancer accepting the
 * handshake with nothing real behind it, not a genuinely exposed Windows service.
 *
 * <p>Both probes send exactly the first message a real SMB/RPC client sends before any
 * authentication - an SMB2 NEGOTIATE request, and a DCE/RPC BIND request against the standard
 * endpoint-mapper interface (the same connectivity check tools like rpcclient/nmap's msrpc-enum
 * perform) - read-only protocol identification, not exploitation or a login attempt; nothing here
 * does anything an unauthenticated client couldn't already do by design. Fails closed (returns
 * false) on any timeout, refusal, or malformed response - an ambiguous result must never be
 * treated as confirmation.
 *
 * <p>Port 139 (legacy NetBIOS-session-wrapped SMB1) is deliberately not handled here - confirming
 * it needs a full NBSS session-request/session-ack handshake before SMB can even be negotiated,
 * which this probe doesn't implement. Callers should treat 139 as always-unconfirmed rather than
 * risk a wrong implementation silently mis-confirming it.
 */
final class SmbRpcConfirmationProbe {

    /** The only two SMB_NETBIOS_RPC_PORTS entries this probe can actually confirm - see class javadoc re: 139. */
    static final Set<Integer> CONFIRMABLE_PORTS = Set.of(135, 445);

    private static final int SMB_PORT = 445;
    private static final int RPC_PORT = 135;
    private static final int CONNECT_TIMEOUT_MS = 2000;
    private static final int READ_TIMEOUT_MS = 3000;

    private SmbRpcConfirmationProbe() {}

    /** Dispatches to the right probe for a real, literal SMB (445) or RPC (135) port; false for anything else. */
    static boolean confirm(InetAddress address, int port) {
        if (port == SMB_PORT) {
            return confirmSmb(address, port);
        }
        if (port == RPC_PORT) {
            return confirmRpcBind(address, port);
        }
        return false;
    }

    /** Port parameterized separately so tests can point this at a real loopback server on an ephemeral port. */
    static boolean confirmSmb(InetAddress address, int port) {
        return probe(address, port, smbNegotiateRequest(), SmbRpcConfirmationProbe::looksLikeSmbResponse);
    }

    /** Port parameterized separately so tests can point this at a real loopback server on an ephemeral port. */
    static boolean confirmRpcBind(InetAddress address, int port) {
        return probe(address, port, rpcBindRequest(), SmbRpcConfirmationProbe::looksLikeRpcBindResponse);
    }

    private interface ResponseCheck {
        boolean test(byte[] response, int length);
    }

    private static boolean probe(InetAddress address, int port, byte[] request, ResponseCheck check) {
        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress(address, port), CONNECT_TIMEOUT_MS);
            socket.setSoTimeout(READ_TIMEOUT_MS);
            OutputStream out = socket.getOutputStream();
            out.write(request);
            out.flush();
            byte[] response = new byte[256];
            int read = readEnoughToIdentify(socket.getInputStream(), response);
            return read > 0 && check.test(response, read);
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Stops as soon as 4 bytes are in hand - enough for either check below - rather than reading
     * to EOF or filling the whole buffer, so a server that keeps the connection open after
     * replying (or one deliberately trickling bytes) can't make this probe wait any longer than
     * it has to.
     */
    private static int readEnoughToIdentify(InputStream in, byte[] buffer) throws IOException {
        int total = 0;
        while (total < 4) {
            int n = in.read(buffer, total, buffer.length - total);
            if (n < 0) {
                break;
            }
            total += n;
        }
        return total;
    }

    private static boolean looksLikeSmbResponse(byte[] response, int length) {
        if (length < 4) {
            return false;
        }
        boolean smb2 = (response[0] & 0xFF) == 0xFE && response[1] == 'S' && response[2] == 'M' && response[3] == 'B';
        boolean smb1 = (response[0] & 0xFF) == 0xFF && response[1] == 'S' && response[2] == 'M' && response[3] == 'B';
        return smb2 || smb1;
    }

    private static boolean looksLikeRpcBindResponse(byte[] response, int length) {
        if (length < 3) {
            return false;
        }
        int ptype = response[2] & 0xFF;
        // 12 = bind_ack, 13 = bind_nak - either one proves a real DCE/RPC implementation parsed
        // our bind PDU and replied in-protocol, even if it ultimately rejected this exact binding.
        return response[0] == 5 && (ptype == 12 || ptype == 13);
    }

    /**
     * SMB2 NEGOTIATE request proposing only the oldest, universally-supported dialect (2.0.2) -
     * real SMB2+ servers reply to this with a valid SMB2 header even when a genuine client's
     * follow-up exchange (never sent here) would go on to negotiate something newer.
     */
    private static byte[] smbNegotiateRequest() {
        ByteArrayOutputStream out = new ByteArrayOutputStream();

        // SMB2 header (64 bytes)
        writeBytes(out, 0xFE, 'S', 'M', 'B'); // ProtocolId
        writeLeShort(out, 64); // StructureSize
        writeLeShort(out, 0); // CreditCharge
        writeLeInt(out, 0); // Status
        writeLeShort(out, 0); // Command = NEGOTIATE
        writeLeShort(out, 1); // CreditRequest
        writeLeInt(out, 0); // Flags
        writeLeInt(out, 0); // NextCommand
        writeLeLong(out, 0); // MessageId
        writeLeInt(out, 0); // Reserved
        writeLeInt(out, 0); // TreeId
        writeLeLong(out, 0); // SessionId
        writeZeros(out, 16); // Signature

        // NEGOTIATE_REQUEST body (36-byte fixed part + one 2-byte dialect entry)
        writeLeShort(out, 36); // StructureSize
        writeLeShort(out, 1); // DialectCount
        writeLeShort(out, 0); // SecurityMode
        writeLeShort(out, 0); // Reserved
        writeLeInt(out, 0); // Capabilities
        writeZeros(out, 16); // ClientGuid
        writeLeLong(out, 0); // ClientStartTime/reserved (dialect-dependent; unused for 2.0.2-only)
        writeLeShort(out, 0x0202); // Dialects[0] = SMB 2.0.2

        return out.toByteArray();
    }

    /**
     * DCE/RPC BIND request against the well-known endpoint-mapper interface
     * (e1af8308-5d1f-11c9-91a4-08002b14a0fa v3.0) over NDR transfer syntax
     * (8a885d04-1ceb-11c9-9fe8-08002b104860 v2.0) - the exact interface/transfer-syntax pair
     * `rpcinfo`/nmap's msrpc-enum use just to confirm an endpoint mapper is listening, not to call
     * anything through it.
     */
    private static byte[] rpcBindRequest() {
        ByteArrayOutputStream out = new ByteArrayOutputStream();

        // Common PDU header (16 bytes)
        writeBytes(out, 5); // rpc_vers
        writeBytes(out, 0); // rpc_vers_minor
        writeBytes(out, 11); // PTYPE = bind
        writeBytes(out, 0x03); // pfc_flags = FIRST_FRAG | LAST_FRAG
        writeBytes(out, 0x10, 0x00, 0x00, 0x00); // packed_drep: little-endian, ASCII
        writeLeShort(out, 72); // frag_length (whole PDU, computed below)
        writeLeShort(out, 0); // auth_length
        writeLeInt(out, 1); // call_id

        // bind-specific body
        writeLeShort(out, 4280); // max_xmit_frag
        writeLeShort(out, 4280); // max_recv_frag
        writeLeInt(out, 0); // assoc_group_id
        writeBytes(out, 1); // n_context_elem
        writeBytes(out, 0); // reserved
        writeLeShort(out, 0); // reserved2

        // p_cont_elem[0]
        writeLeShort(out, 0); // context_id
        writeBytes(out, 1); // n_transfer_syn
        writeBytes(out, 0); // reserved

        // abstract_syntax: epmapper interface UUID (wire-format byte order), version 3.0
        writeBytes(
                out,
                0x08, 0x83, 0xaf, 0xe1, 0x1f, 0x5d, 0xc9, 0x11, 0x91, 0xa4, 0x08, 0x00, 0x2b, 0x14, 0xa0, 0xfa);
        writeLeShort(out, 3); // version
        writeLeShort(out, 0); // version_minor

        // transfer_syntax: NDR UUID (wire-format byte order), version 2.0
        writeBytes(
                out,
                0x04, 0x5d, 0x88, 0x8a, 0xeb, 0x1c, 0xc9, 0x11, 0x9f, 0xe8, 0x08, 0x00, 0x2b, 0x10, 0x48, 0x60);
        writeLeInt(out, 2); // version

        byte[] bytes = out.toByteArray();
        if (bytes.length != 72) {
            // Would mean a transcription error in the hand-built PDU above - frag_length (already
            // written at a fixed offset) would then no longer match the actual packet length.
            throw new IllegalStateException("RPC bind PDU length drifted from the hardcoded frag_length: " + bytes.length);
        }
        return bytes;
    }

    private static void writeBytes(ByteArrayOutputStream out, int... bytes) {
        for (int b : bytes) {
            out.write(b);
        }
    }

    private static void writeZeros(ByteArrayOutputStream out, int count) {
        for (int i = 0; i < count; i++) {
            out.write(0);
        }
    }

    private static void writeLeShort(ByteArrayOutputStream out, int value) {
        out.write(value & 0xFF);
        out.write((value >> 8) & 0xFF);
    }

    private static void writeLeInt(ByteArrayOutputStream out, int value) {
        out.write(value & 0xFF);
        out.write((value >> 8) & 0xFF);
        out.write((value >> 16) & 0xFF);
        out.write((value >> 24) & 0xFF);
    }

    private static void writeLeLong(ByteArrayOutputStream out, long value) {
        for (int i = 0; i < 8; i++) {
            out.write((int) ((value >> (8 * i)) & 0xFF));
        }
    }
}
