package local.knowvault.docparser;

import java.io.InputStream;
import java.io.OutputStream;
import java.nio.channels.Channels;
import java.nio.channels.SocketChannel;
import java.net.UnixDomainSocketAddress;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.regex.Pattern;

/**
 * Production parser process for dispatcher v2.
 *
 * <p>This is intentionally one-shot. The JVM registers one parser role on one
 * Unix socket, claims at most one lease, transfers one result/outcome, closes
 * the socket and returns. An external supervisor owns the fresh PID namespace,
 * cgroup and restart for the next source object. Keeping the process lifetime
 * here finite is part of the publication boundary: a successful result cannot
 * be followed by a second document handled by the same parser state.</p>
 */
final class OneShotParserWorker {
    private OneShotParserWorker() {
    }

    static void run(String socketURI, String workerId, String parserType, String supervisorHandoffId) {
        Startup startup = Startup.validate(socketURI, workerId, parserType, supervisorHandoffId);
        UnixDomainSocketAddress address = UnixDomainSocketAddress.of(startup.socketPath());

        try (SocketChannel channel = SocketChannel.open(address);
             InputStream input = Channels.newInputStream(channel);
             OutputStream output = Channels.newOutputStream(channel)) {
            LeaseGate leaseGate = new LeaseGate();
            DispatcherProtocolV2.writeFrame(output, DispatcherProtocolV2.REGISTER,
                    DispatcherProtocolV2.registration(startup.workerId(), startup.parserType(),
                            Main.artifactHash(), startup.sandboxProfileRevision(),
                            startup.observationProfileRevision(), startup.supervisorHandoffId()),
                    DispatcherProtocolV2.MAX_CONTROL_FRAME_BYTES);
            DispatcherProtocolV2.Frame accepted = DispatcherProtocolV2.readFrame(input,
                    DispatcherProtocolV2.MAX_CONTROL_FRAME_BYTES);
            if (accepted.kind() != DispatcherProtocolV2.REGISTER_ACCEPTED
                    || !DispatcherProtocolV2.REGISTER_ACCEPTED_BODY.equals(
                    new String(accepted.body(), StandardCharsets.UTF_8))) {
                throw new WorkerException("REGISTRATION_REJECTED");
            }

            DispatcherProtocolV2.Frame offeredFrame = DispatcherProtocolV2.readFrame(input,
                    DispatcherProtocolV2.MAX_CONTROL_FRAME_BYTES);
            if (offeredFrame.kind() != DispatcherProtocolV2.LEASE) {
                throw new WorkerException("WIRE_REJECTED");
            }
            DispatcherProtocolV2.Lease offered = DispatcherProtocolV2.Lease.parse(offeredFrame.body());
            leaseGate.accept();
            validateOffered(startup, offered);

            DispatcherProtocolV2.writeFrame(output, DispatcherProtocolV2.CLAIM,
                    DispatcherProtocolV2.claim(offered.leaseId(), startup.workerId()),
                    DispatcherProtocolV2.MAX_CONTROL_FRAME_BYTES);

            DispatcherProtocolV2.Frame transferredFrame = DispatcherProtocolV2.readFrame(input,
                    DispatcherProtocolV2.MAX_CONTROL_FRAME_BYTES);
            if (transferredFrame.kind() != DispatcherProtocolV2.LEASE) {
                throw new WorkerException("WIRE_REJECTED");
            }
            DispatcherProtocolV2.Lease transferred = DispatcherProtocolV2.Lease.parse(transferredFrame.body());
            validateTransferred(startup, offered, transferred);

            DispatcherProtocolV2.Payload payload = DispatcherProtocolV2.readPayload(input,
                    Math.min(transferred.parserRequest().maxInputBytes(), DispatcherProtocolV2.MAX_INPUT_BYTES));
            DispatcherProtocolV2.PayloadHeader header = DispatcherProtocolV2.PayloadHeader.parse(payload.header());
            if (!transferred.leaseId().equals(header.leaseId())) {
                throw new WorkerException("WIRE_REJECTED");
            }

            // Bytes have crossed the dispatcher handoff. From this point a
            // parser contradiction or failure is a quarantine, not a retry.
            reportOne(output, transferred, startup.workerId(), header, payload.body());
        } catch (WorkerException e) {
            throw e;
        } catch (Throwable e) {
            // No exception detail, path, source bytes or parser diagnostics can
            // cross this boundary. Main turns this fixed code into the only
            // stderr signal for a pre-transfer startup/wire failure.
            throw new WorkerException("DISPATCHER_ONCE_FAILED");
        }
    }

    private static void validateOffered(Startup startup, DispatcherProtocolV2.Lease lease) {
        if (!"OFFERED".equals(lease.state())
                || !startup.workerId().equals(lease.workerId())) {
            throw new WorkerException("LEASE_REJECTED");
        }
        lease.parserRequest().validateForRole(startup.parserType());
        validateLeaseWindow(lease);
    }

    private static void validateTransferred(Startup startup,
                                            DispatcherProtocolV2.Lease offered,
                                            DispatcherProtocolV2.Lease transferred) {
        if (!"TRANSFERRED".equals(transferred.state())
                || !offered.leaseId().equals(transferred.leaseId())
                || !offered.jobId().equals(transferred.jobId())
                || !offered.workerId().equals(transferred.workerId())
                || !offered.parserRequest().equals(transferred.parserRequest())
                || !offered.issuedAt().equals(transferred.issuedAt())
                || !offered.expiresAt().equals(transferred.expiresAt())
                || offered.attempt() != transferred.attempt()) {
            throw new WorkerException("LEASE_REJECTED");
        }
        if (!startup.workerId().equals(transferred.workerId())) {
            throw new WorkerException("LEASE_REJECTED");
        }
        transferred.parserRequest().validateForRole(startup.parserType());
        validateLeaseWindow(transferred);
    }

    private static void validateLeaseWindow(DispatcherProtocolV2.Lease lease) {
        try {
            Instant issued = Instant.parse(lease.issuedAt());
            Instant expires = Instant.parse(lease.expiresAt());
            if (!expires.isAfter(issued) || !expires.isAfter(Instant.now())) {
                throw new WorkerException("LEASE_REJECTED");
            }
        } catch (java.time.DateTimeException e) {
            throw new WorkerException("LEASE_REJECTED");
        }
    }

    private static void reportOne(OutputStream output, DispatcherProtocolV2.Lease lease,
                                  String workerId, DispatcherProtocolV2.PayloadHeader header,
                                  byte[] document) {
        DispatcherProtocolV2.ParserRequest request = lease.parserRequest();
        try {
            byte[] result = Main.observeForDispatcher(request, document);
            if (result.length < 1 || result.length > request.maxOutputBytes()
                    || result.length > DispatcherProtocolV2.MAX_OUTPUT_BYTES) {
                throw new WorkerException("OUTPUT_SIZE_REJECTED");
            }
            String digest = sha256(result);
            DispatcherProtocolV2.writeResult(output, result, request.maxOutputBytes());
            byte[] outcome = DispatcherProtocolV2.outcome(lease, workerId, header, true, digest);
            DispatcherProtocolV2.writeFrame(output, DispatcherProtocolV2.OUTCOME, outcome,
                    DispatcherProtocolV2.MAX_CONTROL_FRAME_BYTES);
        } catch (WorkerException e) {
            byte[] outcome = DispatcherProtocolV2.outcome(lease, workerId, header, false, null);
            DispatcherProtocolV2.writeFrame(output, DispatcherProtocolV2.OUTCOME, outcome,
                    DispatcherProtocolV2.MAX_CONTROL_FRAME_BYTES);
        } catch (Throwable e) {
            // A parser/library failure after transfer has one terminal outcome.
            // The source and the throwable are deliberately not represented.
            byte[] outcome = DispatcherProtocolV2.outcome(lease, workerId, header, false, null);
            DispatcherProtocolV2.writeFrame(output, DispatcherProtocolV2.OUTCOME, outcome,
                    DispatcherProtocolV2.MAX_CONTROL_FRAME_BYTES);
        }
    }

    private static String sha256(byte[] bytes) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(bytes);
            StringBuilder result = new StringBuilder(71).append("sha256:");
            for (byte value : digest) {
                result.append(Character.forDigit((value >>> 4) & 0x0f, 16));
                result.append(Character.forDigit(value & 0x0f, 16));
            }
            return result.toString();
        } catch (NoSuchAlgorithmException e) {
            throw new WorkerException("DISPATCHER_ONCE_FAILED");
        }
    }

    static Startup startup(String socketURI, String workerId, String parserType,
                           String supervisorHandoffId) {
        return Startup.validate(socketURI, workerId, parserType, supervisorHandoffId);
    }

    /**
     * A physical one-shot guard: there is no legal second offer in this JVM.
     * Keeping the guard next to the exchange makes an accidental read loop a
     * deterministic lease rejection even before the dispatcher closes the peer.
     */
    static final class LeaseGate {
        private boolean accepted;

        void accept() {
            if (accepted) {
                throw new WorkerException("LEASE_REJECTED");
            }
            accepted = true;
        }
    }

    record Startup(String socketPath, String workerId, String parserType,
                   String supervisorHandoffId) {
        private static final Pattern SUPERVISOR_HANDOFF_ID =
                Pattern.compile("^[A-Za-z0-9][A-Za-z0-9._-]{31,127}$");

        static Startup validate(String socketURI, String workerId, String parserType,
                                String supervisorHandoffId) {
            if (socketURI == null || !socketURI.startsWith("unix://")) {
                throw new WorkerException("BAD_REQUEST");
            }
            String path = socketURI.substring("unix://".length());
            if (path.length() < 2 || path.getBytes(StandardCharsets.UTF_8).length > 100
                    || path.charAt(0) != '/'
                    || path.contains("\\") || path.contains("?") || path.contains("#")
                    || path.indexOf('\0') >= 0 || hasDotSegment(path)) {
                throw new WorkerException("BAD_REQUEST");
            }
            if (workerId == null || workerId.isEmpty()
                    || workerId.getBytes(StandardCharsets.UTF_8).length > 128
                    || hasUnsafeIDChar(workerId)) {
                throw new WorkerException("BAD_REQUEST");
            }
            if (!"OFFICE".equals(parserType) && !"PDF".equals(parserType)) {
                throw new WorkerException("BAD_REQUEST");
            }
            if (supervisorHandoffId == null || !SUPERVISOR_HANDOFF_ID.matcher(supervisorHandoffId).matches()) {
                throw new WorkerException("BAD_REQUEST");
            }
            return new Startup(path, workerId, parserType, supervisorHandoffId);
        }

        String sandboxProfileRevision() {
            return "document-parser-sandbox-v3";
        }

        String observationProfileRevision() {
            return "OFFICE".equals(parserType) ? "office-obs-v1" : "pdf-obs-v1";
        }

        private static boolean hasDotSegment(String path) {
            int start = 0;
            while (start < path.length()) {
                int end = path.indexOf('/', start);
                if (end < 0) {
                    end = path.length();
                }
                if (end - start == 1 && path.charAt(start) == '.') {
                    return true;
                }
                if (end - start == 2 && path.charAt(start) == '.' && path.charAt(start + 1) == '.') {
                    return true;
                }
                start = end + 1;
            }
            return false;
        }

        private static boolean hasUnsafeIDChar(String value) {
            for (int index = 0; index < value.length(); index++) {
                char current = value.charAt(index);
                if (Character.isWhitespace(current) || Character.isISOControl(current)) {
                    return true;
                }
            }
            return false;
        }
    }
}
