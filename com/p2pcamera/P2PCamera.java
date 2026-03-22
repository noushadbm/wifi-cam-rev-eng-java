package com.p2pcamera;

import java.io.*;
import java.net.*;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.file.*;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.*;
import java.util.logging.*;

/**
 * P2P Camera Client — Java 21
 *
 * Reverse-engineered PPPP/CS2 protocol client for YsxLite/TBBT cameras.
 * Supports LAN discovery, authentication, MJPEG video and G.711 audio streaming.
 *
 * Protocol flow:
 *   LanSearch → PunchPkt → P2PRdy → ConnectUser → ConnectUserAck (ticket)
 *   → VideoParamSet → StartVideo → MJPEG + G.711 audio stream
 */
public class P2PCamera {

    // ── PPPP message types ────────────────────────────────────────────────
    static final int MSG_LAN_SEARCH  = 0x30;
    static final int MSG_LAN_SEARCH_EXT = 0x32;
    static final int MSG_PUNCH_PKT   = 0x41;
    static final int MSG_PUNCH_TO    = 0x42;
    static final int MSG_ALIVE       = 0xE0;
    static final int MSG_ALIVE_ACK   = 0xE1;
    static final int MSG_DRW         = 0xD0;
    static final int MSG_DRW_ACK     = 0xD1;
    static final int MSG_CLOSE       = 0xF0;
    static final int P2P_MAGIC       = 0xF1;

    // ── Control commands (from datatypes.ts) ──────────────────────────────
    static final int CMD_CONNECT_USER     = 0x2010;
    static final int CMD_CONNECT_USER_ACK = 0x2011;
    static final int CMD_START_VIDEO      = 0x1030;
    static final int CMD_START_VIDEO_ACK  = 0x1031;
    static final int CMD_VIDEO_PARAM_SET  = 0x1830;
    static final int CMD_VIDEO_PARAM_ACK  = 0x1831;
    static final int CMD_DEV_STATUS       = 0x0810;
    static final int CMD_DEV_STATUS_ACK   = 0x0811;

    // ── ccDest table (from datatypes.ts) ──────────────────────────────────
    static final Map<Integer, Integer> CC_DEST = Map.of(
        CMD_CONNECT_USER,   0xff00,
        CMD_DEV_STATUS,     0x0000,
        CMD_START_VIDEO,    0x0000,
        CMD_VIDEO_PARAM_SET,0x0000
    );

    static final int START_CMD       = 0x110a;
    static final int P2P_LAN_PORT    = 32108;
    static final String BROADCAST_IP = "255.255.255.255";

    // ── Stream types ───────────────────────────────────────────────────────
    static final int STREAM_JPEG  = 0x03;
    static final int STREAM_AUDIO = 0x06;
    static final byte[] FRAME_HEADER = {0x55, (byte)0xaa, 0x15, (byte)0xa8};
    static final byte[] JPEG_HEADER  = {(byte)0xff, (byte)0xd8, (byte)0xff};

    private static final Logger log = Logger.getLogger(P2PCamera.class.getName());

    // ── Device record ──────────────────────────────────────────────────────
    record Device(String prefix, long serial, String checkCode, String uid,
                  InetAddress address, int port) {
        static Device fromPunchPkt(byte[] buf, InetAddress addr, int port) {
            String prefix    = new String(buf, 4, 8).stripTrailing().replace("\0", "");
            long   serial    = ByteBuffer.wrap(buf, 12, 4).getInt() & 0xFFFFFFFFL;
            String checkCode = new String(buf, 16, 6).stripTrailing().replace("\0", "");
            String uid       = "%s-%06d-%s".formatted(prefix, serial, checkCode);
            return new Device(prefix, serial, checkCode, uid, addr, port);
        }
    }

    // ── State ──────────────────────────────────────────────────────────────
    private final AtomicInteger outgoingCommandId = new AtomicInteger(0);
    private volatile byte[]     ticket            = new byte[4];

    // ═══════════════════════════════════════════════════════════════════════
    //  Packet builders
    // ═══════════════════════════════════════════════════════════════════════

    /** Build a standard 4-byte PPPP header + optional payload. */
    byte[] createP2PMessage(int type, byte[] payload) {
        int len = (payload != null) ? payload.length : 0;
        byte[] buf = new byte[4 + len];
        buf[0] = (byte) P2P_MAGIC;
        buf[1] = (byte) type;
        buf[2] = (byte) (len >> 8);
        buf[3] = (byte) (len & 0xff);
        if (payload != null) System.arraycopy(payload, 0, buf, 4, len);
        return buf;
    }

    byte[] createP2PMessage(int type) {
        return createP2PMessage(type, null);
    }

    /**
     * Build a control DRW packet — mirrors impl.ts makeDataReadWrite exactly.
     *
     * Layout:
     *   [0-1]  0xF1D0  MSG_DRW
     *   [2-3]  pkt_len - 4
     *   [4]    0xD1
     *   [5]    0x00    channel
     *   [6-7]  outgoingCommandId
     *   [8-9]  0x110a  START_CMD
     *   [10-11] command
     *   [12-13] u16_swap(payload_len)
     *   [14-15] ccDest[command]
     *   [16-19] ticket (4 bytes)
     *   [20+]  XqBytesEnc'd data
     */
    byte[] makeDataReadWrite(int command, byte[] data) {
        final int DRW_HEADER_LEN = 0x10;
        final int TOKEN_LEN      = 0x4;

        byte[] encoded = null;
        if (data != null && data.length > 4) {
            encoded = xqBytesEnc(data.clone(), data.length, 4);
        }

        int encodedLen  = (encoded != null) ? encoded.length : 0;
        int payloadLen  = TOKEN_LEN + encodedLen;
        int pktLen      = DRW_HEADER_LEN + payloadLen;

        byte[] buf = new byte[pktLen];
        ByteBuffer bb = ByteBuffer.wrap(buf).order(ByteOrder.BIG_ENDIAN);

        bb.putShort((short) 0xF1D0);                     // MSG_DRW
        bb.putShort((short) (pktLen - 4));               // payload length
        bb.put((byte) 0xD1);                             // DRW marker
        bb.put((byte) 0x00);                             // channel
        bb.putShort((short) outgoingCommandId.getAndIncrement()); // cmd id
        bb.putShort((short) START_CMD);                  // 0x110a
        bb.putShort((short) command);                    // e.g. 0x2010
        bb.putShort((short) u16Swap(payloadLen));        // swapped length
        bb.putShort((short) (int) CC_DEST.getOrDefault(command, 0x0000)); // dest
        bb.put(ticket, 0, 4);                            // ticket

        if (encoded != null) bb.put(encoded);

        return buf;
    }

    /** Swap bytes of a 16-bit value. */
    static int u16Swap(int v) {
        return ((v & 0xff) << 8) | ((v >> 8) & 0xff);
    }

    /**
     * XqBytesEnc — from func_replacements.js:
     * 1. XOR every byte with 0x01
     * 2. Rotate array LEFT by `rotate` positions
     */
    static byte[] xqBytesEnc(byte[] data, int length, int rotate) {
        byte[] newBuf = new byte[length];
        for (int i = 0; i < length; i++) {
            newBuf[i] = (byte) (data[i] ^ 1);
        }
        byte[] result = new byte[length];
        for (int i = 0; i < length - rotate; i++) result[i] = newBuf[i + rotate];
        for (int i = 0; i < rotate; i++) result[length - rotate + i] = newBuf[i];
        return result;
    }

    /**
     * XqBytesDec — inverse of XqBytesEnc:
     * 1. XOR every byte with 0x01
     * 2. Rotate array RIGHT by `rotate` positions
     */
    static byte[] xqBytesDec(byte[] data, int length, int rotate) {
        byte[] newBuf = new byte[length];
        for (int i = 0; i < length; i++) {
            newBuf[i] = (byte) (data[i] ^ 1);
        }
        byte[] result = new byte[length];
        for (int i = rotate; i < length; i++) result[i] = newBuf[i - rotate];
        for (int i = 0; i < rotate; i++) result[i] = newBuf[length - rotate + i];
        return result;
    }

    /**
     * Build a batched DRW ACK packet.
     * Acknowledges multiple packet IDs in one UDP packet.
     */
    static byte[] makeDrwAck(int streamByte, List<Integer> pktIds) {
        int itemCount = pktIds.size();
        int replyLen  = itemCount * 2 + 4;
        byte[] buf    = new byte[8 + itemCount * 2];
        ByteBuffer bb = ByteBuffer.wrap(buf).order(ByteOrder.BIG_ENDIAN);
        bb.putShort((short) 0xF1D1);       // MSG_DRW_ACK
        bb.putShort((short) replyLen);
        bb.put((byte) 0xD2);
        bb.put((byte) streamByte);
        bb.putShort((short) itemCount);
        for (int id : pktIds) bb.putShort((short) id);
        return buf;
    }

    // ═══════════════════════════════════════════════════════════════════════
    //  High-level commands
    // ═══════════════════════════════════════════════════════════════════════

    /**
     * ConnectUser (login) — CMD 0x2010
     * Payload: username(32 bytes) + password(128 bytes), XqBytesEnc'd
     */
    byte[] sendConnectUser(String username, String password) {
        byte[] buf = new byte[0x20 + 0x80];
        byte[] uBytes = username.getBytes();
        byte[] pBytes = password.getBytes();
        System.arraycopy(uBytes, 0, buf, 0,    Math.min(uBytes.length, 0x20));
        System.arraycopy(pBytes, 0, buf, 0x20, Math.min(pBytes.length, 0x80));
        return makeDataReadWrite(CMD_CONNECT_USER, buf);
    }

    /**
     * VideoParamSet — CMD 0x1830
     * Sets resolution before starting video stream.
     * resolution: 1=320x240, 2=640x480, 3/4=640x480
     */
    byte[] sendVideoParamSet(int resolution) {
        Map<Integer, byte[]> resMap = Map.of(
            1, new byte[]{1,0,0,0, 0,0,0,0},
            2, new byte[]{1,0,0,0, 2,0,0,0},
            3, new byte[]{1,0,0,0, 3,0,0,0},
            4, new byte[]{1,0,0,0, 4,0,0,0}
        );
        return makeDataReadWrite(CMD_VIDEO_PARAM_SET,
               resMap.getOrDefault(resolution, resMap.get(2)));
    }

    /** StartVideo — CMD 0x1030 */
    byte[] sendStartVideo() {
        return makeDataReadWrite(CMD_START_VIDEO, null);
    }

    // ═══════════════════════════════════════════════════════════════════════
    //  LAN Discovery
    // ═══════════════════════════════════════════════════════════════════════

    /**
     * Broadcast LAN search and collect responding cameras.
     * Returns list of discovered devices.
     */
    List<Device> discoverDevices(int timeoutMs) throws IOException {
        List<Device> devices = new ArrayList<>();
        Set<String> seen    = new HashSet<>();

        try (DatagramSocket sock = new DatagramSocket()) {
            sock.setBroadcast(true);
            sock.setSoTimeout(timeoutMs);

            InetAddress broadcast = InetAddress.getByName(BROADCAST_IP);
            byte[] search    = createP2PMessage(MSG_LAN_SEARCH);
            byte[] searchExt = createP2PMessage(MSG_LAN_SEARCH_EXT);

            sock.send(new DatagramPacket(search,    search.length,    broadcast, P2P_LAN_PORT));
            sock.send(new DatagramPacket(searchExt, searchExt.length, broadcast, P2P_LAN_PORT));

            byte[] buf = new byte[1024];
            DatagramPacket pkt = new DatagramPacket(buf, buf.length);

            while (true) {
                try {
                    sock.receive(pkt);
                    byte[] data = Arrays.copyOf(pkt.getData(), pkt.getLength());
                    if (data.length >= 4 && (data[0] & 0xff) == P2P_MAGIC
                            && (data[1] & 0xff) == MSG_PUNCH_PKT && data.length >= 22) {
                        Device dev = Device.fromPunchPkt(data, pkt.getAddress(), pkt.getPort());
                        if (!seen.contains(dev.uid())) {
                            seen.add(dev.uid());
                            devices.add(dev);
                            log.info("Found device: %s at %s".formatted(
                                     dev.uid(), dev.address().getHostAddress()));
                        }
                    }
                } catch (SocketTimeoutException e) {
                    break;
                }
            }
        }
        return devices;
    }

    // ═══════════════════════════════════════════════════════════════════════
    //  Streaming
    // ═══════════════════════════════════════════════════════════════════════

    /**
     * Full stream session: handshake → login → video+audio → save files.
     *
     * @param device     Target camera device
     * @param username   Camera username (default: "admin")
     * @param password   Camera password (e.g. "WuZfSZHC")
     * @param videoFile  Output MJPEG file path
     * @param audioFile  Output raw G.711 audio file path
     * @param durationSec  How many seconds to record
     */
    void streamVideo(Device device, String username, String password,
                     Path videoFile, Path audioFile, int durationSec)
            throws IOException, InterruptedException {

        outgoingCommandId.set(0);
        ticket = new byte[4];

        try (DatagramSocket sock = new DatagramSocket()) {
            sock.setSoTimeout(2000);
            InetSocketAddress camAddr = new InetSocketAddress(device.address(), device.port());

            // ── Handshake ───────────────────────────────────────────────
            doHandshake(sock, device, camAddr);

            // ── Login ───────────────────────────────────────────────────
            sock.setSoTimeout(5000);
            byte[] loginPkt = sendConnectUser(username, password);
            send(sock, loginPkt, camAddr);
            log.info("[>] Sent ConnectUser");

            if (!waitForLogin(sock, camAddr)) {
                log.severe("[!] Login failed");
                return;
            }
            log.info("[+] LOGIN OK! Ticket: " + bytesToHex(ticket));

            // ── Start stream ────────────────────────────────────────────
            sock.setSoTimeout(50);   // fast polling for streaming
            send(sock, sendVideoParamSet(2), camAddr);
            send(sock, sendStartVideo(), camAddr);
            log.info("[>] Sent VideoParamSet + StartVideo");

            // ── Receive stream ──────────────────────────────────────────
            log.info("[*] Recording %ds → video=%s audio=%s"
                     .formatted(durationSec, videoFile, audioFile));

            receiveStream(sock, camAddr, videoFile, audioFile, durationSec);
        }
    }

    // ── Handshake ──────────────────────────────────────────────────────────

    private void doHandshake(DatagramSocket sock, Device device,
                             InetSocketAddress camAddr) throws IOException {

        sock.setBroadcast(true);
        byte[] lanSearch = createP2PMessage(MSG_LAN_SEARCH);
        InetAddress broadcast = InetAddress.getByName(BROADCAST_IP);
        send(sock, lanSearch, new InetSocketAddress(broadcast, P2P_LAN_PORT));
        log.fine("[>] MSG_LAN_SEARCH");

        // Wait for punch reply
        byte[] buf = new byte[1024];
        DatagramPacket pkt = new DatagramPacket(buf, buf.length);
        try {
            sock.receive(pkt);
            log.fine("[<] Punch reply received");
        } catch (SocketTimeoutException e) {
            log.warning("[!] No punch reply");
        }
        sock.setBroadcast(false);

        // Send P2PRdy (MSG_PUNCH_TO) with UID
        byte[] punchPayload = buildPunchPayload(device);
        send(sock, createP2PMessage(MSG_PUNCH_TO, punchPayload), camAddr);
        log.fine("[>] MSG_PUNCH_TO");

        // ALIVE handshake
        send(sock, createP2PMessage(MSG_ALIVE), camAddr);
        long deadline = System.currentTimeMillis() + 2000;
        while (System.currentTimeMillis() < deadline) {
            try {
                sock.receive(pkt);
                byte[] data = Arrays.copyOf(pkt.getData(), pkt.getLength());
                if ((data[1] & 0xff) == MSG_ALIVE) {
                    send(sock, createP2PMessage(MSG_ALIVE_ACK), camAddr);
                }
            } catch (SocketTimeoutException e) {
                break;
            }
        }
    }

    private byte[] buildPunchPayload(Device device) {
        byte[] payload = new byte[20];
        byte[] prefix  = device.prefix().getBytes();
        byte[] check   = device.checkCode().getBytes();
        System.arraycopy(prefix, 0, payload, 0,  Math.min(prefix.length, 8));
        ByteBuffer.wrap(payload, 8, 4).order(ByteOrder.BIG_ENDIAN)
                  .putInt((int) device.serial());
        System.arraycopy(check,  0, payload, 12, Math.min(check.length, 8));
        return payload;
    }

    // ── Login wait ─────────────────────────────────────────────────────────

    private boolean waitForLogin(DatagramSocket sock,
                                 InetSocketAddress camAddr) throws IOException {
        byte[] buf = new byte[4096];
        DatagramPacket pkt = new DatagramPacket(buf, buf.length);
        long deadline = System.currentTimeMillis() + 5000;

        while (System.currentTimeMillis() < deadline) {
            try {
                sock.receive(pkt);
                byte[] data = Arrays.copyOf(pkt.getData(), pkt.getLength());
                int msgType = data[1] & 0xff;

                if (msgType == MSG_ALIVE) {
                    send(sock, createP2PMessage(MSG_ALIVE_ACK), camAddr);
                    continue;
                }
                if (msgType == MSG_DRW_ACK) continue;
                if (msgType != MSG_DRW)     continue;

                int pktId      = ((data[6] & 0xff) << 8) | (data[7] & 0xff);
                int streamByte = data[5] & 0xff;
                byte[] drwPayload = Arrays.copyOfRange(data, 8, data.length);
                int cmd = ((drwPayload[2] & 0xff) << 8) | (drwPayload[3] & 0xff);

                // ACK it
                send(sock, makeDrwAck(streamByte, List.of(pktId)), camAddr);

                if (cmd == CMD_CONNECT_USER_ACK) {
                    // Decode payload and extract ticket
                    int rawPayloadLen = ((drwPayload[4] & 0xff) << 8) | (drwPayload[5] & 0xff);
                    int payloadLen    = u16Swap(rawPayloadLen);
                    int encLen        = payloadLen - 4;
                    if (data.length >= 20 + encLen && encLen > 0) {
                        byte[] encoded = Arrays.copyOfRange(data, 20, 20 + encLen);
                        byte[] decoded = xqBytesDec(encoded, encLen, 4);
                        // Ticket at offset 0x18 from packet start = decoded[4]
                        ticket = Arrays.copyOfRange(decoded, 4, 8);
                    }
                    return true;
                }
            } catch (SocketTimeoutException e) {
                break;
            }
        }
        return false;
    }

    // ── Stream receive loop ────────────────────────────────────────────────

    private void receiveStream(DatagramSocket sock, InetSocketAddress camAddr,
                               Path videoFile, Path audioFile,
                               int durationSec) throws IOException {

        // Stats
        AtomicLong frameCount  = new AtomicLong();
        AtomicLong audioChunks = new AtomicLong();
        AtomicLong videoBytes  = new AtomicLong();
        AtomicLong audioBytes  = new AtomicLong();

        // Pending ACK queues (by stream byte)
        List<Integer> pendingDataAcks    = new ArrayList<>();
        List<Integer> pendingControlAcks = new ArrayList<>();
        long lastAckSent  = System.currentTimeMillis();
        long lastAlive    = System.currentTimeMillis();
        long lastLog      = System.currentTimeMillis();
        long startTime    = System.currentTimeMillis();
        long endTime      = startTime + durationSec * 1000L;

        ByteArrayOutputStream currentJpeg = new ByteArrayOutputStream();
        boolean              jpegStarted  = false;
        boolean              firstAudio   = true;

        byte[] buf = new byte[65535];
        DatagramPacket pkt = new DatagramPacket(buf, buf.length);

        try (OutputStream vOut = Files.newOutputStream(videoFile);
             OutputStream aOut = Files.newOutputStream(audioFile)) {

            while (System.currentTimeMillis() < endTime) {
                long now = System.currentTimeMillis();

                // Keepalive every 500ms
                if (now - lastAlive > 500) {
                    send(sock, createP2PMessage(MSG_ALIVE), camAddr);
                    lastAlive = now;
                }

                // Flush ACKs every 10ms (batched, like real client)
                if (now - lastAckSent > 10) {
                    flushAcks(sock, camAddr, pendingDataAcks, 0x01);
                    flushAcks(sock, camAddr, pendingControlAcks, 0x00);
                    lastAckSent = now;
                }

                // Progress log every 2s
                if (now - lastLog > 2000) {
                    log.info("[*] video=%d frames %d bytes | audio=%d chunks %d bytes | %.1fs"
                             .formatted(frameCount.get(), videoBytes.get(),
                                        audioChunks.get(), audioBytes.get(),
                                        (now - startTime) / 1000.0));
                    lastLog = now;
                }

                // Receive packet
                try {
                    pkt.setLength(buf.length);
                    sock.receive(pkt);
                } catch (SocketTimeoutException e) {
                    continue;
                }

                byte[] data = Arrays.copyOf(pkt.getData(), pkt.getLength());
                if (data.length < 4) continue;
                int msgType = data[1] & 0xff;

                if (msgType == MSG_ALIVE) {
                    send(sock, createP2PMessage(MSG_ALIVE_ACK), camAddr);
                    continue;
                }
                if (msgType == MSG_DRW_ACK) continue;
                if (msgType != MSG_DRW)     continue;

                int pktId      = ((data[6] & 0xff) << 8) | (data[7] & 0xff);
                int streamByte = data[5] & 0xff;
                byte[] drwPayload = Arrays.copyOfRange(data, 8, data.length);

                if (streamByte == 0x00) {
                    // Control packet
                    pendingControlAcks.add(pktId);
                    int cmd = ((drwPayload[2] & 0xff) << 8) | (drwPayload[3] & 0xff);
                    log.fine("[<] Control cmd=0x%04x".formatted(cmd));
                    flushAcks(sock, camAddr, pendingControlAcks, 0x00);
                    continue;
                }

                // Data packet
                pendingDataAcks.add(pktId);
                if (drwPayload.length < 4) continue;

                if (startsWith(drwPayload, FRAME_HEADER)) {
                    int streamType = drwPayload[4] & 0xff;

                    if (streamType == STREAM_JPEG) {
                        // Save previous complete frame
                        if (jpegStarted && currentJpeg.size() > 0) {
                            byte[] frame = currentJpeg.toByteArray();
                            vOut.write(frame);
                            vOut.flush();
                            frameCount.incrementAndGet();
                            videoBytes.addAndGet(frame.length);
                        }
                        // Start new frame (skip 32-byte stream_head_t)
                        currentJpeg.reset();
                        if (drwPayload.length > 32) {
                            currentJpeg.write(drwPayload, 32, drwPayload.length - 32);
                        }
                        jpegStarted = true;

                    } else if (streamType == STREAM_AUDIO) {
                        // Audio: length at drwPayload[16:18] LE, data at drwPayload[32:]
                        if (drwPayload.length >= 18) {
                            int audioLen = (drwPayload[16] & 0xff)
                                         | ((drwPayload[17] & 0xff) << 8);
                            if (drwPayload.length >= 32 + audioLen && audioLen > 0) {
                                byte[] audioData = Arrays.copyOfRange(
                                    drwPayload, 32, 32 + audioLen);
                                if (firstAudio) {
                                    log.info("[*] First audio chunk: %d bytes, hex=%s"
                                             .formatted(audioLen, bytesToHex(
                                                Arrays.copyOf(audioData, Math.min(8, audioLen)))));
                                    firstAudio = false;
                                }
                                aOut.write(audioData);
                                aOut.flush();
                                audioChunks.incrementAndGet();
                                audioBytes.addAndGet(audioLen);
                            }
                        }
                    } else {
                        log.fine("[<] Unknown stream_type=0x%02x".formatted(streamType));
                    }

                } else if (startsWith(drwPayload, JPEG_HEADER)) {
                    // Unframed JPEG start
                    if (jpegStarted && currentJpeg.size() > 0) {
                        byte[] frame = currentJpeg.toByteArray();
                        vOut.write(frame);
                        vOut.flush();
                        frameCount.incrementAndGet();
                        videoBytes.addAndGet(frame.length);
                    }
                    currentJpeg.reset();
                    currentJpeg.write(drwPayload);
                    jpegStarted = true;

                } else if (jpegStarted) {
                    // Continuation chunk
                    currentJpeg.write(drwPayload);
                }
            } // end while

            // Save last frame
            if (jpegStarted && currentJpeg.size() > 0) {
                byte[] frame = currentJpeg.toByteArray();
                vOut.write(frame);
                frameCount.incrementAndGet();
                videoBytes.addAndGet(frame.length);
            }

            // Flush remaining ACKs
            flushAcks(sock, camAddr, pendingDataAcks,    0x01);
            flushAcks(sock, camAddr, pendingControlAcks, 0x00);

        } // end try-with-resources

        // ── Summary ──
        long elapsed = System.currentTimeMillis() - startTime;
        double bps   = audioBytes.get() / (elapsed / 1000.0);
        log.info("\n[*] Done: %d video frames (%d bytes) | %d audio chunks (%d bytes)"
                 .formatted(frameCount.get(), videoBytes.get(),
                             audioChunks.get(), audioBytes.get()));
        log.info("[*] Avg audio bitrate: %.0f bytes/sec".formatted(bps));

        String fmt = detectAudioFormat(bps);
        log.info("[*] Audio format: %s".formatted(fmt));
        log.info("[*] Play video:  ffplay -f mjpeg %s".formatted(videoFile));
        log.info("[*] Play audio:  ffplay -f %s -ar 8000 -ac 1 %s".formatted(fmt, audioFile));
        log.info("[*] Mux A+V:     ffmpeg -f mjpeg -i %s -f %s -ar 8000 -ac 1 -i %s "
                 + "-c:v libx264 -c:a aac output_av.mp4"
                 .formatted(videoFile, fmt, audioFile));
    }

    // ── Helpers ────────────────────────────────────────────────────────────

    private void flushAcks(DatagramSocket sock, InetSocketAddress camAddr,
                           List<Integer> pending, int streamByte) throws IOException {
        if (pending.isEmpty()) return;
        send(sock, makeDrwAck(streamByte, new ArrayList<>(pending)), camAddr);
        pending.clear();
    }

    private void send(DatagramSocket sock, byte[] data,
                      InetSocketAddress addr) throws IOException {
        sock.send(new DatagramPacket(data, data.length, addr));
    }

    private static boolean startsWith(byte[] data, byte[] prefix) {
        if (data.length < prefix.length) return false;
        for (int i = 0; i < prefix.length; i++) {
            if (data[i] != prefix[i]) return false;
        }
        return true;
    }

    private static String bytesToHex(byte[] b) {
        StringBuilder sb = new StringBuilder();
        for (byte x : b) sb.append("%02x".formatted(x & 0xff));
        return sb.toString();
    }

    private static String detectAudioFormat(double bps) {
        if (bps >= 7000 && bps <= 9000)   return "mulaw";
        if (bps >= 3500 && bps <= 4500)   return "adpcm_ima_wav";
        if (bps >= 15000 && bps <= 17000) return "s16le";
        return "mulaw"; // default
    }

    // ═══════════════════════════════════════════════════════════════════════
    //  Main
    // ═══════════════════════════════════════════════════════════════════════

    public static void main(String[] args) throws Exception {
        // Configure logging
        Logger root = Logger.getLogger("");
        root.setLevel(Level.INFO);
        for (var h : root.getHandlers()) {
            h.setFormatter(new SimpleFormatter() {
                @Override public String format(LogRecord r) {
                    return r.getMessage() + "\n";
                }
            });
        }

        // Parse args
        String password   = "WuZfSZHC";
        String username   = "admin";
        int    duration   = 30;
        Path   videoFile  = Path.of("stream.mjpeg");
        Path   audioFile  = Path.of("stream.raw");

        for (int i = 0; i < args.length; i++) {
            switch (args[i]) {
                case "--password" -> password  = args[++i];
                case "--username" -> username  = args[++i];
                case "--duration" -> duration  = Integer.parseInt(args[++i]);
                case "--video"    -> videoFile = Path.of(args[++i]);
                case "--audio"    -> audioFile = Path.of(args[++i]);
            }
        }

        System.out.println("[*] P2P Camera Client — Java 21");
        System.out.println("[*] Discovering cameras on LAN...\n");

        P2PCamera client = new P2PCamera();
        List<Device> devices = client.discoverDevices(1000);

        if (devices.isEmpty()) {
            System.out.println("[!] No devices found.");
            return;
        }

        System.out.println("[*] Found %d device(s)\n".formatted(devices.size()));

        // Stream from first discovered device
        Device device = devices.getFirst();
        System.out.println("[*] Streaming from: %s at %s".formatted(
                           device.uid(), device.address().getHostAddress()));

        client.streamVideo(device, username, password, videoFile, audioFile, duration);
    }
}
