package com.vpnengine.nativecore

import android.util.Log
import java.net.InetAddress
import java.nio.ByteBuffer
import java.nio.ByteOrder

/**
 * IpPacketParser — User-space IP/TCP/UDP packet parser for TUN-to-SOCKS5 bridge.
 *
 * Parses raw IP packets read from the Android VpnService TUN interface,
 * extracting headers and payloads for TCP/UDP connection tracking and
 * SOCKS5 proxy routing.
 *
 * This is essential for RECEIVER (Full Tunneling) mode because:
 *   1. Android VpnService captures ALL device traffic as raw IP packets via TUN
 *   2. Without root, we cannot use iptables NAT — we must process packets in user space
 *   3. Each TCP packet must be parsed, tracked, and routed through a SOCKS5 proxy
 *      connection to the Sender/Exit Node via ZeroTier secure sockets
 *
 * IP Packet Structure (IPv4):
 *   ┌──────────┬──────────┬─────────────┬──────────┬──────────┐
 *   │ Version  │  IHL     │ Total Length │ Protocol │ ...      │
 *   │ (4 bits) │ (4 bits) │ (16 bits)    │ (8 bits) │          │
 *   └──────────┴──────────┴─────────────┴──────────┴──────────┘
 *
 * TCP Header:
 *   ┌──────────┬──────────┬──────────┬──────────┬──────┬───────┐
 *   │ Src Port │ Dst Port │ Seq Num  │ Ack Num  │Flags │ ...   │
 *   │ (16 bit) │ (16 bit) │ (32 bit) │ (32 bit) │(9bit)│       │
 *   └──────────┴──────────┴──────────┴──────────┴──────┴───────┘
 *
 * UDP Header:
 *   ┌──────────┬──────────┬──────────┬──────────┐
 *   │ Src Port │ Dst Port │ Length   │ Checksum │
 *   │ (16 bit) │ (16 bit) │ (16 bit) │ (16 bit) │
 *   └──────────┴──────────┴──────────┴──────────┘
 */
object IpPacketParser {

    private const val TAG = "IpPacketParser"

    // ── IP Protocol Constants ─────────────────────────────────────────────
    const val PROTOCOL_TCP = 6
    const val PROTOCOL_UDP = 17
    const val PROTOCOL_ICMP = 1

    // ── TCP Flag Bits ────────────────────────────────────────────────────
    const val TCP_FLAG_FIN = 0x01
    const val TCP_FLAG_SYN = 0x02
    const val TCP_FLAG_RST = 0x04
    const val TCP_FLAG_PSH = 0x08
    const val TCP_FLAG_ACK = 0x10
    const val TCP_FLAG_URG = 0x20

    // ── DNS Port ─────────────────────────────────────────────────────────
    const val PORT_DNS = 53

    /**
     * Parsed IPv4 packet with transport layer details.
     *
     * @param version IP version (4 or 6)
     * @param protocol Transport protocol (TCP/UDP/ICMP)
     * @param sourceAddress Source IP address string
     * @param destinationAddress Destination IP address string
     * @param sourcePort Source port (TCP/UDP only, 0 for ICMP)
     * @param destinationPort Destination port (TCP/UDP only, 0 for ICMP)
     * @param tcpFlags TCP flags (TCP only, 0 for UDP/ICMP)
     * @param tcpSeqNumber TCP sequence number
     * @param tcpAckNumber TCP acknowledgment number
     * @param tcpWindowSize TCP window size
     * @param payloadOffset Offset where payload starts in the raw packet
     * @param payloadLength Length of the transport payload
     * @param totalLength Total IP packet length
     * @param headerLength IP header length in bytes
     * @param tcpHeaderLength TCP header length in bytes (TCP only)
     * @param rawPacket The complete raw IP packet bytes
     * @param ttl Time-to-live
     * @param identification IP identification field for fragmentation
     */
    data class ParsedPacket(
        val version: Int,
        val protocol: Int,
        val sourceAddress: String,
        val destinationAddress: String,
        val sourcePort: Int,
        val destinationPort: Int,
        val tcpFlags: Int,
        val tcpSeqNumber: Long,
        val tcpAckNumber: Long,
        val tcpWindowSize: Int,
        val payloadOffset: Int,
        val payloadLength: Int,
        val totalLength: Int,
        val headerLength: Int,
        val tcpHeaderLength: Int,
        val rawPacket: ByteArray,
        val ttl: Int,
        val identification: Int
    ) {
        /** Unique 4-tuple key for TCP/UDP connection tracking */
        val connectionKey: String
            get() = "$sourceAddress:$sourcePort->$destinationAddress:$destinationPort"

        /** Whether this is a TCP SYN packet (new connection) */
        val isSyn: Boolean get() = (tcpFlags and TCP_FLAG_SYN) != 0 && (tcpFlags and TCP_FLAG_ACK) == 0

        /** Whether this is a TCP SYN-ACK packet */
        val isSynAck: Boolean get() = (tcpFlags and TCP_FLAG_SYN) != 0 && (tcpFlags and TCP_FLAG_ACK) != 0

        /** Whether this is a TCP FIN packet */
        val isFin: Boolean get() = (tcpFlags and TCP_FLAG_FIN) != 0

        /** Whether this is a TCP RST packet */
        val isRst: Boolean get() = (tcpFlags and TCP_FLAG_RST) != 0

        /** Whether this is a TCP ACK packet */
        val isAck: Boolean get() = (tcpFlags and TCP_FLAG_ACK) != 0

        /** Whether this is a DNS query */
        val isDns: Boolean get() = protocol == PROTOCOL_UDP && destinationPort == PORT_DNS

        /** TCP payload data (empty if not TCP or no payload) */
        val tcpPayload: ByteArray
            get() = if (protocol == PROTOCOL_TCP && payloadLength > 0) {
                rawPacket.copyOfRange(payloadOffset, payloadOffset + payloadLength)
            } else {
                ByteArray(0)
            }

        /** UDP payload data */
        val udpPayload: ByteArray
            get() = if (protocol == PROTOCOL_UDP && payloadLength > 0) {
                rawPacket.copyOfRange(payloadOffset, payloadOffset + payloadLength)
            } else {
                ByteArray(0)
            }
    }

    /**
     * Parse a raw IP packet from the TUN interface.
     *
     * @param packet Raw IP packet bytes (including IP header)
     * @param length Number of valid bytes in the packet array
     * @return ParsedPacket with extracted fields, or null if the packet is invalid
     */
    fun parse(packet: ByteArray, length: Int): ParsedPacket? {
        if (length < 20) {
            Log.w(TAG, "Packet too short: $length bytes")
            return null
        }

        try {
            val buf = ByteBuffer.wrap(packet, 0, length)
            buf.order(ByteOrder.BIG_ENDIAN)

            // ── IPv4 Header ────────────────────────────────────────────
            val versionIhl = buf.get().toInt() and 0xFF
            val version = (versionIhl shr 4) and 0x0F
            val ihl = (versionIhl and 0x0F) * 4  // Header length in bytes

            if (version != 4) {
                // IPv6 not fully supported in this simplified parser
                if (version == 6 && length >= 40) {
                    return parseIPv6(packet, length)
                }
                return null
            }

            if (ihl < 20 || ihl > length) {
                Log.w(TAG, "Invalid IHL: $ihl (len=$length)")
                return null
            }

            buf.get()  // TOS / DSCP
            val totalLength = buf.short.toInt() and 0xFFFF
            val identification = buf.short.toInt() and 0xFFFF
            buf.short  // Flags + Fragment Offset
            val ttl = buf.get().toInt() and 0xFF
            val protocol = buf.get().toInt() and 0xFF
            buf.short  // Header checksum

            val srcAddrBytes = ByteArray(4)
            buf.get(srcAddrBytes)
            val srcAddr = InetAddress.getByAddress(srcAddrBytes).hostAddress ?: return null

            val dstAddrBytes = ByteArray(4)
            buf.get(dstAddrBytes)
            val dstAddr = InetAddress.getByAddress(dstAddrBytes).hostAddress ?: return null

            // ── Transport Layer Parsing ────────────────────────────────
            var sourcePort = 0
            var destinationPort = 0
            var tcpFlags = 0
            var tcpSeqNumber = 0L
            var tcpAckNumber = 0L
            var tcpWindowSize = 0
            var tcpHeaderLength = 0
            var payloadOffset = ihl
            var payloadLength = totalLength - ihl

            when (protocol) {
                PROTOCOL_TCP -> {
                    if (length < ihl + 20) {
                        Log.w(TAG, "TCP header truncated: need ${ihl + 20}, have $length")
                        return null
                    }

                    val tcpBuf = ByteBuffer.wrap(packet, ihl, length - ihl)
                    tcpBuf.order(ByteOrder.BIG_ENDIAN)

                    sourcePort = tcpBuf.short.toInt() and 0xFFFF
                    destinationPort = tcpBuf.short.toInt() and 0xFFFF
                    tcpSeqNumber = tcpBuf.int.toLong() and 0xFFFFFFFFL
                    tcpAckNumber = tcpBuf.int.toLong() and 0xFFFFFFFFL

                    val dataOffsetFlags = tcpBuf.short.toInt() and 0xFFFF
                    tcpHeaderLength = ((dataOffsetFlags shr 12) and 0x0F) * 4
                    tcpFlags = dataOffsetFlags and 0x1FF

                    tcpWindowSize = tcpBuf.short.toInt() and 0xFFFF

                    payloadOffset = ihl + tcpHeaderLength
                    payloadLength = totalLength - ihl - tcpHeaderLength
                    if (payloadLength < 0) payloadLength = 0
                }

                PROTOCOL_UDP -> {
                    if (length < ihl + 8) {
                        Log.w(TAG, "UDP header truncated: need ${ihl + 8}, have $length")
                        return null
                    }

                    val udpBuf = ByteBuffer.wrap(packet, ihl, length - ihl)
                    udpBuf.order(ByteOrder.BIG_ENDIAN)

                    sourcePort = udpBuf.short.toInt() and 0xFFFF
                    destinationPort = udpBuf.short.toInt() and 0xFFFF
                    val udpLength = udpBuf.short.toInt() and 0xFFFF
                    // UDP checksum skipped

                    payloadOffset = ihl + 8
                    payloadLength = udpLength - 8
                    if (payloadLength < 0) payloadLength = 0
                }

                PROTOCOL_ICMP -> {
                    // ICMP: no ports, payload after IP header
                    payloadOffset = ihl
                    payloadLength = totalLength - ihl
                    if (payloadLength < 0) payloadLength = 0
                }
            }

            return ParsedPacket(
                version = version,
                protocol = protocol,
                sourceAddress = srcAddr,
                destinationAddress = dstAddr,
                sourcePort = sourcePort,
                destinationPort = destinationPort,
                tcpFlags = tcpFlags,
                tcpSeqNumber = tcpSeqNumber,
                tcpAckNumber = tcpAckNumber,
                tcpWindowSize = tcpWindowSize,
                payloadOffset = payloadOffset,
                payloadLength = payloadLength,
                totalLength = totalLength,
                headerLength = ihl,
                tcpHeaderLength = tcpHeaderLength,
                rawPacket = packet.copyOf(length),
                ttl = ttl,
                identification = identification
            )

        } catch (e: Exception) {
            Log.e(TAG, "Error parsing packet: ${e.message}")
            return null
        }
    }

    /**
     * Minimal IPv6 packet parser.
     * Only extracts source/destination addresses and next header (protocol).
     */
    private fun parseIPv6(packet: ByteArray, length: Int): ParsedPacket? {
        try {
            val buf = ByteBuffer.wrap(packet, 0, length)
            buf.order(ByteOrder.BIG_ENDIAN)

            val versionFlow = buf.int
            val version = (versionFlow shr 28) and 0x0F
            if (version != 6) return null

            buf.short  // Payload length
            val nextHeader = buf.get().toInt() and 0xFF
            val hopLimit = buf.get().toInt() and 0xFF

            val srcAddrBytes = ByteArray(16)
            buf.get(srcAddrBytes)
            val srcAddr = InetAddress.getByAddress(srcAddrBytes).hostAddress ?: return null

            val dstAddrBytes = ByteArray(16)
            buf.get(dstAddrBytes)
            val dstAddr = InetAddress.getByAddress(dstAddrBytes).hostAddress ?: return null

            var sourcePort = 0
            var destinationPort = 0
            var tcpFlags = 0
            var tcpHeaderLength = 0
            var payloadOffset = 40
            var payloadLength = length - 40

            when (nextHeader) {
                PROTOCOL_TCP -> {
                    if (length < 60) return null
                    val tcpBuf = ByteBuffer.wrap(packet, 40, length - 40)
                    tcpBuf.order(ByteOrder.BIG_ENDIAN)
                    sourcePort = tcpBuf.short.toInt() and 0xFFFF
                    destinationPort = tcpBuf.short.toInt() and 0xFFFF
                    tcpBuf.int  // seq
                    tcpBuf.int  // ack
                    val dataOffsetFlags = tcpBuf.short.toInt() and 0xFFFF
                    tcpHeaderLength = ((dataOffsetFlags shr 12) and 0x0F) * 4
                    tcpFlags = dataOffsetFlags and 0x1FF
                    payloadOffset = 40 + tcpHeaderLength
                    payloadLength = length - 40 - tcpHeaderLength
                    if (payloadLength < 0) payloadLength = 0
                }
                PROTOCOL_UDP -> {
                    if (length < 48) return null
                    val udpBuf = ByteBuffer.wrap(packet, 40, length - 40)
                    udpBuf.order(ByteOrder.BIG_ENDIAN)
                    sourcePort = udpBuf.short.toInt() and 0xFFFF
                    destinationPort = udpBuf.short.toInt() and 0xFFFF
                    payloadOffset = 48
                    payloadLength = length - 48
                    if (payloadLength < 0) payloadLength = 0
                }
            }

            return ParsedPacket(
                version = 6,
                protocol = nextHeader,
                sourceAddress = srcAddr,
                destinationAddress = dstAddr,
                sourcePort = sourcePort,
                destinationPort = destinationPort,
                tcpFlags = tcpFlags,
                tcpSeqNumber = 0,
                tcpAckNumber = 0,
                tcpWindowSize = 0,
                payloadOffset = payloadOffset,
                payloadLength = payloadLength,
                totalLength = length,
                headerLength = 40,
                tcpHeaderLength = tcpHeaderLength,
                rawPacket = packet.copyOf(length),
                ttl = hopLimit,
                identification = 0
            )
        } catch (e: Exception) {
            Log.e(TAG, "Error parsing IPv6 packet: ${e.message}")
            return null
        }
    }

    /**
     * Build a TCP packet for writing back to the TUN interface.
     * Used for generating SYN-ACK, ACK, FIN-ACK responses in the user-space
     * TCP connection tracker.
     *
     * @param srcAddr Source IP address
     * @param dstAddr Destination IP address
     * @param srcPort Source port
     * @param dstPort Destination port
     * @param seqNum Sequence number
     * @param ackNum Acknowledgment number
     * @param flags TCP flags
     * @param windowSize TCP window size
     * @param payload Optional TCP payload data
     * @return Raw IP packet bytes ready to write to TUN
     */
    fun buildTcpPacket(
        srcAddr: String,
        dstAddr: String,
        srcPort: Int,
        dstPort: Int,
        seqNum: Long,
        ackNum: Long,
        flags: Int,
        windowSize: Int = 65535,
        payload: ByteArray = ByteArray(0)
    ): ByteArray {
        val srcAddrBytes = InetAddress.getByName(srcAddr).address
        val dstAddrBytes = InetAddress.getByName(dstAddr).address
        val tcpHeaderLen = 20
        val ipHeaderLen = 20
        val totalLen = ipHeaderLen + tcpHeaderLen + payload.size

        val buf = ByteBuffer.allocate(totalLen)
        buf.order(ByteOrder.BIG_ENDIAN)

        // ── IPv4 Header ────────────────────────────────────────────
        buf.put((0x45).toByte())  // Version=4, IHL=5 (20 bytes)
        buf.put(0)  // TOS
        buf.putShort(totalLen.toShort())  // Total length
        buf.putShort(0)  // Identification
        buf.putShort(0x4000.toShort())  // Flags: Don't Fragment
        buf.put(64)  // TTL
        buf.put(PROTOCOL_TCP.toByte())  // Protocol = TCP
        buf.putShort(0)  // Header checksum (will calculate)
        buf.put(srcAddrBytes)
        buf.put(dstAddrBytes)

        // Calculate IP checksum
        val ipChecksum = calculateChecksum(buf.array(), 0, ipHeaderLen)
        buf.putShort(10, ipChecksum)

        // ── TCP Header ─────────────────────────────────────────────
        buf.putShort(srcPort.toShort())
        buf.putShort(dstPort.toShort())
        buf.putInt(seqNum.toInt())
        buf.putInt(ackNum.toInt())
        buf.putShort(((tcpHeaderLen / 4) shl 12 or flags).toShort())
        buf.putShort(windowSize.toShort())
        buf.putShort(0)  // Checksum (placeholder)
        buf.putShort(0)  // Urgent pointer

        // TCP payload
        if (payload.isNotEmpty()) {
            buf.put(payload)
        }

        // Calculate TCP checksum (with pseudo-header)
        val tcpChecksum = calculateTcpChecksum(
            buf.array(), ipHeaderLen, totalLen - ipHeaderLen,
            srcAddrBytes, dstAddrBytes
        )
        buf.putShort(ipHeaderLen + 16, tcpChecksum)

        return buf.array()
    }

    /**
     * Build a UDP packet for writing back to the TUN interface.
     */
    fun buildUdpPacket(
        srcAddr: String,
        dstAddr: String,
        srcPort: Int,
        dstPort: Int,
        payload: ByteArray
    ): ByteArray {
        val srcAddrBytes = InetAddress.getByName(srcAddr).address
        val dstAddrBytes = InetAddress.getByName(dstAddr).address
        val ipHeaderLen = 20
        val udpHeaderLen = 8
        val totalLen = ipHeaderLen + udpHeaderLen + payload.size

        val buf = ByteBuffer.allocate(totalLen)
        buf.order(ByteOrder.BIG_ENDIAN)

        // IPv4 Header
        buf.put((0x45).toByte())
        buf.put(0)
        buf.putShort(totalLen.toShort())
        buf.putShort(0)
        buf.putShort(0x4000.toShort())
        buf.put(64)
        buf.put(PROTOCOL_UDP.toByte())
        buf.putShort(0)  // checksum
        buf.put(srcAddrBytes)
        buf.put(dstAddrBytes)

        val ipChecksum = calculateChecksum(buf.array(), 0, ipHeaderLen)
        buf.putShort(10, ipChecksum)

        // UDP Header
        buf.putShort(srcPort.toShort())
        buf.putShort(dstPort.toShort())
        buf.putShort((udpHeaderLen + payload.size).toShort())
        buf.putShort(0)  // UDP checksum (optional for IPv4)

        buf.put(payload)

        return buf.array()
    }

    /**
     * Calculate Internet checksum (RFC 1071) for IP header.
     */
    private fun calculateChecksum(data: ByteArray, offset: Int, length: Int): Short {
        var sum = 0L
        var i = offset
        var remaining = length

        while (remaining > 1) {
            sum += ((data[i].toInt() and 0xFF) shl 8) or (data[i + 1].toInt() and 0xFF)
            i += 2
            remaining -= 2
        }

        if (remaining == 1) {
            sum += (data[i].toInt() and 0xFF) shl 8
        }

        while (sum shr 16 != 0L) {
            sum = (sum and 0xFFFF) + (sum shr 16)
        }

        return (sum.inv() and 0xFFFF).toShort()
    }

    /**
     * Calculate TCP checksum with pseudo-header.
     */
    private fun calculateTcpChecksum(
        data: ByteArray, offset: Int, length: Int,
        srcAddr: ByteArray, dstAddr: ByteArray
    ): Short {
        var sum = 0L

        // Pseudo-header
        for (b in srcAddr) {
            sum += (b.toInt() and 0xFF).toLong()
        }
        for (b in dstAddr) {
            sum += (b.toInt() and 0xFF).toLong()
        }
        sum += PROTOCOL_TCP.toLong()
        sum += length.toLong()

        // TCP header + data
        var i = offset
        var remaining = length
        while (remaining > 1) {
            sum += ((data[i].toInt() and 0xFF) shl 8) or (data[i + 1].toInt() and 0xFF)
            i += 2
            remaining -= 2
        }
        if (remaining == 1) {
            sum += (data[i].toInt() and 0xFF) shl 8
        }

        while (sum shr 16 != 0L) {
            sum = (sum and 0xFFFF) + (sum shr 16)
        }

        return (sum.inv() and 0xFFFF).toShort()
    }
}
