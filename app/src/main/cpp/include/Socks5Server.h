/**
 * Socks5Server.h — Native SOCKS5 proxy server using libzt user-space stack.
 *
 * The previous Kotlin-based Socks5ProxyServer used java.net.ServerSocket
 * to bind to the ZeroTier virtual IP. That cannot work, because the
 * ZeroTier virtual address only exists inside libzt's own user-space TCP/IP
 * stack (lwIP), NOT inside the Linux kernel — so bind(2) on the kernel
 * socket either fails outright with EADDRNOTAVAIL or, if it succeeds on the
 * loopback interface, never receives any traffic from the ZT mesh.
 *
 * This native server fixes that by using libzt's zts_socket / zts_bind /
 * zts_listen / zts_accept which work directly against the ZeroTier
 * virtual interface inside the user-space stack. Outgoing connections to
 * the real internet are made with regular BSD sockets, which are
 * protected via VpnService.protect() through a JNI callback so they
 * never re-enter the local VPN tunnel.
 *
 * This file is part of the SENDER mode: when a Sender app receives a
 * SOCKS5 CONNECT request from a Receiver peer over the ZeroTier network,
 * the Sender opens the requested connection through its own real
 * internet uplink and bridges bytes between the two sockets. That is
 * what "shares internet across long distance" actually means in this app.
 */

#pragma once

#include <atomic>
#include <thread>
#include <mutex>
#include <unordered_set>
#include <memory>
#include <string>
#include <functional>
#include <vector>
#include <cstdint>

class Socks5Server {
public:
    using ProtectFdFn = std::function<bool(int)>;

    Socks5Server();
    ~Socks5Server();

    /**
     * Start the SOCKS5 listener using libzt's user-space stack.
     *
     * @param bindIpV4   ZeroTier virtual IPv4 to bind on, or "0.0.0.0"
     *                   to accept on every assigned ZT address.
     * @param port       TCP port to listen on (typically 1080).
     * @param protectFd  Callback invoked for every outgoing BSD socket
     *                   so VpnService.protect() can keep it off the
     *                   local VPN tunnel.
     * @return true if the listening socket was created successfully.
     */
    bool start(const std::string& bindIpV4, uint16_t port, ProtectFdFn protectFd);

    /**
     * Stop the listener and all in-flight client connections.
     * Idempotent and safe to call multiple times. Blocks until all
     * worker threads have joined.
     */
    void stop();

    bool isRunning() const { return running_.load(std::memory_order_acquire); }

    std::string lastError() const;

private:
    void acceptLoop();
    void handleClient(int ztClientFd, std::string remote);
    bool socks5Handshake(int ztFd);
    bool readSocks5Connect(int ztFd, std::string& host, uint16_t& port, uint8_t& atyp);
    int  connectTargetBsd(const std::string& host, uint16_t port);
    void sendReply(int ztFd, uint8_t replyCode);
    void bridge(int ztFd, int bsdFd);

    void setLastError(const std::string& err);

    std::atomic<bool>      running_{false};
    int                    listenFd_{-1};
    uint16_t               port_{0};
    std::string            bindIp_;
    ProtectFdFn            protectFd_;
    std::unique_ptr<std::thread> acceptThread_;

    // Track active client threads so stop() can join them.
    std::mutex             clientMu_;
    std::unordered_set<std::thread::id> activeClientIds_;
    std::vector<std::thread> clientThreads_;
    std::unordered_set<int> activeBsdFds_;
    std::unordered_set<int> activeZtFds_;

    mutable std::mutex     errMu_;
    std::string            lastError_;
};
