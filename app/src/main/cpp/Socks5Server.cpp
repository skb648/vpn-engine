/**
 * Socks5Server.cpp — Native SOCKS5 proxy server implementation.
 *
 * Listens on the ZeroTier virtual IP through libzt's user-space stack
 * (zts_socket / zts_bind / zts_listen / zts_accept), and bridges client
 * sessions to outgoing BSD sockets that go out the device's real
 * internet uplink. The outgoing sockets are handed to a JNI callback
 * (VpnService.protect) so they bypass the local VPN tunnel.
 *
 * Protocol (RFC 1928) — minimal subset:
 *   - METHOD selection: only NO AUTH (0x00) is accepted.
 *   - Command: only CONNECT (0x01).
 *   - Address types: IPv4 (0x01), DOMAINNAME (0x03), IPv6 (0x04).
 */

#include "Socks5Server.h"

#include <ZeroTierSockets.h>

#include <android/log.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <poll.h>

#include <cstring>
#include <cstdio>
#include <chrono>

#define LOG_TAG "ZT-Socks5"
#define LOG_D(...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)
#define LOG_I(...) __android_log_print(ANDROID_LOG_INFO,  LOG_TAG, __VA_ARGS__)
#define LOG_W(...) __android_log_print(ANDROID_LOG_WARN,  LOG_TAG, __VA_ARGS__)
#define LOG_E(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

// SOCKS5 protocol constants
static constexpr uint8_t SOCKS_VER         = 0x05;
static constexpr uint8_t AUTH_NONE         = 0x00;
static constexpr uint8_t AUTH_NO_ACCEPT    = 0xFF;
static constexpr uint8_t CMD_CONNECT       = 0x01;
static constexpr uint8_t ATYP_IPV4         = 0x01;
static constexpr uint8_t ATYP_DOMAIN       = 0x03;
static constexpr uint8_t ATYP_IPV6         = 0x04;
static constexpr uint8_t REP_SUCCESS       = 0x00;
static constexpr uint8_t REP_GENERAL_FAIL  = 0x01;
static constexpr uint8_t REP_NOT_ALLOWED   = 0x02;
static constexpr uint8_t REP_NET_UNREACH   = 0x03;
static constexpr uint8_t REP_HOST_UNREACH  = 0x04;
static constexpr uint8_t REP_CONN_REFUSED  = 0x05;
static constexpr uint8_t REP_CMD_NOT_SUP   = 0x07;
static constexpr uint8_t REP_ATYP_NOT_SUP  = 0x08;

static constexpr int  CONNECT_TIMEOUT_MS = 15'000;
static constexpr int  BRIDGE_BUF_SIZE    = 16 * 1024;

namespace {

// Read `len` bytes from a ZeroTier socket. Returns true on success.
bool ztReadFully(int fd, void* dst, size_t len) {
    auto* p = static_cast<uint8_t*>(dst);
    size_t got = 0;
    while (got < len) {
        ssize_t n = zts_recv(fd, p + got, len - got, 0);
        if (n <= 0) return false;
        got += static_cast<size_t>(n);
    }
    return true;
}

bool ztWriteAll(int fd, const void* src, size_t len) {
    auto* p = static_cast<const uint8_t*>(src);
    size_t sent = 0;
    while (sent < len) {
        ssize_t n = zts_send(fd, p + sent, len - sent, 0);
        if (n <= 0) return false;
        sent += static_cast<size_t>(n);
    }
    return true;
}

bool bsdWriteAll(int fd, const void* src, size_t len) {
    auto* p = static_cast<const uint8_t*>(src);
    size_t sent = 0;
    while (sent < len) {
        ssize_t n = ::send(fd, p + sent, len - sent, MSG_NOSIGNAL);
        if (n < 0) {
            if (errno == EINTR) continue;
            return false;
        }
        if (n == 0) return false;
        sent += static_cast<size_t>(n);
    }
    return true;
}

} // namespace

// ──────────────────────────────────────────────────────────────────────────

Socks5Server::Socks5Server() = default;

Socks5Server::~Socks5Server() {
    stop();
}

void Socks5Server::setLastError(const std::string& err) {
    std::lock_guard<std::mutex> g(errMu_);
    lastError_ = err;
}

std::string Socks5Server::lastError() const {
    std::lock_guard<std::mutex> g(errMu_);
    return lastError_;
}

bool Socks5Server::start(const std::string& bindIpV4, uint16_t port, ProtectFdFn protectFd) {
    if (running_.exchange(true, std::memory_order_acq_rel)) {
        LOG_W("Socks5Server already running");
        return true;
    }

    bindIp_    = bindIpV4;
    port_      = port;
    protectFd_ = std::move(protectFd);

    int fd = zts_socket(ZTS_AF_INET, ZTS_SOCK_STREAM, 0);
    if (fd < 0) {
        std::string msg = "zts_socket failed, zts_errno=" + std::to_string(zts_errno);
        LOG_E("%s", msg.c_str());
        setLastError(msg);
        running_.store(false, std::memory_order_release);
        return false;
    }

    const char* bindStr = bindIp_.empty() ? "0.0.0.0" : bindIp_.c_str();
    int rc = zts_bind(fd, bindStr, port_);
    if (rc != ZTS_ERR_OK) {
        std::string msg = "zts_bind(" + std::string(bindStr) + ":" + std::to_string(port_) +
                          ") failed, rc=" + std::to_string(rc) +
                          " zts_errno=" + std::to_string(zts_errno);
        LOG_E("%s", msg.c_str());
        setLastError(msg);
        zts_close(fd);
        running_.store(false, std::memory_order_release);
        return false;
    }

    rc = zts_listen(fd, 16);
    if (rc != ZTS_ERR_OK) {
        std::string msg = "zts_listen failed, rc=" + std::to_string(rc) +
                          " zts_errno=" + std::to_string(zts_errno);
        LOG_E("%s", msg.c_str());
        setLastError(msg);
        zts_close(fd);
        running_.store(false, std::memory_order_release);
        return false;
    }

    listenFd_ = fd;
    LOG_I("SOCKS5 listening on ZT %s:%u (fd=%d)", bindStr, (unsigned)port_, fd);

    try {
        acceptThread_ = std::make_unique<std::thread>(&Socks5Server::acceptLoop, this);
    } catch (const std::exception& e) {
        LOG_E("Failed to start accept thread: %s", e.what());
        setLastError(std::string("Failed to start accept thread: ") + e.what());
        zts_close(fd);
        listenFd_ = -1;
        running_.store(false, std::memory_order_release);
        return false;
    }

    return true;
}

void Socks5Server::stop() {
    if (!running_.exchange(false, std::memory_order_acq_rel)) {
        return;
    }
    LOG_I("Stopping SOCKS5 server...");

    // Close the listen socket to unblock zts_accept.
    if (listenFd_ >= 0) {
        zts_close(listenFd_);
        listenFd_ = -1;
    }

    // Close every in-flight ZT and BSD socket so worker threads bail out.
    {
        std::lock_guard<std::mutex> g(clientMu_);
        for (int fd : activeZtFds_) {
            zts_close(fd);
        }
        for (int fd : activeBsdFds_) {
            ::shutdown(fd, SHUT_RDWR);
            ::close(fd);
        }
        activeZtFds_.clear();
        activeBsdFds_.clear();
    }

    if (acceptThread_ && acceptThread_->joinable()) {
        acceptThread_->join();
    }
    acceptThread_.reset();

    // Join worker threads
    std::vector<std::thread> toJoin;
    {
        std::lock_guard<std::mutex> g(clientMu_);
        toJoin = std::move(clientThreads_);
        clientThreads_.clear();
    }
    for (auto& t : toJoin) {
        if (t.joinable()) t.join();
    }

    LOG_I("SOCKS5 server stopped");
}

void Socks5Server::acceptLoop() {
    LOG_I("SOCKS5 accept loop started");
    while (running_.load(std::memory_order_acquire)) {
        char remoteBuf[64] = {0};
        unsigned short remotePort = 0;
        int client = zts_accept(listenFd_, remoteBuf, sizeof(remoteBuf), &remotePort);
        if (client < 0) {
            if (!running_.load(std::memory_order_acquire)) break;
            LOG_W("zts_accept returned %d, zts_errno=%d — sleeping briefly", client, zts_errno);
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
            continue;
        }
        // Track this ZT fd so stop() can force it closed.
        {
            std::lock_guard<std::mutex> g(clientMu_);
            activeZtFds_.insert(client);
        }
        std::string remote = remoteBuf;
        if (!remote.empty()) {
            remote += ":" + std::to_string(remotePort);
        }
        LOG_I("SOCKS5 accept fd=%d from %s", client, remote.c_str());

        try {
            std::thread t(&Socks5Server::handleClient, this, client, remote);
            std::lock_guard<std::mutex> g(clientMu_);
            clientThreads_.push_back(std::move(t));
        } catch (const std::exception& e) {
            LOG_E("Failed to spawn client thread: %s", e.what());
            std::lock_guard<std::mutex> g(clientMu_);
            activeZtFds_.erase(client);
            zts_close(client);
        }
    }
    LOG_I("SOCKS5 accept loop exiting");
}

void Socks5Server::handleClient(int ztFd, std::string remote) {
    int bsdFd = -1;
    bool ok = false;
    do {
        if (!socks5Handshake(ztFd)) {
            LOG_W("SOCKS5 handshake failed from %s", remote.c_str());
            break;
        }

        std::string host;
        uint16_t    port = 0;
        uint8_t     atyp = 0;
        if (!readSocks5Connect(ztFd, host, port, atyp)) {
            LOG_W("Bad CONNECT request from %s", remote.c_str());
            sendReply(ztFd, REP_GENERAL_FAIL);
            break;
        }
        LOG_I("SOCKS5 CONNECT %s:%u from %s", host.c_str(), (unsigned)port, remote.c_str());

        bsdFd = connectTargetBsd(host, port);
        if (bsdFd < 0) {
            LOG_W("Failed to connect upstream to %s:%u", host.c_str(), (unsigned)port);
            uint8_t reply = REP_HOST_UNREACH;
            if (errno == ECONNREFUSED) reply = REP_CONN_REFUSED;
            else if (errno == ENETUNREACH) reply = REP_NET_UNREACH;
            sendReply(ztFd, reply);
            break;
        }

        {
            std::lock_guard<std::mutex> g(clientMu_);
            activeBsdFds_.insert(bsdFd);
        }

        sendReply(ztFd, REP_SUCCESS);
        bridge(ztFd, bsdFd);
        ok = true;
    } while (false);

    // Cleanup
    {
        std::lock_guard<std::mutex> g(clientMu_);
        activeZtFds_.erase(ztFd);
        if (bsdFd >= 0) activeBsdFds_.erase(bsdFd);
    }
    zts_close(ztFd);
    if (bsdFd >= 0) {
        ::shutdown(bsdFd, SHUT_RDWR);
        ::close(bsdFd);
    }
    LOG_D("SOCKS5 session %s ended (%s)", remote.c_str(), ok ? "ok" : "err");
}

bool Socks5Server::socks5Handshake(int ztFd) {
    // VER | NMETHODS | METHODS...
    uint8_t hdr[2];
    if (!ztReadFully(ztFd, hdr, 2)) return false;
    if (hdr[0] != SOCKS_VER) {
        LOG_W("Bad SOCKS version: 0x%02x", hdr[0]);
        return false;
    }
    uint8_t nMethods = hdr[1];
    if (nMethods == 0 || nMethods > 255) return false;
    uint8_t methods[255];
    if (!ztReadFully(ztFd, methods, nMethods)) return false;

    bool noAuthOk = false;
    for (uint8_t i = 0; i < nMethods; i++) {
        if (methods[i] == AUTH_NONE) { noAuthOk = true; break; }
    }

    uint8_t reply[2] = { SOCKS_VER, noAuthOk ? AUTH_NONE : AUTH_NO_ACCEPT };
    if (!ztWriteAll(ztFd, reply, 2)) return false;
    return noAuthOk;
}

bool Socks5Server::readSocks5Connect(int ztFd, std::string& host, uint16_t& port, uint8_t& atyp) {
    // VER | CMD | RSV | ATYP | ADDR | PORT
    uint8_t head[4];
    if (!ztReadFully(ztFd, head, 4)) return false;
    if (head[0] != SOCKS_VER) return false;
    if (head[1] != CMD_CONNECT) {
        LOG_W("Unsupported SOCKS command: 0x%02x", head[1]);
        sendReply(ztFd, REP_CMD_NOT_SUP);
        return false;
    }
    atyp = head[3];
    char buf[256] = {0};
    if (atyp == ATYP_IPV4) {
        uint8_t a[4];
        if (!ztReadFully(ztFd, a, 4)) return false;
        std::snprintf(buf, sizeof(buf), "%u.%u.%u.%u", a[0], a[1], a[2], a[3]);
        host = buf;
    } else if (atyp == ATYP_DOMAIN) {
        uint8_t dlen = 0;
        if (!ztReadFully(ztFd, &dlen, 1)) return false;
        if (dlen == 0) return false;
        if (!ztReadFully(ztFd, buf, dlen)) return false;
        buf[dlen] = '\0';
        host.assign(buf, dlen);
    } else if (atyp == ATYP_IPV6) {
        uint8_t a[16];
        if (!ztReadFully(ztFd, a, 16)) return false;
        char ipbuf[INET6_ADDRSTRLEN] = {0};
        if (!inet_ntop(AF_INET6, a, ipbuf, sizeof(ipbuf))) return false;
        host = ipbuf;
    } else {
        LOG_W("Unsupported SOCKS atyp: 0x%02x", atyp);
        sendReply(ztFd, REP_ATYP_NOT_SUP);
        return false;
    }

    uint8_t pp[2];
    if (!ztReadFully(ztFd, pp, 2)) return false;
    port = (static_cast<uint16_t>(pp[0]) << 8) | pp[1];
    return true;
}

int Socks5Server::connectTargetBsd(const std::string& host, uint16_t port) {
    // Resolve the target (IPv4 / IPv6 / hostname). We use a real DNS
    // lookup via getaddrinfo on the device's own kernel stack so that
    // the Sender resolves names through its own ISP, not through ZT.
    struct addrinfo hints{};
    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    char portStr[8];
    std::snprintf(portStr, sizeof(portStr), "%u", (unsigned)port);

    struct addrinfo* res = nullptr;
    int gai = ::getaddrinfo(host.c_str(), portStr, &hints, &res);
    if (gai != 0 || res == nullptr) {
        LOG_W("getaddrinfo(%s) failed: %s", host.c_str(), gai_strerror(gai));
        errno = EHOSTUNREACH;
        return -1;
    }

    int outFd = -1;
    for (auto* ai = res; ai != nullptr; ai = ai->ai_next) {
        int fd = ::socket(ai->ai_family, ai->ai_socktype | SOCK_CLOEXEC, ai->ai_protocol);
        if (fd < 0) continue;

        // CRITICAL: keep this socket OFF our own VPN tunnel, otherwise
        // we'd recurse forever (Sender's outgoing traffic would re-enter
        // its own TUN and end up looped back into libzt).
        if (protectFd_) {
            try {
                if (!protectFd_(fd)) {
                    LOG_W("VpnService.protect(%d) returned false", fd);
                }
            } catch (...) {
                LOG_W("protectFd_ callback threw");
            }
        }

        // Non-blocking connect with timeout.
        int flags = ::fcntl(fd, F_GETFL, 0);
        ::fcntl(fd, F_SETFL, flags | O_NONBLOCK);

        int rc = ::connect(fd, ai->ai_addr, ai->ai_addrlen);
        if (rc == 0) {
            ::fcntl(fd, F_SETFL, flags);
            outFd = fd;
            break;
        }
        if (errno != EINPROGRESS) {
            ::close(fd);
            continue;
        }
        struct pollfd pfd{};
        pfd.fd     = fd;
        pfd.events = POLLOUT;
        int pr = ::poll(&pfd, 1, CONNECT_TIMEOUT_MS);
        if (pr <= 0) {
            ::close(fd);
            errno = ETIMEDOUT;
            continue;
        }
        int soerr = 0;
        socklen_t slen = sizeof(soerr);
        if (::getsockopt(fd, SOL_SOCKET, SO_ERROR, &soerr, &slen) < 0 || soerr != 0) {
            ::close(fd);
            errno = soerr ? soerr : ECONNREFUSED;
            continue;
        }
        ::fcntl(fd, F_SETFL, flags);
        outFd = fd;
        break;
    }
    ::freeaddrinfo(res);

    if (outFd >= 0) {
        int one = 1;
        ::setsockopt(outFd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
    }
    return outFd;
}

void Socks5Server::sendReply(int ztFd, uint8_t replyCode) {
    // VER | REP | RSV | ATYP=IPv4 | BND.ADDR (0.0.0.0) | BND.PORT (0)
    uint8_t resp[10] = {
        SOCKS_VER, replyCode, 0x00,
        ATYP_IPV4,
        0, 0, 0, 0,
        0, 0
    };
    ztWriteAll(ztFd, resp, sizeof(resp));
}

void Socks5Server::bridge(int ztFd, int bsdFd) {
    // Bidirectional, blocking forwarder using two threads. Each side
    // closes the opposite when its half hits EOF / error so the other
    // direction can wake up.

    std::atomic<bool> alive{true};

    std::thread ztToBsd([&]() {
        std::vector<uint8_t> buf(BRIDGE_BUF_SIZE);
        while (alive.load(std::memory_order_acquire)) {
            ssize_t n = zts_recv(ztFd, buf.data(), buf.size(), 0);
            if (n <= 0) break;
            if (!bsdWriteAll(bsdFd, buf.data(), static_cast<size_t>(n))) break;
        }
        alive.store(false, std::memory_order_release);
        ::shutdown(bsdFd, SHUT_RDWR);
    });

    std::thread bsdToZt([&]() {
        std::vector<uint8_t> buf(BRIDGE_BUF_SIZE);
        while (alive.load(std::memory_order_acquire)) {
            ssize_t n = ::recv(bsdFd, buf.data(), buf.size(), 0);
            if (n < 0) {
                if (errno == EINTR) continue;
                break;
            }
            if (n == 0) break;
            if (!ztWriteAll(ztFd, buf.data(), static_cast<size_t>(n))) break;
        }
        alive.store(false, std::memory_order_release);
        // Force the ZT side to wake up.
        zts_close(ztFd);
    });

    ztToBsd.join();
    bsdToZt.join();
}
