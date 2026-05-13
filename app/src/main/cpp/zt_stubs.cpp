/**
 * zt_stubs.cpp — Stub implementations for ZeroTier SDK functions
 *
 * When the real ZeroTier library (libzt.a/.so) is NOT linked,
 * these stub implementations provide the necessary symbols so the
 * project compiles and runs. The stubs return error codes, and the
 * ZeroTierEngine will fail gracefully with clear error messages.
 *
 * When the real library IS linked, this file is NOT compiled
 * (excluded by CMakeLists.txt when libzt.so is found).
 *
 * IMPORTANT: These stubs match the REAL ZeroTier SDK API:
 *   - zts_init_set_event_handler() (NOT zts_init_set_event_callback)
 *   - zts_addr_get() for address retrieval
 *   - zts_addr_get_str() for string-based IP retrieval
 *   - ZTS_AF_INET / ZTS_AF_INET6 address families
 *   - zts_event_msg_t with node/network/peer/addr pointers
 *   - zts_node_free() for resource cleanup
 */

#include <ZeroTierSockets.h>
#include <unistd.h>
#include <string.h>

// ── Stub implementations ────────────────────────────────────────────────────

int zts_init_from_storage(const char *) { return ZTS_ERR_SERVICE; }

// CRITICAL: The real SDK function is zts_init_set_event_handler,
// NOT zts_init_set_event_callback. This was the root cause of the crash!
int zts_init_set_event_handler(void (*callback)(void*)) { return ZTS_ERR_SERVICE; }

int zts_node_start(void) { return ZTS_ERR_SERVICE; }
int zts_node_stop(void) { return ZTS_ERR_SERVICE; }
void zts_node_free(void) { }  // No-op stub — real version frees internal state
int zts_node_is_online(void) { return 0; }
uint64_t zts_node_get_id(void) { return 0; }
int zts_node_get_id_pair(uint64_t, char *, unsigned int, char *, unsigned int) { return ZTS_ERR_SERVICE; }
int zts_net_join(uint64_t) { return ZTS_ERR_SERVICE; }
int zts_net_leave(uint64_t) { return ZTS_ERR_SERVICE; }
int zts_net_transport_is_ready(uint64_t) { return 0; }

int zts_addr_is_assigned(uint64_t, unsigned int) { return 0; }

int zts_addr_get(uint64_t, unsigned int, struct zts_sockaddr_storage *addr) {
    if (addr) memset(addr, 0, sizeof(struct zts_sockaddr_storage));
    return ZTS_ERR_SERVICE;
}

int zts_addr_get_str(uint64_t, unsigned int, char *dst, unsigned int len) {
    if (dst && len > 0) dst[0] = '\0';
    return ZTS_ERR_SERVICE;
}

int zts_addr_get_all(uint64_t, struct zts_sockaddr_storage *, unsigned int *) {
    return ZTS_ERR_SERVICE;
}

int zts_bsd_socket(int, int, int) { return ZTS_ERR_SOCKET; }
int zts_bsd_close(int) { return ZTS_ERR_SOCKET; }
int zts_bsd_bind(int, const struct zts_sockaddr *, zts_socklen_t) { return ZTS_ERR_SOCKET; }
int zts_bsd_connect(int, const struct zts_sockaddr *, zts_socklen_t) { return ZTS_ERR_SOCKET; }
int zts_bsd_setsockopt(int, int, int, const void *, zts_socklen_t) { return ZTS_ERR_SOCKET; }
ssize_t zts_bsd_sendto(int, const void *, size_t, int, const struct zts_sockaddr *, zts_socklen_t) {
    return ZTS_ERR_SOCKET;
}
ssize_t zts_bsd_recvfrom(int, void *, size_t, int, struct zts_sockaddr *, zts_socklen_t *) {
    return ZTS_ERR_SOCKET;
}

// ── Additional stubs for high-level socket API ──────────────────────────────
// These are used by nativeZtsTcpConnect in native-lib.cpp and by Socks5Server
int zts_socket(int, int, int) { return ZTS_ERR_SOCKET; }
int zts_connect(int, const char *, unsigned short, int) { return ZTS_ERR_SOCKET; }
int zts_close(int) { return ZTS_ERR_SOCKET; }

int zts_bind(int, const char *, unsigned short) { return ZTS_ERR_SOCKET; }
int zts_listen(int, int) { return ZTS_ERR_SOCKET; }
int zts_accept(int, char *, int, unsigned short *) { return ZTS_ERR_SOCKET; }
ssize_t zts_send(int, const void *, size_t, int) { return ZTS_ERR_SOCKET; }
ssize_t zts_recv(int, void *, size_t, int) { return ZTS_ERR_SOCKET; }
ssize_t zts_read(int, void *, size_t) { return ZTS_ERR_SOCKET; }
ssize_t zts_write(int, const void *, size_t) { return ZTS_ERR_SOCKET; }
int zts_set_no_delay(int, int) { return ZTS_ERR_SOCKET; }

// Global errno for ZeroTier SDK socket operations
int zts_errno = 0;
