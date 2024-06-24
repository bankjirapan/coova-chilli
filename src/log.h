#ifndef LOG_H
#define LOG_H

#include <arpa/inet.h>

// Structure declarations for dhcp_conn_t, if they are not included elsewhere
struct dhcp_conn_t {
    struct app_conn_t *peer;
};

// Function declaration for logging
void log_to_file(const char *function, int line, struct dhcp_conn_t *conn, struct in_addr *addr, uint8_t *dhcp_pkt, size_t dhcp_len);

// Macro for logging DHCP requests
#define LOG_DHCP_REQUEST(conn, addr, dhcp_pkt, dhcp_len) log_to_file(__FUNCTION__, __LINE__, conn, addr, dhcp_pkt, dhcp_len)

#endif // LOG_H