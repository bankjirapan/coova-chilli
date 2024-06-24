#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include "log.h"

// Function to log to a file
void log_to_file(const char *function, int line, struct dhcp_conn_t *conn, struct in_addr *addr, uint8_t *dhcp_pkt, size_t dhcp_len) {
    FILE *log_file = fopen("/var/log/chilli/dhcp.log", "a");
    if (log_file == NULL) {
        perror("Error opening log file");
        return;
    }

    fprintf(log_file, "%s(%d): DHCP request for IP address %s\n", 
            function, 
            line, 
            addr ? inet_ntoa(*addr) : "n/a");

    // Optionally, you can log more details about dhcp_pkt and dhcp_len if needed
    // fprintf(log_file, "DHCP packet length: %zu\n", dhcp_len);
    // fwrite(dhcp_pkt, 1, dhcp_len, log_file);

    fclose(log_file);
}