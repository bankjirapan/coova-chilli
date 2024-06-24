#include "log.h"

#define LOG_FILE_PATH "/var/log/chilli/dhcp.log"

// Helper function to get the current timestamp as a string
char* get_timestamp() {
    time_t rawtime;
    struct tm * timeinfo;
    char *buffer = (char*)malloc(20 * sizeof(char));

    time(&rawtime);
    timeinfo = localtime(&rawtime);

    strftime(buffer, 20, "%Y-%m-%d %H:%M:%S", timeinfo);
    return buffer;
}

void write_log(const char *message) {
    FILE *log_file = fopen(LOG_FILE_PATH, "a");
    if (log_file == NULL) {
        perror("Error opening log file");
        return;
    }

    char *timestamp = get_timestamp();
    if (timestamp == NULL) {
        perror("Error getting timestamp");
        fclose(log_file);
        return;
    }

    fprintf(log_file, "[%s] %s\n", timestamp, message);
    free(timestamp);
    fclose(log_file);
}