#include "log.h"
#include <sys/stat.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>

#define DHCP_LOG_FILE_PATH "/var/log/chilli/"

char* get_timestamp() {
    time_t rawtime;
    struct tm * timeinfo;
    char *buffer = (char*)malloc(20 * sizeof(char)); // ปรับขนาดตามความต้องการ
    if (buffer == NULL) {
        perror("Error allocating memory for timestamp");
        return NULL;
    }
    time(&rawtime);
    timeinfo = localtime(&rawtime);
    strftime(buffer, 20, "%Y-%m-%d %H:%M:%S", timeinfo);
    return buffer;
}

void write_dhcp_log(const char *message) {

    struct stat st = {0};
    FILE *log_file;

    if (stat(DHCP_LOG_FILE_PATH, &st) == -1) {
        mkdir(DHCP_LOG_FILE_PATH, 0700);
    }

    log_file = fopen(DHCP_LOG_FILE_PATH "chilli.log", "a");
    if (log_file == NULL) {
        perror("Error opening log file");
        return;
    }

    char *timestamp = get_timestamp();
    if (timestamp == NULL) {
        fclose(log_file);
        return;
    }

    fprintf(log_file, "[%s] %s\n", timestamp, message);
    free(timestamp);
    fclose(log_file);
}