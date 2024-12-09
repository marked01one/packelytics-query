#ifndef WRITER_H
#define WRITER_H

#include <linux/debugfs.h>
#include <linux/time.h>

#define BUF_SIZE 256
#define LOG_DIR "packet_sniffer" 
#define LOG_FILE_NAME "data"


int append_packet(const char* data, ...);

#endif