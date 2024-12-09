#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/debugfs.h>
#include <linux/fs.h>
#include <linux/time.h>
#include <linux/stdarg.h>
#include <linux/mutex.h>
#include <linux/slab.h>
#include <linux/buffer_head.h>


#include <asm/segment.h>
#include <asm/uaccess.h>
#include <linux/buffer_head.h>

#include "../headers/writer.h"

static struct file* fp;
static int ret;
static struct mutex packet_mtx = __MUTEX_INITIALIZER(packet_mtx);

int append_packet(const char* data, ...)
{
    char filename[64];
    struct timespec64 ts;
    struct tm tm;

    // Get current time
    ktime_get_real_ts64(&ts);
    time64_to_tm(ts.tv_sec, 0, &tm);

    // Copy current time to timestamp buffer
    snprintf(filename, sizeof(filename), "/var/packet_sniffer/%s__%04d-%02d-%02dT%02d-%02d",
        LOG_FILE_NAME, 
        (int)tm.tm_year, tm.tm_mon, tm.tm_yday,
        tm.tm_hour, tm.tm_min
    );

    mutex_lock(&packet_mtx);
    
    printk(KERN_INFO "Attempting to open %s\n", filename);
    fp = filp_open(filename, O_WRONLY | O_APPEND | O_CREAT, 0644);

    ret = kernel_write(fp, data, strlen(data), &fp->f_pos);

    filp_close(fp, NULL);

    mutex_unlock(&packet_mtx);

    return ret;
}