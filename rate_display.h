#ifndef __RATE_DISPLAY_H__
#define __RATE_DISPLAY_H__
#include <sys/time.h>
#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
#include <inttypes.h>

struct rate_display
{
    uint64_t ra_size;
    uint64_t ra_time;
};

static inline void rate_display(struct rate_display *dis, unsigned long size, const char *prompt, const char *uint)
{
    uint64_t now;
    struct timeval tv;

    gettimeofday(&tv, NULL);
    now = tv.tv_sec * 1000000 + tv.tv_usec;

    dis->ra_size += size;
    if(dis->ra_time == 0) {
        dis->ra_time = now;
    } else if((now - dis->ra_time) >= 5000000) {
        printf("%s %" PRIu64 " %s/s\n", prompt, (dis->ra_size * 1000000) / (now - dis->ra_time), uint);
        dis->ra_time = now;
        dis->ra_size = 0;
    }
}

#endif
