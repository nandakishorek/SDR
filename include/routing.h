#ifndef ROUTING_H_
#define ROUTING_H_

struct rentry {
    uint16_t id;
    uint16_t rout_port;
    uint16_t data_port;
    uint16_t cost;
    uint16_t hopid;
    uint32_t ipaddr; // network format
    uint8_t is_neighbor;
    uint8_t update_missed;
    struct timeval start_time;
    struct rentry *next;
};

struct __attribute__((__packed__)) dv_hdr {
    uint16_t n;
    uint16_t src_port;
    uint32_t src_ipaddr;
};

struct __attribute__((__packed__)) dv_entry {
    uint32_t ipaddr;
    uint16_t port;
    uint16_t padding;
    uint16_t id;
    uint16_t cost;
};

struct __attribute__((__packed__)) DV {
    uint16_t id;
    struct dv_hdr *header;
    struct dv_entry *entries;
    struct DV *next;
};

// timer queue entry
struct tentry {
    uint16_t id;
    struct timeval start_time;
    struct tentry *next;
};
#endif
