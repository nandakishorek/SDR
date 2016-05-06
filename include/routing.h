#ifndef ROUTING_H_
#define ROUTING_H_

#define DATA_PYLD_SIZE 1024
#define DATA_PYLD_OFFSET 12
#define FIN ((uint32_t)1 << 31)

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

struct DV {
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

// data packet to be routed
struct __attribute__((__packed__)) datapkt {
    uint32_t destip;
    uint8_t transfer_id;
    uint8_t ttl;
    uint16_t seqnum;
    uint32_t fin; // set MSB for FIN flag
    char payload[DATA_PYLD_SIZE];
};

// transfer id - related seqnums and ttl
struct transfer {
    uint8_t transfer_id;
    uint8_t ttl;
    uint16_t start_seqnum;
    uint16_t end_seqnum;
    struct transfer *next;
};
#endif
