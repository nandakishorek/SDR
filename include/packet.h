#ifndef PACKET_H_
#define PACKET_H_

struct __attribute__((__packed__)) ctrl_hdr {
    uint32_t destip;
    uint8_t ctrl_code;
    uint8_t resp_time;
    uint16_t payload_len;
};

struct __attribute__((__packed__)) ctrl_resp_hdr {
    uint32_t ctrl_ip;
    uint8_t ctrl_code;
    uint8_t resp_code;
    uint16_t payload_len;
};

#endif
