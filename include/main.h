#ifndef MAIN_H_
#define MAIN_H_

#include <stdint.h>

enum ctrlcode_t {AUTHOR, INIT, ROUTING_TABLE, UPDATE, CRASH, SENDFILE, SENDFILE_STATS, LAST_DATA_PACKET, PENULTIMATE_DATA_PACKET};

// infinity value - Largest unsigned integer that can be represented in 2 bytes
const uint16_t INF = 0xFF;
#endif
