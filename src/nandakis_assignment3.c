/**
 * @nandakis_assignment3
 * @author  Nandakishore Krishna <nandakis@buffalo.edu>
 * @version 1.0
 *
 * @section LICENSE
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of
 * the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details at
 * http://www.gnu.org/copyleft/gpl.html
 *
 * @section DESCRIPTION
 *
 * This contains the main function.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <inttypes.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include "../include/main.h"
#include "../include/packet.h"
#include "../include/routing.h"

#define BACKLOG 10
#define CTRL_HDR_SIZE 8

// listen sockets
int ctrl_sockfd;
int rout_sockfd;
int data_sockfd;

// ports
uint16_t ctrl_port;
uint16_t rout_port;
uint16_t data_port;

static fd_set read_fds;
static fd_set all_fds;
static int maxfd;

// IP is in network format
static uint32_t myip;
static uint16_t myid;

// number of routers
static uint16_t N;

// update interval
static uint16_t interval;
static struct timeval timeout;

static struct rentry *list_head = NULL;

// list DVs of neighbors
static struct DV *dv_list = NULL;

/**
 * Function to send buf
 *
 * @param s socket fd
 * @param buf the buffer
 * @param len length of data in the buffer
 *
 *  This function was taken form beej.us guide
 */
int sendall(int s, char *buf, int *len){
    int total = 0;
    // how many bytes we've sent
    int bytesleft = *len; // how many we have left to send
    int n;
    while(total < *len) {
        n = send(s, buf+total, bytesleft, 0);
        if (n == -1) { break; }
        total += n;
        bytesleft -= n;
    }   
    *len = total; // return number actually sent here
    return n==-1?-1:0; // return -1 on failure, 0 on success
}

/**
 * Function to receive data in buf
 *
 * @param s socket fd
 * @param buf the buffer
 * @param len length of data to be received
 * @return total number of bytes read
 *
 *  This function is similar to sendall in beej.us guide
 */
int recvall(int s, char *buf, int *len){
    printf("%s: E\n", __func__);
    int total = 0;
    int bytesleft = *len;
    int n = -1;
    while(total < *len) {
        n = recv(s, buf+total, bytesleft, 0);
        printf("%s: read %d bytes\n", __func__, n);
        if (n <= 0) { break; }
        total += n;
        bytesleft -= n;
    }
    *len = total;

    printf("%s: Total %d bytes\n", __func__, total);
    printf("%s: X\n", __func__);
    return (n < 0) ? -1 : 0; // return -1 on failure, 0 on success
}

/**
 * Function to create control socket and start listening
 */
void create_ctrl_sock() {
    ctrl_sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (ctrl_sockfd < 0) {
        perror("Error creating socket");
        exit(EXIT_FAILURE);
    }

    int yes;
    if (setsockopt(ctrl_sockfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) == -1) {
        perror("setsockopt");
        close(ctrl_sockfd);
        exit(EXIT_FAILURE);
    }

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(struct sockaddr_in));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(ctrl_port);

    if(bind(ctrl_sockfd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind() failed");
        close(ctrl_sockfd);
        exit(EXIT_FAILURE);
    }

    printf("%s: Control socket bind success\n", __func__);

    if(listen(ctrl_sockfd, BACKLOG) < 0) {
        perror("listen() failed");
        exit(EXIT_FAILURE);
    }

    printf("%s: Control socket listen success\n", __func__);

    FD_SET(ctrl_sockfd, &all_fds);
    maxfd = ctrl_sockfd;
}

/**
 * Function to create router socket
 */
void create_router_sock() {
    rout_sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (ctrl_sockfd < 0) {
        perror("Error creating socket");
        exit(EXIT_FAILURE);
    }

    int yes;
    if (setsockopt(rout_sockfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) == -1) {
        perror("setsockopt");
        close(rout_sockfd);
        exit(EXIT_FAILURE);
    }

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(struct sockaddr_in));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(rout_port);

    if(bind(rout_sockfd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind() failed");
        close(rout_sockfd);
        exit(EXIT_FAILURE);
    }

    printf("%s: Control socket bind success\n", __func__);

    FD_SET(rout_sockfd, &all_fds);
    if (rout_sockfd > maxfd) {
        maxfd = rout_sockfd;
    }
}

/**
 *  Router init
 */
void init() {
    FD_ZERO(&read_fds);
    FD_ZERO(&all_fds);

    // create control socket and start listening
    create_ctrl_sock();
}

/**
 * Accept the incoming control connection
 */
void accept_ctrl_conn() {
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(struct sockaddr_in));

    socklen_t len = sizeof(struct sockaddr_in);

    int fd = accept(ctrl_sockfd, (struct sockaddr *) &addr, &len);
    if (fd < 0) {
        // TODO: write a cleanup method to close all sockets
        perror("error: accept");
        close(ctrl_sockfd);
        exit(EXIT_FAILURE);
    }

    printf("%s: new ctrl connection fd=%d\n", __func__, fd);

    FD_SET(fd, &all_fds);
    if (fd > maxfd) {
        maxfd = fd;
    }
}

/**
 * Function taken from the sample written by TA
 *
 */
char* create_response_header(int sockfd, uint8_t control_code, uint8_t response_code, uint16_t payload_len)
{
    char *buffer;
    struct ctrl_resp_hdr *cntrl_resp_header;
    struct sockaddr_in addr;
    socklen_t addr_size = sizeof(struct sockaddr_in);

    buffer = malloc(sizeof(char)*CTRL_HDR_SIZE);
    memset(buffer, 0, CTRL_HDR_SIZE);

    cntrl_resp_header = (struct ctrl_resp_hdr *)buffer;
    
    getpeername(sockfd, (struct sockaddr *)&addr, &addr_size);

    /* Controller IP Address */
    memcpy(&(cntrl_resp_header->ctrl_ip), &(addr.sin_addr), sizeof(struct in_addr));
    /* Control Code */
    cntrl_resp_header->ctrl_code = control_code;
    /* Response Code */
    cntrl_resp_header->resp_code = response_code;
    /* Payload Length */
    cntrl_resp_header->payload_len = htons(payload_len);
    
    return buffer;
}

void handle_author_msg(int sockfd) {
    printf("%s: E\n", __func__);

    // payload
    char *payload = "I, nandakis, have read and understood the course academic integrity policy.";
    uint16_t len = (uint16_t)strlen(payload);

    // create header
    char *hdr = create_response_header(sockfd, (uint8_t)AUTHOR, 0, len);

    // concat header and payload
    char *buf = malloc(sizeof(char) * (len + CTRL_HDR_SIZE));
    memcpy(buf, hdr, CTRL_HDR_SIZE);
    memcpy(buf + CTRL_HDR_SIZE, payload, len);

    // send the response back
    int buflen = len + CTRL_HDR_SIZE;
    if (sendall(sockfd, buf, &buflen) == -1) {
        printf("%s: error - unable to send resp\n", __func__);
    }

    free(buf);
    free(hdr);
    printf("%s: X\n", __func__);
}

void parse_init_payload(char *payload) {
    printf("%s: E\n", __func__);

    int offset = 0;

    // number of routers
    memcpy(&N, payload + offset, sizeof(uint16_t));
    N = ntohs(N);
    printf("%s: Number of routers %" PRIu16 "\n", __func__, N);

    // update interval
    offset = sizeof(uint16_t);
    memcpy(&interval, payload + offset, sizeof(uint16_t));
    interval = ntohs(interval);
    printf("%s: Update interval %" PRIu16 "\n", __func__, interval);

    offset += sizeof(uint16_t);
    for(int i = 0; i < N; ++i) {

        // create an entry and populate it
        struct rentry *entry = malloc(sizeof(struct rentry));
        memset(entry, 0, sizeof(struct rentry));

        memcpy(&entry->id, payload + offset, sizeof(entry->id));
        offset += sizeof(entry->id);
        entry->id = ntohs(entry->id);
        printf("%s: Router id %" PRIu16 "\n", __func__, entry->id);

        memcpy(&entry->rout_port, payload + offset, sizeof(entry->rout_port));
        offset += sizeof(entry->rout_port);
        entry->rout_port = ntohs(entry->rout_port);
        printf("%s: Router port %" PRIu16 "\n", __func__, entry->rout_port);

        memcpy(&entry->data_port, payload + offset, sizeof(entry->data_port));
        offset += sizeof(entry->data_port);
        entry->data_port = ntohs(entry->data_port);
        printf("%s: Data port %" PRIu16 "\n", __func__, entry->data_port);

        memcpy(&entry->cost, payload + offset, sizeof(entry->cost));
        offset += sizeof(entry->cost);
        entry->cost = ntohs(entry->cost);
        printf("%s: Cost %" PRIu16 "\n", __func__, entry->cost);

        memcpy(&entry->ipaddr, payload + offset, sizeof(entry->ipaddr));
        offset += sizeof(entry->ipaddr);

        char ipstr[INET_ADDRSTRLEN];
        if (inet_ntop(AF_INET, &(entry->ipaddr), ipstr, INET_ADDRSTRLEN) != NULL) {
            printf("%s: IP address %s \n", __func__, ipstr);
        }

        // add this entry to the list
        if (list_head == NULL) {
            list_head = entry;
        } else {
            struct rentry *iter = list_head;
            while(iter->next != NULL) {
                iter = iter->next;
            }
            iter->next = entry;
        }

        // get this router's id
        if (entry->cost == 0) {
            myid = entry->id;
            rout_port = entry->rout_port;
            data_port = entry->data_port;
        }

        // check if neighbor
        if (entry->cost == INF || entry->cost == 0) {
            entry->is_neighbor = 0;
        } else {
            printf("%s: Neigbor id %" PRIu16 "\n", __func__, entry->id);
            entry->is_neighbor = 1;
        }
    }

    printf("%s: X\n", __func__);
}

/**
 * Function to send msg using UDP
 */
void send_udp_msg(char *msg, int len, uint32_t destip, uint16_t destport){
    printf("%s: E\n", __func__);

    // create a UDP socket
    int sfd = socket(AF_INET, SOCK_DGRAM, 0);

    if (sfd == -1) {
        perror("Error creating UDP socket");
        exit(EXIT_FAILURE);
    }

    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(struct sockaddr_in));
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = destip;
    sa.sin_port = htons(destport);

    // connect, just to use send()
    if (connect(sfd, (const struct sockaddr*) &sa, sizeof(struct sockaddr_in)) == -1) {
        perror("Error connecting");
        exit(EXIT_FAILURE);
    }

    //send the message
    int msglen = len;
    if (sendall(sfd, msg, &msglen) == -1) {
        printf("%s: error - unable to send message\n", __func__);
    }
 
    close(sfd);

    printf("%s: X\n", __func__);
}

char* create_dv_packet(int *len) {
    *len = sizeof(struct dv_hdr) + N * sizeof(struct dv_entry);
    char *buf = malloc(*len);
    int offset = 0;

    // create header
    struct dv_hdr header;
    header.n = htons(N);
    header.src_port = htons(rout_port);
    header.src_ipaddr = myip;

    memcpy(buf, &header, sizeof(struct dv_hdr));
    offset += sizeof(struct dv_hdr);

    struct rentry *iter = list_head;
    while(iter != NULL) {
        struct dv_entry entry;

        entry.ipaddr = iter->ipaddr;
        entry.port = htons(iter->rout_port);
        entry.padding = 0;
        entry.id = htons(iter->id);
        entry.cost = htons(iter->cost);

        memcpy(buf + offset, &entry, sizeof(struct dv_entry));
        offset += sizeof(struct dv_entry);

        iter = iter->next;
    }

    return buf;
}

/**
 *
 * Advertise DV to neighbors
 *
 */
void send_dv() {
    printf("%s: E\n", __func__);

    int len;
    char *msg = create_dv_packet(&len);

    struct rentry *iter = list_head;
    while(iter != NULL) {
        if (iter->is_neighbor) {
            printf("%s: sending dv update to id %" PRIu16 "\n", __func__, iter->id);
            send_udp_msg(msg, len, iter->ipaddr, iter->rout_port);
        }
        iter = iter->next;
    }

    free(msg);
    printf("%s: X\n", __func__);
}

void start_router() {
    printf("%s: E\n", __func__);

    // create scoket and listen on routing port
    create_router_sock();

    // send DV to neighbors
    send_dv();

    printf("%s: X\n", __func__);
}

void handle_ctrl_init(int sockfd, uint16_t payload_len) {
    printf("%s: E\n", __func__);

    // create response header
    char *hdr = create_response_header(sockfd, (uint8_t)INIT, 0, 0);

    // send response back
    int buflen = CTRL_HDR_SIZE;
    if (sendall(sockfd, hdr, &buflen) == -1) {
        printf("%s: error - unable to send resp\n", __func__);
    }
    free(hdr);

    char *payload = malloc(sizeof(char) * payload_len);
    printf("%s: payload len %" PRIu16 "\n", __func__, payload_len);
    int len = payload_len;
    if (recvall(sockfd, payload, &len) == -1) {
        printf("%s: recv error\n", __func__);
        goto end;
    }

    printf("%s: received init payload\n", __func__);

    // parse the payload
    parse_init_payload(payload);

    // start listening for routing and data updates
    start_router();

end:
    free(payload);
    printf("%s: X\n", __func__);
}

void handle_ctrl_msg(int sockfd) {
    printf("%s: E\n", __func__);

    char *buf = malloc(sizeof(char) * CTRL_HDR_SIZE);
    memset(buf, 0, CTRL_HDR_SIZE);

    int len = CTRL_HDR_SIZE;
    if (recvall(sockfd, buf, &len) == -1) {
       printf("%s: recv error\n", __func__);
       close(sockfd);
       FD_CLR(sockfd, &all_fds);
       goto end;
    }

    if (len == 0) {
        // control connection closed
        printf("%s: ctrl conn %d closed\n", __func__, sockfd);
        close(sockfd);
        FD_CLR(sockfd, &all_fds);
        goto end;
    }

    struct ctrl_hdr *control_hdr = (struct ctrl_hdr *)buf;
    printf("%s: Response time limit %" PRIu8 "\n", __func__, control_hdr->resp_time);
    myip = control_hdr->destip;
    uint16_t payload_len = ntohs(control_hdr->payload_len);

    switch(control_hdr->ctrl_code) {
        case AUTHOR:
            handle_author_msg(sockfd);
            break;
        case INIT:
            handle_ctrl_init(sockfd, payload_len);
            break;
        case ROUTING_TABLE:
            break;
        case UPDATE:
            break;
        case CRASH:
            break;
        case SENDFILE:
            break;
        case SENDFILE_STATS:
            break;
        case LAST_DATA_PACKET:
            break;
        case PENULTIMATE_DATA_PACKET:
            break;
        default:
            printf("Error: unknown control code\n");
            break;
    }

end:
    free(buf);
    printf("%s: X\n", __func__);
}

void handle_timeout() {
}

/**
 * Function to get cost to neigbor, cost from neighbor to dest.
 *
 * @param neighborid Router id of the neighbor
 * @param destid Destination router id
 * @param neighbor_cost will be filled with cost to the neighbor
 */
uint16_t get_cost_frm_neighbor(uint16_t neighborid, uint16_t destid) {
    struct DV *iter = dv_list;
    while (iter != NULL && iter->id != neighborid) {
        iter = iter->next;
    }

    if (iter == NULL || iter->id != neighborid) {
        // the neighbor's DV was not found
        printf("%s: DV for neighbor %" PRIu16 " not found\n", __func__, neighborid);
        return INF;
    }

    for (int i = 0; i < N; ++i) {
        struct dv_entry *entry = &iter->entries[i];
        if (entry->id == destid) {
            printf("%s: neighborid %" PRIu16 " destid %" PRIu16 " cost %" PRIu16 "\n", __func__, neighborid, destid, entry->cost);
            return entry->cost;
        }
    }
}

/**
 * Function to store DV update from neighbor
 *
 * @return the id of the neigbor from which this DV was received
 */
uint16_t add_dv_tolist(char *buf) {
    printf("%s: E\n", __func__);

    struct DV *newdv = malloc(sizeof(struct DV));
    memset(newdv, 0, sizeof(struct DV));

    struct dv_hdr *header = malloc(sizeof(struct dv_hdr));
    memcpy(header, buf, sizeof(struct dv_hdr));

    struct dv_entry *entries = malloc(N * sizeof(struct dv_entry));
    memcpy(entries, buf + sizeof(struct dv_hdr), N * sizeof(struct dv_entry));

    // convert network to host
    header->n = ntohs(header->n);
    header->src_port = ntohs(header->src_port);
    newdv->header = header;

    for (int i = 0; i < N; ++i) {
        entries[i].port = ntohs(entries[i].port);
        entries[i].id = ntohs(entries[i].id);
        entries[i].cost = ntohs(entries[i].cost);
    }
    newdv->entries = entries;

    struct rentry *iter = list_head;
    while (iter != NULL) {
        if (iter->ipaddr == header->src_ipaddr && iter->cost != 0) {
            newdv->id = iter->id;

            // reset the missed count
            iter->update_missed = 0;
            break;
        }
        iter = iter->next;
    }

    if (dv_list == NULL) {
        dv_list = newdv;
    } else {
        struct DV *list_iter = dv_list;
        struct DV *prev = list_iter;

        while (list_iter->next != NULL && list_iter->id != newdv->id) {
            prev = list_iter;
            list_iter = list_iter->next;
        }

        if (list_iter->id == newdv->id) {
            // update the existing entry
            struct DV *existing = list_iter;
            free(existing->header);
            free(existing->entries);
            newdv->next = existing->next;
            prev->next = newdv;
            free(existing);
        } else {
            list_iter->next = newdv;
        }
    }

    printf("%s: Added DV from id %" PRIu16 " to list\n", __func__, newdv->id);

    printf("%s: X\n", __func__);
    return newdv->id;
}

/**
 * Function to update this node's DV
 */
void update_dv(uint16_t neighborid) {
    printf("%s: E\n", __func__);

    struct rentry *iter = list_head;
    while (iter != NULL) {
        if (iter->id != myid) {
            uint16_t min_cost = INF;
            struct rentry *riter = list_head;
            while(riter != NULL) {
                if (riter->is_neighbor) {
                    uint16_t total = get_cost_frm_neighbor(riter->id, iter->id) + riter->cost;
                    if (total < min_cost) {
                        min_cost = total;
                    }
                }
                riter = riter->next;
            }

            // update the cost with min_cost
            iter->cost = min_cost;
            printf("%s: New cost to %" PRIu16 " is %" PRIu16 "\n", __func__, iter->id, iter->cost);
        }

        iter = iter->next;
    }

    printf("%s: X\n", __func__);
}

void handle_dv_update(int sockfd) {
    printf("%s: E\n", __func__);

    int len = sizeof(struct dv_hdr) + N * sizeof(struct dv_entry);
    char *buf = malloc(len);

    if (recvall(sockfd, buf, &len) == -1) {
        printf("%s: recv error\n", __func__);
        goto end;
    }

    /*
    struct dv_hdr *header = (struct dv_hdr *)buf;
    printf("%s: N %" PRIu16 ",src port %" PRIu16 "\n", __func__, ntohs(header->n), ntohs(header->src_port));
    char ipstr[INET_ADDRSTRLEN];
    if (inet_ntop(AF_INET, &(header->src_ipaddr), ipstr, INET_ADDRSTRLEN) != NULL) {
        printf("%s: IP address %s \n", __func__, ipstr);
    }

    int offset = sizeof(struct dv_hdr);
    for (int i = 0; i < N; ++i) {
        struct dv_entry *entry = (struct dv_entry *)(buf + offset);
        printf("%s: port %" PRIu16 ", Id %" PRIu16 ", Cost %" PRIu16, __func__, ntohs(entry->port), ntohs(entry->id), ntohs(entry->cost));

        if (inet_ntop(AF_INET, &(entry->ipaddr), ipstr, INET_ADDRSTRLEN) != NULL) {
            printf(",IP address %s \n", ipstr);
        }

        offset += sizeof(struct dv_entry);
    }
    */

    // update the neighbor dv list
    uint16_t neighborid = add_dv_tolist(buf);

    // update my DV
    update_dv(neighborid);

end:
    free(buf);

    printf("%s: X\n", __func__);
}

void start_event_loop() {
    printf("%s: E\n", __func__);
    int ret;

    while(1) {
        read_fds = all_fds;
        ret = select(maxfd + 1, &read_fds, NULL, NULL, NULL);
        if (ret == -1) {
            perror("error: select");
            exit(EXIT_FAILURE);
        }

        if (ret == 0) {
            // timeout
            handle_timeout();
        } else {
            for (int i = 0; i <= maxfd; ++i) {
                if (FD_ISSET(i, &read_fds)) {
                    if (i == ctrl_sockfd) {
                        accept_ctrl_conn();
                    } else if (i == rout_sockfd){
                        handle_dv_update(i);
                    } else if (i == data_sockfd) {
                        // data connection
                    } else {
                        handle_ctrl_msg(i);
                    }
                }
            }
        }
    }
    printf("%s: X\n", __func__);
}

void get_ctrl_port(char *port) {
    char *str = port;
    char *endptr;
    errno = 0;

    long val = strtol(str, &endptr, 10);
    if (errno || endptr == str || val > 65535 || val < 0) {
        printf("error: invalid port\n");
        exit(EXIT_FAILURE);
    }

    ctrl_port = (uint16_t)val;

    printf("control port %" PRIu16 "\n", ctrl_port);
}

/**
 * main function
 *
 * @param  argc Number of arguments
 * @param  argv The argument list
 * @return 0 EXIT_SUCCESS
 */
int main(int argc, char **argv) {

    if (argc != 2) {
        printf("Usage: ./%s <control_port>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    // extract control port
    get_ctrl_port(argv[1]);

    // init the select lists, control socket and start listening for control connections
    init();

    start_event_loop();

    return 0;
}
