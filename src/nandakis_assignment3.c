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
#include "../include/main.h"
#include "../include/packet.h"

#define BACKLOG 10
#define CTRL_HDR_SIZE 8

// listen sockets
int ctrl_sockfd;
int rout_sockfd;
int data_sockfd;

//control port
uint16_t ctrl_port;

static fd_set read_fds;
static fd_set all_fds;
static int maxfd;

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
 *
 *  This function is similar to sendall in beej.us guide
 */
int recvall(int s, char *buf, int *len){
    int total = 0;
    int bytesleft = *len;
    int n = 0;
    while(total < *len) {
        n = recv(s, buf+total, bytesleft, 0);
        if (n == -1) { break; }
        total += n;
        bytesleft -= n;
    }   
    *len = total;
    return n==-1?-1:0; // return -1 on failure, 0 on success
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

    buffer = (char *) malloc(sizeof(char)*CTRL_HDR_SIZE);
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
        printf("Error: unable to send AUTHOR resp");
    }

    free(buf);
    free(hdr);
}

void handle_ctrl_msg(int sockfd) {

    char *buf;

    buf = malloc(sizeof(char) * CTRL_HDR_SIZE);
    memset(buf, 0, CTRL_HDR_SIZE);

    int len = CTRL_HDR_SIZE;
    if (recvall(sockfd, buf, &len) == -1) {
       printf("recv error");
       free(buf);
       return;
    }

    struct ctrl_hdr *control_hdr = (struct ctrl_hdr *)buf;
    switch(control_hdr->ctrl_code) {
        case AUTHOR:
            handle_author_msg(sockfd);
            break;
        case INIT:
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

    free(buf);
}

void start_router() {
    int ret;

    while(1) {
        read_fds = all_fds;
        if (select(maxfd + 1, &read_fds, NULL, NULL, NULL) == -1) {
            perror("error: select");
            exit(EXIT_FAILURE);
        }

        for (int i = 0; i <= maxfd; ++i) {
            if (FD_ISSET(i, &read_fds)) {
                if (i == ctrl_sockfd) {
                    accept_ctrl_conn();
                } else if (i == rout_sockfd){
                    // router update
                } else if (i == data_sockfd) {
                    // data connection
                } else {
                    handle_ctrl_msg(i);
                }
            }
        }
    }
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

    start_router();

    return 0;
}
