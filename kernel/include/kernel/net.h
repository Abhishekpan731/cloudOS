#ifndef KERNEL_NET_H
#define KERNEL_NET_H

#include "types.h"

#define MAX_NETWORK_INTERFACES 8
#define MAX_SOCKETS 1024
#define MTU_SIZE 1500
#define ETH_ADDR_LEN 6
#define IP_ADDR_LEN 4
#define MAX_PACKET_SIZE 2048

// Ethernet header
typedef struct eth_header {
    uint8_t dest_mac[ETH_ADDR_LEN];
    uint8_t src_mac[ETH_ADDR_LEN];
    uint16_t ethertype;
} __attribute__((packed)) eth_header_t;

// IP header
typedef struct ip_header {
    uint8_t version_ihl;
    uint8_t tos;
    uint16_t total_length;
    uint16_t identification;
    uint16_t flags_fragment;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t checksum;
    uint32_t src_addr;
    uint32_t dest_addr;
} __attribute__((packed)) ip_header_t;

// TCP header
typedef struct tcp_header {
    uint16_t src_port;
    uint16_t dest_port;
    uint32_t seq_num;
    uint32_t ack_num;
    uint8_t data_offset_flags;
    uint8_t flags;
    uint16_t window_size;
    uint16_t checksum;
    uint16_t urgent_ptr;
} __attribute__((packed)) tcp_header_t;

// UDP header
typedef struct udp_header {
    uint16_t src_port;
    uint16_t dest_port;
    uint16_t length;
    uint16_t checksum;
} __attribute__((packed)) udp_header_t;

// Network packet
typedef struct net_packet {
    uint8_t* data;
    size_t size;
    size_t capacity;
    struct net_packet* next;
} net_packet_t;

// Network interface
typedef struct net_interface {
    char name[16];
    uint8_t mac_addr[ETH_ADDR_LEN];
    uint32_t ip_addr;
    uint32_t netmask;
    uint32_t gateway;
    bool up;
    uint64_t bytes_sent;
    uint64_t bytes_received;
    uint64_t packets_sent;
    uint64_t packets_received;

    int (*send)(struct net_interface* iface, net_packet_t* packet);
    int (*receive)(struct net_interface* iface, net_packet_t* packet);
    void* private_data;
    struct net_interface* next;
} net_interface_t;

// Socket types
typedef enum {
    SOCK_STREAM = 1,  // TCP
    SOCK_DGRAM = 2,   // UDP
    SOCK_RAW = 3      // Raw socket
} socket_type_t;

// Socket states
typedef enum {
    SOCKET_CLOSED = 0,
    SOCKET_LISTEN = 1,
    SOCKET_SYN_SENT = 2,
    SOCKET_SYN_RECEIVED = 3,
    SOCKET_ESTABLISHED = 4,
    SOCKET_FIN_WAIT1 = 5,
    SOCKET_FIN_WAIT2 = 6,
    SOCKET_CLOSE_WAIT = 7,
    SOCKET_CLOSING = 8,
    SOCKET_LAST_ACK = 9,
    SOCKET_TIME_WAIT = 10
} socket_state_t;

// Socket address
typedef struct sockaddr_in {
    uint16_t sin_family;
    uint16_t sin_port;
    uint32_t sin_addr;
    uint8_t sin_zero[8];
} sockaddr_in_t;

// Socket structure
typedef struct socket {
    int fd;
    socket_type_t type;
    socket_state_t state;
    uint32_t local_addr;
    uint16_t local_port;
    uint32_t remote_addr;
    uint16_t remote_port;

    // TCP specific
    uint32_t seq_num;
    uint32_t ack_num;
    uint16_t window_size;

    // Packet queues
    net_packet_t* rx_queue;
    net_packet_t* tx_queue;

    // Wait queues for blocking operations
    void* wait_queue;

    struct socket* next;
} socket_t;

// Protocol numbers
#define IPPROTO_ICMP    1
#define IPPROTO_TCP     6
#define IPPROTO_UDP     17

// TCP flags
#define TCP_FIN         0x01
#define TCP_SYN         0x02
#define TCP_RST         0x04
#define TCP_PSH         0x08
#define TCP_ACK         0x10
#define TCP_URG         0x20

// Ethernet types
#define ETH_TYPE_IP     0x0800
#define ETH_TYPE_ARP    0x0806

// Network stack initialization
int net_init(void);

// Interface management
int net_register_interface(net_interface_t* iface);
net_interface_t* net_find_interface(const char* name);
int net_interface_up(const char* name);
int net_interface_down(const char* name);
int net_set_ip_address(const char* name, uint32_t ip, uint32_t netmask, uint32_t gateway);

// Packet handling
net_packet_t* net_alloc_packet(size_t size);
void net_free_packet(net_packet_t* packet);
int net_send_packet(net_interface_t* iface, net_packet_t* packet);
void net_receive_packet(net_interface_t* iface, net_packet_t* packet);

// Layer 2 (Ethernet)
int eth_send(net_interface_t* iface, const uint8_t* dest_mac, uint16_t ethertype,
             const void* data, size_t size);
void eth_receive(net_interface_t* iface, net_packet_t* packet);

// Layer 3 (IP)
int ip_send(uint32_t dest_ip, uint8_t protocol, const void* data, size_t size);
void ip_receive(net_interface_t* iface, net_packet_t* packet);
uint32_t ip_route(uint32_t dest_ip);

// Layer 4 (TCP/UDP)
int tcp_send(socket_t* sock, const void* data, size_t size);
void tcp_receive(net_interface_t* iface, net_packet_t* packet);
int udp_send(uint32_t dest_ip, uint16_t dest_port, uint16_t src_port,
             const void* data, size_t size);
void udp_receive(net_interface_t* iface, net_packet_t* packet);

// Socket API
struct sockaddr;
typedef uint32_t socklen_t;

int net_socket(int domain, int type, int protocol);
int net_bind(int sockfd, const struct sockaddr* addr, socklen_t addrlen);
int net_listen(int sockfd, int backlog);
int net_accept(int sockfd, struct sockaddr* addr, socklen_t* addrlen);
int net_connect(int sockfd, const struct sockaddr* addr, socklen_t addrlen);
ssize_t net_send(int sockfd, const void* buf, size_t len, int flags);
ssize_t net_recv(int sockfd, void* buf, size_t len, int flags);
ssize_t net_sendto(int sockfd, const void* buf, size_t len, int flags,
                   const struct sockaddr* dest_addr, socklen_t addrlen);
ssize_t net_recvfrom(int sockfd, void* buf, size_t len, int flags,
                     struct sockaddr* src_addr, socklen_t* addrlen);
int net_close(int sockfd);

// Utility functions
uint16_t net_checksum(const void* data, size_t size);
uint32_t net_htonl(uint32_t hostlong);
uint16_t net_htons(uint16_t hostshort);
uint32_t net_ntohl(uint32_t netlong);
uint16_t net_ntohs(uint16_t netshort);

// Loopback interface
int loopback_init(void);

#endif
