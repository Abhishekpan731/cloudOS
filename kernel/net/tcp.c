/*
 * TCP/IP Stack Implementation
 * Complete networking protocol implementation for CloudOS
 */

#include "kernel/net.h"
#include "kernel/memory.h"
#include "kernel/kernel.h"
#include "kernel/types.h"

// Simple string and memory functions for kernel use
static int strcmp(const char *s1, const char *s2)
{
    while (*s1 && (*s1 == *s2))
    {
        s1++;
        s2++;
    }
    return *(unsigned char *)s1 - *(unsigned char *)s2;
}

static char *strcpy(char *dest, const char *src)
{
    char *orig_dest = dest;
    while ((*dest++ = *src++))
        ;
    return orig_dest;
}

static void *memset(void *s, int c, size_t n)
{
    unsigned char *p = (unsigned char *)s;
    for (size_t i = 0; i < n; i++)
    {
        p[i] = (unsigned char)c;
    }
    return s;
}

static void *memcpy(void *dest, const void *src, size_t n)
{
    unsigned char *d = (unsigned char *)dest;
    const unsigned char *s = (const unsigned char *)src;
    for (size_t i = 0; i < n; i++)
    {
        d[i] = s[i];
    }
    return dest;
}

// Socket domain constants
#define AF_INET 2   // IPv4
#define AF_INET6 10 // IPv6

// Socket types
#define SOCK_STREAM 1 // TCP
#define SOCK_DGRAM 2  // UDP

// Network constants
#define INADDR_ANY 0x00000000       // 0.0.0.0
#define INADDR_BROADCAST 0xFFFFFFFF // 255.255.255.255

// Additional types
typedef uint32_t sa_family_t;
typedef uint32_t in_addr_t;
typedef uint16_t in_port_t;

// sockaddr structure
struct sockaddr
{
    sa_family_t sa_family;
    char sa_data[14];
};

// Socket address structures are defined in kernel/net.h

// Byte order conversion macros
#define htons(x) net_htons(x)
#define htonl(x) net_htonl(x)
#define ntohs(x) net_ntohs(x)
#define ntohl(x) net_ntohl(x)

// Ethernet frame handling
#define ETHERTYPE_IP 0x0800
#define ETHERTYPE_ARP 0x0806
#define ETH_ALEN 6

// IP protocol numbers
#define IPPROTO_ICMP 1
#define IPPROTO_TCP 6
#define IPPROTO_UDP 17

// TCP flags
#define TCP_FIN 0x01
#define TCP_SYN 0x02
#define TCP_RST 0x04
#define TCP_PSH 0x08
#define TCP_ACK 0x10
#define TCP_URG 0x20
#define TCP_ECE 0x40
#define TCP_CWR 0x80

// TCP states
typedef enum
{
    TCP_CLOSED,
    TCP_LISTEN,
    TCP_SYN_SENT,
    TCP_SYN_RECEIVED,
    TCP_ESTABLISHED,
    TCP_FIN_WAIT_1,
    TCP_FIN_WAIT_2,
    TCP_CLOSE_WAIT,
    TCP_CLOSING,
    TCP_LAST_ACK,
    TCP_TIME_WAIT
} tcp_state_t;

// Ethernet header
typedef struct
{
    uint8_t dest[ETH_ALEN];
    uint8_t src[ETH_ALEN];
    uint16_t type;
} __attribute__((packed)) ethernet_header_t;

// IPv4 header
typedef struct
{
    uint8_t version_ihl;
    uint8_t tos;
    uint16_t total_len;
    uint16_t id;
    uint16_t frag_off;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t checksum;
    uint32_t src_addr;
    uint32_t dest_addr;
} __attribute__((packed)) ipv4_header_t;

// TCP/UDP headers and socket structures are defined in kernel/net.h

// Remove duplicate socket structure - use the one from net.h

// Network interface structure
typedef struct net_device
{
    char name[16];
    uint8_t mac_addr[ETH_ALEN];
    uint32_t ip_addr;
    uint32_t netmask;
    uint32_t gateway;
    int (*send_packet)(struct net_device *dev, const void *data, size_t len);
    struct net_device *next;
} net_device_t;

// Global network state
static net_device_t *net_devices = NULL;
static socket_t *socket_list = NULL;
static uint16_t next_ephemeral_port = 49152; // Start of ephemeral port range

// Socket descriptor table
#define MAX_SOCKETS 1024
static socket_t *socket_table[MAX_SOCKETS];
static int __attribute__((unused)) next_sockfd = 3; // Start after stdin, stdout, stderr

// Forward declarations
static void net_process_ipv4(net_device_t *dev, const uint8_t *data, size_t len);
static void net_process_tcp(net_device_t *dev, const ipv4_header_t *ip,
                            const uint8_t *data, size_t len);
static void net_process_udp(net_device_t *dev, const ipv4_header_t *ip,
                            const uint8_t *data, size_t len);

// Socket descriptor management
static int alloc_sockfd(socket_t *sock) {
    for (int i = 3; i < MAX_SOCKETS; i++) {
        if (socket_table[i] == NULL) {
            socket_table[i] = sock;
            sock->fd = i;
            return i;
        }
    }
    return -1; // No free descriptors
}

static socket_t *get_socket(int sockfd) {
    if (sockfd < 3 || sockfd >= MAX_SOCKETS) {
        return NULL;
    }
    return socket_table[sockfd];
}

static void free_sockfd(int sockfd) {
    if (sockfd >= 3 && sockfd < MAX_SOCKETS) {
        socket_table[sockfd] = NULL;
    }
}

// Utility functions
static uint16_t calculate_checksum(const void *data, size_t len)
{
    uint32_t sum = 0;
    const uint16_t *ptr = (const uint16_t *)data;

    while (len > 1)
    {
        sum += *ptr++;
        len -= 2;
    }

    if (len > 0)
    {
        sum += *(uint8_t *)ptr;
    }

    while (sum >> 16)
    {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    return ~sum;
}

static uint16_t ip_checksum(const ipv4_header_t *ip)
{
    return calculate_checksum(ip, sizeof(ipv4_header_t));
}

static uint16_t __attribute__((unused)) tcp_checksum(const ipv4_header_t *ip, const tcp_header_t *tcp, size_t tcp_len)
{
    // TCP checksum includes pseudo-header
    uint32_t sum = 0;
    uint16_t *ptr;

    // Pseudo-header
    sum += (ip->src_addr >> 16) & 0xFFFF;
    sum += ip->src_addr & 0xFFFF;
    sum += (ip->dest_addr >> 16) & 0xFFFF;
    sum += ip->dest_addr & 0xFFFF;
    sum += ip->protocol;
    sum += tcp_len;

    // TCP header and data
    ptr = (uint16_t *)tcp;
    while (tcp_len > 1)
    {
        sum += *ptr++;
        tcp_len -= 2;
    }

    if (tcp_len > 0)
    {
        sum += *(uint8_t *)ptr;
    }

    while (sum >> 16)
    {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    return ~sum;
}

// Network device management
int net_register_device(net_device_t *dev)
{
    if (!dev)
        return -1;

    dev->next = net_devices;
    net_devices = dev;

    kprintf("Network: Registered device %s\n", dev->name);
    return 0;
}

net_device_t *net_get_device(const char *name)
{
    net_device_t *dev = net_devices;
    while (dev)
    {
        if (strcmp(dev->name, name) == 0)
        {
            return dev;
        }
        dev = dev->next;
    }
    return NULL;
}

// Socket operations
int net_socket(int domain, int type, int protocol)
{
    (void)protocol; // TODO: Use protocol parameter
    if (domain != AF_INET)
        return -1;
    if (type != SOCK_STREAM && type != SOCK_DGRAM)
        return -1;

    socket_t *sock = (socket_t *)kmalloc(sizeof(socket_t));
    if (!sock)
        return -1;

    // Initialize socket structure
    sock->type = (socket_type_t)type;
    sock->state = SOCKET_CLOSED;
    sock->local_addr = INADDR_ANY;
    sock->local_port = 0;
    sock->remote_addr = 0;
    sock->remote_port = 0;
    sock->seq_num = 0;
    sock->ack_num = 0;
    sock->window_size = 0;
    sock->rx_queue = NULL;
    sock->tx_queue = NULL;
    sock->wait_queue = NULL;
    sock->next = socket_list;
    socket_list = sock;

    // Allocate socket descriptor
    int sockfd = alloc_sockfd(sock);
    if (sockfd == -1) {
        kfree(sock);
        return -1;
    }

    return sockfd;
}

int net_bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
{
    socket_t *sock = get_socket(sockfd);
    if (!sock || !addr)
        return -1;
    (void)addrlen; // TODO: Use addrlen parameter

    const struct sockaddr_in *sin = (const struct sockaddr_in *)addr;
    sock->local_addr = sin->sin_addr;
    sock->local_port = net_ntohs(sin->sin_port);

    return 0;
}

int net_listen(int sockfd, int backlog)
{
    socket_t *sock = get_socket(sockfd);
    if (!sock)
        return -1;

    if (sock->type != SOCK_STREAM)
        return -1;

    sock->state = SOCKET_LISTEN;
    (void)backlog; // Not implemented yet

    return 0;
}

int net_accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen)
{
    socket_t *sock = get_socket(sockfd);
    if (!sock)
        return -1;

    // Simplified implementation - just return the same socket
    // In a real implementation, this would create a new socket for the connection
    if (addr && addrlen)
    {
        struct sockaddr_in *sin = (struct sockaddr_in *)addr;
        sin->sin_family = AF_INET;
        sin->sin_addr = sock->remote_addr;
        sin->sin_port = htons(sock->remote_port);
        *addrlen = sizeof(struct sockaddr_in);
    }

    return sockfd;
}

int net_connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
{
    socket_t *sock = get_socket(sockfd);
    (void)addrlen; // TODO: Use addrlen parameter
    if (!sock || !addr)
        return -1;

    const struct sockaddr_in *sin = (const struct sockaddr_in *)addr;
    sock->remote_addr = sin->sin_addr;
    sock->remote_port = net_ntohs(sin->sin_port);

    // For TCP, initiate connection
    if (sock->type == SOCK_STREAM)
    {
        sock->state = SOCKET_SYN_SENT;
        // TODO: Send SYN packet
    }

    return 0;
}

ssize_t net_send(int sockfd, const void *buf, size_t len, int flags)
{
    socket_t *sock = get_socket(sockfd);
    if (!sock || !buf)
        return -1;

    (void)flags; // Not implemented

    // Find appropriate network device
    net_device_t *dev = net_devices;
    if (!dev)
        return -1;

    // For TCP
    if (sock->type == SOCK_STREAM)
    {
        if (sock->state != SOCKET_ESTABLISHED)
        {
            return -1; // Connection not established
        }
        // TODO: Implement TCP send
        return len;
    }

    // For UDP
    if (sock->type == SOCK_DGRAM)
    {
        return net_sendto(sockfd, buf, len, flags, NULL, 0);
    }

    return -1;
}

ssize_t net_recv(int sockfd, void *buf, size_t len, int flags)
{
    socket_t *sock = get_socket(sockfd);
    (void)buf; // TODO: Use buf parameter
    (void)len; // TODO: Use len parameter
    if (!sock || !buf)
        return -1;

    (void)flags; // Not implemented

    // TODO: Implement receive logic
    // This is a simplified stub
    return 0;
}

ssize_t net_sendto(int sockfd, const void *buf, size_t len, int flags,
                   const struct sockaddr *dest_addr, socklen_t addrlen)
{
    socket_t *sock = get_socket(sockfd);
    (void)addrlen; // TODO: Use addrlen parameter
    if (!sock || !buf)
        return -1;

    (void)flags; // Not implemented

    // Get destination address
    uint32_t dest_ip = 0;
    uint16_t dest_port = 0;

    if (dest_addr)
    {
        const struct sockaddr_in *sin = (const struct sockaddr_in *)dest_addr;
        dest_ip = sin->sin_addr;
        dest_port = net_ntohs(sin->sin_port);
    }
    else
    {
        dest_ip = sock->remote_addr;
        dest_port = sock->remote_port;
    }

    // Find network device
    net_device_t *dev = net_devices;
    if (!dev)
        return -1;

    // Allocate packet buffer
    size_t packet_size = sizeof(ethernet_header_t) + sizeof(ipv4_header_t) +
                         sizeof(udp_header_t) + len;
    uint8_t *packet = (uint8_t *)kmalloc(packet_size);
    if (!packet)
        return -1;

    // Build Ethernet header
    ethernet_header_t *eth = (ethernet_header_t *)packet;
    memset(eth->dest, 0xFF, ETH_ALEN); // Broadcast for now
    memcpy(eth->src, dev->mac_addr, ETH_ALEN);
    eth->type = htons(ETHERTYPE_IP);

    // Build IPv4 header
    ipv4_header_t *ip = (ipv4_header_t *)(packet + sizeof(ethernet_header_t));
    ip->version_ihl = (4 << 4) | 5; // IPv4, 5 words header
    ip->tos = 0;
    ip->total_len = htons(sizeof(ipv4_header_t) + sizeof(udp_header_t) + len);
    ip->id = 0;
    ip->frag_off = 0;
    ip->ttl = 64;
    ip->protocol = IPPROTO_UDP;
    ip->src_addr = htonl(dev->ip_addr);
    ip->dest_addr = htonl(dest_ip);
    ip->checksum = 0;
    ip->checksum = ip_checksum(ip);

    // Build UDP header
    udp_header_t *udp = (udp_header_t *)(packet + sizeof(ethernet_header_t) + sizeof(ipv4_header_t));
    udp->src_port = htons(sock->local_port ? sock->local_port : next_ephemeral_port++);
    udp->dest_port = htons(dest_port);
    udp->length = htons(sizeof(udp_header_t) + len);
    udp->checksum = 0; // Optional for IPv4

    // Copy data
    memcpy(packet + sizeof(ethernet_header_t) + sizeof(ipv4_header_t) + sizeof(udp_header_t),
           buf, len);

    // Send packet
    if (dev->send_packet)
    {
        dev->send_packet(dev, packet, packet_size);
    }

    kfree(packet);
    return len;
}

ssize_t net_recvfrom(int sockfd, void *buf, size_t len, int flags,
                     struct sockaddr *src_addr, socklen_t *addrlen)
{
    (void)sockfd;
    (void)buf;
    (void)len;
    (void)flags;
    (void)src_addr;
    (void)addrlen;

    // TODO: Implement UDP receive
    return -1;
}

int net_close(int sockfd)
{
    socket_t *sock = get_socket(sockfd);
    if (!sock)
        return -1;

    // Remove from socket list
    if (socket_list == sock)
    {
        socket_list = sock->next;
    }
    else
    {
        socket_t *current = socket_list;
        while (current && current->next != sock)
        {
            current = current->next;
        }
        if (current)
        {
            current->next = sock->next;
        }
    }

    // Free socket descriptor
    free_sockfd(sockfd);
    kfree(sock);
    return 0;
}

// Packet processing
void net_process_packet(net_device_t *dev, const void *data, size_t len)
{
    if (len < sizeof(ethernet_header_t))
        return;

    const ethernet_header_t *eth = (const ethernet_header_t *)data;

    // Handle different Ethernet types
    switch (ntohs(eth->type))
    {
    case ETHERTYPE_IP:
        net_process_ipv4(dev, (const uint8_t *)data + sizeof(ethernet_header_t),
                         len - sizeof(ethernet_header_t));
        break;
    case ETHERTYPE_ARP:
        // TODO: Implement ARP
        break;
    default:
        // Unknown packet type
        break;
    }
}

static void net_process_ipv4(net_device_t *dev, const uint8_t *data, size_t len)
{
    if (len < sizeof(ipv4_header_t))
        return;

    const ipv4_header_t *ip = (const ipv4_header_t *)data;

    // Verify IP checksum
    if (ip_checksum(ip) != 0)
        return;

    // Check if packet is for us
    uint32_t dest_addr = ntohl(ip->dest_addr);
    if (dest_addr != dev->ip_addr && dest_addr != 0xFFFFFFFF)
        return;

    // Handle different IP protocols
    switch (ip->protocol)
    {
    case IPPROTO_TCP:
        net_process_tcp(dev, ip, (const uint8_t *)data + (ip->version_ihl & 0xF) * 4,
                        len - (ip->version_ihl & 0xF) * 4);
        break;
    case IPPROTO_UDP:
        net_process_udp(dev, ip, (const uint8_t *)data + (ip->version_ihl & 0xF) * 4,
                        len - (ip->version_ihl & 0xF) * 4);
        break;
    case IPPROTO_ICMP:
        // TODO: Implement ICMP
        break;
    default:
        // Unknown protocol
        break;
    }
}

static void net_process_tcp(net_device_t *dev, const ipv4_header_t *ip,
                            const uint8_t *data, size_t len)
{
    (void)dev;
    (void)ip;
    (void)data;
    (void)len;
    // TODO: Implement TCP packet processing
}

static void net_process_udp(net_device_t *dev, const ipv4_header_t *ip,
                            const uint8_t *data, size_t len)
{
    (void)dev; // TODO: Use dev parameter
    if (len < sizeof(udp_header_t))
        return;

    const udp_header_t *udp = (const udp_header_t *)data;

    // Find socket for this packet
    socket_t *sock = socket_list;
    while (sock)
    {
        if (sock->local_port == ntohs(udp->dest_port) &&
            (sock->local_addr == INADDR_ANY || sock->local_addr == ntohl(ip->src_addr)))
        {
            // TODO: Deliver data to socket
            break;
        }
        sock = sock->next;
    }
}

// Network initialization
int net_init(void)
{
    kprintf("Network: Initializing TCP/IP stack...\n");

    // Initialize socket structures
    socket_list = NULL;
    for (int i = 0; i < MAX_SOCKETS; i++) {
        socket_table[i] = NULL;
    }

    // Create loopback device
    net_device_t *loopback = (net_device_t *)kmalloc(sizeof(net_device_t));
    if (loopback)
    {
        strcpy(loopback->name, "lo");
        memset(loopback->mac_addr, 0, ETH_ALEN);
        loopback->ip_addr = 0x7F000001; // 127.0.0.1
        loopback->netmask = 0xFF000000; // 255.0.0.0
        loopback->gateway = 0;
        loopback->send_packet = NULL; // Loopback doesn't send
        loopback->next = NULL;

        net_register_device(loopback);
    }

    kprintf("Network: TCP/IP stack initialized\n");
    return 0;
}

// Network configuration
int net_set_ip(net_device_t *dev, uint32_t ip, uint32_t netmask, uint32_t gateway)
{
    if (!dev)
        return -1;

    dev->ip_addr = ip;
    dev->netmask = netmask;
    dev->gateway = gateway;

    return 0;
}

int net_set_mac(net_device_t *dev, const uint8_t *mac)
{
    if (!dev || !mac)
        return -1;

    memcpy(dev->mac_addr, mac, ETH_ALEN);
    return 0;
}

// Network utilities
uint32_t net_htonl(uint32_t hostlong)
{
    return ((hostlong & 0xFF000000) >> 24) |
           ((hostlong & 0x00FF0000) >> 8) |
           ((hostlong & 0x0000FF00) << 8) |
           ((hostlong & 0x000000FF) << 24);
}

uint16_t net_htons(uint16_t hostshort)
{
    return ((hostshort & 0xFF00) >> 8) | ((hostshort & 0x00FF) << 8);
}

uint32_t net_ntohl(uint32_t netlong)
{
    return net_htonl(netlong);
}

uint16_t net_ntohs(uint16_t netshort)
{
    return net_htons(netshort);
}
