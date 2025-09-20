#include "kernel/net.h"
#include "kernel/kernel.h"
#include "kernel/memory.h"

// Forward declarations for network protocol initializers
int arp_init(void);
int icmp_init(void);
int virtio_net_init(void);

static net_interface_t* interfaces = NULL;
static socket_t* sockets = NULL;
static uint16_t next_port = 32768;

int net_init(void) {
    kprintf("Network Stack: Initializing...\n");

    // Initialize ARP subsystem
    if (arp_init() != 0) {
        kprintf("Network Stack: ARP initialization failed\n");
        return -1;
    }

    // Initialize ICMP subsystem
    if (icmp_init() != 0) {
        kprintf("Network Stack: ICMP initialization failed\n");
        return -1;
    }

    // Initialize loopback interface
    loopback_init();

    // Initialize virtio-net driver support
    virtio_net_init();

    kprintf("Network Stack: Ready\n");
    return 0;
}

int net_register_interface(net_interface_t* iface) {
    if (!iface) return -1;

    iface->next = interfaces;
    interfaces = iface;

    kprintf("Network: Registered interface %s\n", iface->name);
    return 0;
}

net_interface_t* net_find_interface(const char* name) {
    net_interface_t* current = interfaces;

    while (current) {
        int match = 1;
        for (int i = 0; name[i] || current->name[i]; i++) {
            if (name[i] != current->name[i]) {
                match = 0;
                break;
            }
        }
        if (match) return current;
        current = current->next;
    }
    return NULL;
}

int net_interface_up(const char* name) {
    net_interface_t* iface = net_find_interface(name);
    if (!iface) return -1;

    iface->up = true;
    kprintf("Network: Interface %s is up\n", name);
    return 0;
}

int net_interface_down(const char* name) {
    net_interface_t* iface = net_find_interface(name);
    if (!iface) return -1;

    iface->up = false;
    kprintf("Network: Interface %s is down\n", name);
    return 0;
}

int net_set_ip_address(const char* name, uint32_t ip, uint32_t netmask, uint32_t gateway) {
    net_interface_t* iface = net_find_interface(name);
    if (!iface) return -1;

    iface->ip_addr = ip;
    iface->netmask = netmask;
    iface->gateway = gateway;

    kprintf("Network: Set IP %d.%d.%d.%d/%d on %s\n",
            (ip >> 24) & 0xFF, (ip >> 16) & 0xFF,
            (ip >> 8) & 0xFF, ip & 0xFF,
            __builtin_popcount(netmask), name);
    return 0;
}

net_packet_t* net_alloc_packet(size_t size) {
    net_packet_t* packet = (net_packet_t*)kmalloc(sizeof(net_packet_t));
    if (!packet) return NULL;

    packet->data = (uint8_t*)kmalloc(size);
    if (!packet->data) {
        kfree(packet);
        return NULL;
    }

    packet->size = 0;
    packet->capacity = size;
    packet->next = NULL;

    return packet;
}

void net_free_packet(net_packet_t* packet) {
    if (packet) {
        kfree(packet->data);
        kfree(packet);
    }
}

int net_send_packet(net_interface_t* iface, net_packet_t* packet) {
    if (!iface || !packet || !iface->up) return -1;

    if (iface->send) {
        int result = iface->send(iface, packet);
        if (result >= 0) {
            iface->packets_sent++;
            iface->bytes_sent += packet->size;
        }
        return result;
    }

    return -1;
}

void net_receive_packet(net_interface_t* iface, net_packet_t* packet) {
    if (!iface || !packet) return;

    iface->packets_received++;
    iface->bytes_received += packet->size;

    // Process ethernet frame
    eth_receive(iface, packet);
}

// Utility functions
uint16_t net_checksum(const void* data, size_t size) {
    const uint16_t* buf = (const uint16_t*)data;
    uint32_t sum = 0;

    // Sum all 16-bit words
    while (size > 1) {
        sum += *buf++;
        size -= 2;
    }

    // Add odd byte if present
    if (size == 1) {
        sum += *(const uint8_t*)buf;
    }

    // Add carry bits
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    return ~sum;
}

uint32_t net_htonl(uint32_t hostlong) {
    return ((hostlong & 0xFF) << 24) |
           (((hostlong >> 8) & 0xFF) << 16) |
           (((hostlong >> 16) & 0xFF) << 8) |
           ((hostlong >> 24) & 0xFF);
}

uint16_t net_htons(uint16_t hostshort) {
    return ((hostshort & 0xFF) << 8) | ((hostshort >> 8) & 0xFF);
}

uint32_t net_ntohl(uint32_t netlong) {
    return net_htonl(netlong);  // Same implementation
}

uint16_t net_ntohs(uint16_t netshort) {
    return net_htons(netshort);  // Same implementation
}

// Socket management
static socket_t* find_socket(int fd) {
    socket_t* current = sockets;
    while (current) {
        if (current->fd == fd) return current;
        current = current->next;
    }
    return NULL;
}

static uint16_t alloc_port(void) {
    return next_port++;
}

int net_socket(int domain, int type, int protocol) {
    (void)domain;  // AF_INET assumed
    (void)protocol; // Auto-detect from type

    socket_t* sock = (socket_t*)kmalloc(sizeof(socket_t));
    if (!sock) return -1;

    // Find free file descriptor
    static int next_fd = 3;
    sock->fd = next_fd++;

    sock->type = (socket_type_t)type;
    sock->state = SOCKET_CLOSED;
    sock->local_addr = 0;
    sock->local_port = 0;
    sock->remote_addr = 0;
    sock->remote_port = 0;
    sock->seq_num = 0;
    sock->ack_num = 0;
    sock->window_size = 8192;
    sock->rx_queue = NULL;
    sock->tx_queue = NULL;
    sock->wait_queue = NULL;

    // Add to socket list
    sock->next = sockets;
    sockets = sock;

    return sock->fd;
}

int net_bind(int sockfd, const struct sockaddr* addr, socklen_t addrlen) {
    (void)addrlen;
    socket_t* sock = find_socket(sockfd);
    if (!sock) return -1;

    const struct sockaddr_in* sin = (const struct sockaddr_in*)addr;
    sock->local_addr = sin->sin_addr;
    sock->local_port = net_ntohs(sin->sin_port);

    if (sock->local_port == 0) {
        sock->local_port = alloc_port();
    }

    return 0;
}

int net_listen(int sockfd, int backlog) {
    (void)backlog;
    socket_t* sock = find_socket(sockfd);
    if (!sock || sock->type != SOCK_STREAM) return -1;

    sock->state = SOCKET_LISTEN;
    return 0;
}

int net_accept(int sockfd, struct sockaddr* addr, socklen_t* addrlen) {
    (void)addr;
    (void)addrlen;
    socket_t* sock = find_socket(sockfd);
    if (!sock || sock->state != SOCKET_LISTEN) return -1;

    // TODO: Implement proper accept with connection queue
    return -1;
}

int net_connect(int sockfd, const struct sockaddr* addr, socklen_t addrlen) {
    (void)addrlen;
    socket_t* sock = find_socket(sockfd);
    if (!sock) return -1;

    const struct sockaddr_in* sin = (const struct sockaddr_in*)addr;
    sock->remote_addr = sin->sin_addr;
    sock->remote_port = net_ntohs(sin->sin_port);

    if (sock->local_port == 0) {
        sock->local_port = alloc_port();
    }

    if (sock->type == SOCK_STREAM) {
        // TCP connect - send SYN
        sock->state = SOCKET_SYN_SENT;
        // TODO: Send SYN packet
    } else {
        // UDP - just set up addresses
        sock->state = SOCKET_ESTABLISHED;
    }

    return 0;
}

ssize_t net_send(int sockfd, const void* buf, size_t len, int flags) {
    (void)flags;
    socket_t* sock = find_socket(sockfd);
    if (!sock) return -1;

    if (sock->type == SOCK_STREAM) {
        return tcp_send(sock, buf, len);
    } else if (sock->type == SOCK_DGRAM) {
        return udp_send(sock->remote_addr, sock->remote_port, sock->local_port, buf, len);
    }

    return -1;
}

ssize_t net_recv(int sockfd, void* buf, size_t len, int flags) {
    (void)flags;
    socket_t* sock = find_socket(sockfd);
    if (!sock || !sock->rx_queue) return -1;

    // Get packet from receive queue
    net_packet_t* packet = sock->rx_queue;
    sock->rx_queue = packet->next;

    size_t copy_size = (packet->size < len) ? packet->size : len;
    uint8_t* buffer = (uint8_t*)buf;

    for (size_t i = 0; i < copy_size; i++) {
        buffer[i] = packet->data[i];
    }

    net_free_packet(packet);
    return copy_size;
}

int net_close_socket(int sockfd) {
    socket_t** current = &sockets;

    while (*current) {
        if ((*current)->fd == sockfd) {
            socket_t* to_remove = *current;

            // Free queued packets
            while (to_remove->rx_queue) {
                net_packet_t* packet = to_remove->rx_queue;
                to_remove->rx_queue = packet->next;
                net_free_packet(packet);
            }

            while (to_remove->tx_queue) {
                net_packet_t* packet = to_remove->tx_queue;
                to_remove->tx_queue = packet->next;
                net_free_packet(packet);
            }

            *current = to_remove->next;
            kfree(to_remove);
            return 0;
        }
        current = &(*current)->next;
    }

    return -1;
}

// Virtio-net driver support
int virtio_net_init(void) {
    kprintf("Network: Initializing virtio-net driver support\n");

    // Initialize virtio-net driver framework
    // In a real implementation, this would:
    // - Detect virtio-net devices on PCI bus
    // - Initialize virtio queues for TX/RX
    // - Set up virtio configuration space
    // - Register interrupt handlers

    kprintf("Network: Virtio-net driver support ready\n");
    return 0;
}

// Quality of Service (QoS) support
static int net_qos_classify_packet(net_packet_t* packet) {
    if (!packet) return 0;

    // Basic QoS classification based on packet type
    // In a real implementation, this would:
    // - Examine packet headers for QoS markings
    // - Apply traffic shaping policies
    // - Set priority levels
    // - Implement bandwidth control

    return 0; // Normal priority
}

int net_qos_init(void) {
    kprintf("Network: Initializing Quality of Service (QoS) support\n");
    return 0;
}

// Traffic Control support
static int net_traffic_control_init(void) {
    kprintf("Network: Initializing traffic control subsystem\n");

    // Initialize traffic control framework
    // In a real implementation, this would:
    // - Set up traffic scheduling algorithms
    // - Configure rate limiting
    // - Implement packet queuing disciplines
    // - Support traffic shaping and policing

    return 0;
}
