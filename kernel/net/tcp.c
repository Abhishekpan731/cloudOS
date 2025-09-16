#include "kernel/net.h"
#include "kernel/kernel.h"
#include "kernel/memory.h"

static uint32_t tcp_seq_counter = 1000;

static uint16_t tcp_checksum(uint32_t src_ip, uint32_t dest_ip,
                           const tcp_header_t* tcp, size_t tcp_len) {
    // TCP pseudo-header for checksum calculation
    struct {
        uint32_t src_addr;
        uint32_t dest_addr;
        uint8_t zero;
        uint8_t protocol;
        uint16_t tcp_length;
    } pseudo_header;

    pseudo_header.src_addr = net_htonl(src_ip);
    pseudo_header.dest_addr = net_htonl(dest_ip);
    pseudo_header.zero = 0;
    pseudo_header.protocol = IPPROTO_TCP;
    pseudo_header.tcp_length = net_htons(tcp_len);

    // Calculate checksum over pseudo-header + TCP header + data
    uint32_t sum = 0;
    const uint16_t* buf;

    // Add pseudo-header
    buf = (const uint16_t*)&pseudo_header;
    for (size_t i = 0; i < sizeof(pseudo_header) / 2; i++) {
        sum += buf[i];
    }

    // Add TCP header and data
    buf = (const uint16_t*)tcp;
    size_t remaining = tcp_len;
    while (remaining > 1) {
        sum += *buf++;
        remaining -= 2;
    }

    // Add odd byte if present
    if (remaining == 1) {
        sum += *(const uint8_t*)buf;
    }

    // Add carry bits
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    return ~sum;
}

int tcp_send(socket_t* sock, const void* data, size_t size) {
    if (!sock || !data || sock->type != SOCK_STREAM) return -1;

    if (sock->state != SOCKET_ESTABLISHED) {
        return -1; // Connection not established
    }

    net_packet_t* packet = net_alloc_packet(sizeof(tcp_header_t) + size);
    if (!packet) return -1;

    tcp_header_t* tcp = (tcp_header_t*)packet->data;

    // Fill TCP header
    tcp->src_port = net_htons(sock->local_port);
    tcp->dest_port = net_htons(sock->remote_port);
    tcp->seq_num = net_htonl(sock->seq_num);
    tcp->ack_num = net_htonl(sock->ack_num);
    tcp->data_offset_flags = (5 << 4); // Data offset: 5 words (20 bytes)
    tcp->flags = TCP_PSH | TCP_ACK;
    tcp->window_size = net_htons(sock->window_size);
    tcp->checksum = 0; // Will be calculated later
    tcp->urgent_ptr = 0;

    // Copy data
    uint8_t* payload = packet->data + sizeof(tcp_header_t);
    const uint8_t* src_data = (const uint8_t*)data;
    for (size_t i = 0; i < size; i++) {
        payload[i] = src_data[i];
    }

    packet->size = sizeof(tcp_header_t) + size;

    // Calculate checksum
    tcp->checksum = tcp_checksum(sock->local_addr, sock->remote_addr, tcp, packet->size);

    // Update sequence number
    sock->seq_num += size;

    // Send via IP layer
    int result = ip_send(sock->remote_addr, IPPROTO_TCP, packet->data, packet->size);
    net_free_packet(packet);

    return (result >= 0) ? size : -1;
}

static socket_t* tcp_find_socket(uint32_t local_addr, uint16_t local_port,
                                uint32_t remote_addr, uint16_t remote_port) {
    // TODO: Access global socket list
    (void)local_addr;
    (void)local_port;
    (void)remote_addr;
    (void)remote_port;
    return NULL;
}

void tcp_receive(net_interface_t* iface, net_packet_t* packet) {
    if (!iface || !packet || packet->size < sizeof(tcp_header_t)) {
        net_free_packet(packet);
        return;
    }

    tcp_header_t* tcp = (tcp_header_t*)packet->data;

    uint16_t src_port = net_ntohs(tcp->src_port);
    uint16_t dest_port = net_ntohs(tcp->dest_port);
    uint32_t seq_num = net_ntohl(tcp->seq_num);
    uint32_t ack_num = net_ntohl(tcp->ack_num);
    uint8_t data_offset = (tcp->data_offset_flags >> 4) * 4;
    uint8_t flags = tcp->flags;

    if (data_offset < sizeof(tcp_header_t) || data_offset > packet->size) {
        net_free_packet(packet);
        return;
    }

    // Find matching socket
    socket_t* sock = tcp_find_socket(iface->ip_addr, dest_port, 0, src_port);
    if (!sock) {
        // TODO: Send RST
        net_free_packet(packet);
        return;
    }

    // Verify checksum
    uint16_t recv_checksum = tcp->checksum;
    tcp->checksum = 0;
    uint16_t calc_checksum = tcp_checksum(sock->remote_addr, sock->local_addr, tcp, packet->size);
    tcp->checksum = recv_checksum;

    if (recv_checksum != calc_checksum) {
        net_free_packet(packet);
        return;
    }

    // Process based on current state and flags
    switch (sock->state) {
        case SOCKET_LISTEN:
            if (flags & TCP_SYN) {
                // Incoming connection request
                sock->remote_addr = 0; // TODO: Get from IP header
                sock->remote_port = src_port;
                sock->ack_num = seq_num + 1;
                sock->seq_num = tcp_seq_counter++;
                sock->state = SOCKET_SYN_RECEIVED;

                // TODO: Send SYN+ACK
            }
            break;

        case SOCKET_SYN_SENT:
            if ((flags & (TCP_SYN | TCP_ACK)) == (TCP_SYN | TCP_ACK)) {
                // Connection established
                sock->ack_num = seq_num + 1;
                sock->state = SOCKET_ESTABLISHED;

                // TODO: Send ACK
            }
            break;

        case SOCKET_ESTABLISHED:
            if (flags & TCP_FIN) {
                // Connection close initiated by remote
                sock->ack_num = seq_num + 1;
                sock->state = SOCKET_CLOSE_WAIT;

                // TODO: Send ACK
            } else if (data_offset < packet->size) {
                // Data packet
                size_t data_size = packet->size - data_offset;

                // Create new packet with just the data
                net_packet_t* data_packet = net_alloc_packet(data_size);
                if (data_packet) {
                    uint8_t* src = packet->data + data_offset;
                    for (size_t i = 0; i < data_size; i++) {
                        data_packet->data[i] = src[i];
                    }
                    data_packet->size = data_size;

                    // Add to socket receive queue
                    data_packet->next = sock->rx_queue;
                    sock->rx_queue = data_packet;

                    // Update ACK number
                    sock->ack_num = seq_num + data_size;

                    // TODO: Send ACK
                }
            }
            break;

        case SOCKET_FIN_WAIT1:
            if (flags & TCP_ACK) {
                sock->state = SOCKET_FIN_WAIT2;
            }
            if (flags & TCP_FIN) {
                sock->ack_num = seq_num + 1;
                sock->state = (sock->state == SOCKET_FIN_WAIT2) ? SOCKET_TIME_WAIT : SOCKET_CLOSING;
                // TODO: Send ACK
            }
            break;

        case SOCKET_FIN_WAIT2:
            if (flags & TCP_FIN) {
                sock->ack_num = seq_num + 1;
                sock->state = SOCKET_TIME_WAIT;
                // TODO: Send ACK
            }
            break;

        default:
            break;
    }

    net_free_packet(packet);
}
