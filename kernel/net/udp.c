#include "kernel/net.h"
#include "kernel/kernel.h"
#include "kernel/memory.h"

static uint16_t udp_checksum(uint32_t src_ip, uint32_t dest_ip,
                           const udp_header_t* udp, size_t udp_len) {
    // UDP pseudo-header for checksum calculation
    struct {
        uint32_t src_addr;
        uint32_t dest_addr;
        uint8_t zero;
        uint8_t protocol;
        uint16_t udp_length;
    } pseudo_header;

    pseudo_header.src_addr = net_htonl(src_ip);
    pseudo_header.dest_addr = net_htonl(dest_ip);
    pseudo_header.zero = 0;
    pseudo_header.protocol = IPPROTO_UDP;
    pseudo_header.udp_length = net_htons(udp_len);

    // Calculate checksum over pseudo-header + UDP header + data
    uint32_t sum = 0;
    const uint16_t* buf;

    // Add pseudo-header
    buf = (const uint16_t*)&pseudo_header;
    for (size_t i = 0; i < sizeof(pseudo_header) / 2; i++) {
        sum += buf[i];
    }

    // Add UDP header and data
    buf = (const uint16_t*)udp;
    size_t remaining = udp_len;
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

int udp_send(uint32_t dest_ip, uint16_t dest_port, uint16_t src_port,
             const void* data, size_t size) {
    if (!data || size > (MTU_SIZE - sizeof(ip_header_t) - sizeof(udp_header_t))) {
        return -1;
    }

    net_packet_t* packet = net_alloc_packet(sizeof(udp_header_t) + size);
    if (!packet) return -1;

    udp_header_t* udp = (udp_header_t*)packet->data;

    // Fill UDP header
    udp->src_port = net_htons(src_port);
    udp->dest_port = net_htons(dest_port);
    udp->length = net_htons(sizeof(udp_header_t) + size);
    udp->checksum = 0; // Will be calculated later

    // Copy data
    uint8_t* payload = packet->data + sizeof(udp_header_t);
    const uint8_t* src_data = (const uint8_t*)data;
    for (size_t i = 0; i < size; i++) {
        payload[i] = src_data[i];
    }

    packet->size = sizeof(udp_header_t) + size;

    // Calculate checksum
    // TODO: Get source IP from routing
    uint32_t src_ip = 0x7F000001; // localhost for now
    udp->checksum = udp_checksum(src_ip, dest_ip, udp, packet->size);

    // Send via IP layer
    int result = ip_send(dest_ip, IPPROTO_UDP, packet->data, packet->size);
    net_free_packet(packet);

    return (result >= 0) ? size : -1;
}

static socket_t* udp_find_socket(uint16_t port) {
    // TODO: Access global socket list and find UDP socket bound to port
    (void)port;
    return NULL;
}

void udp_receive(net_interface_t* iface, net_packet_t* packet) {
    if (!iface || !packet || packet->size < sizeof(udp_header_t)) {
        net_free_packet(packet);
        return;
    }

    udp_header_t* udp = (udp_header_t*)packet->data;

    uint16_t src_port = net_ntohs(udp->src_port);
    uint16_t dest_port = net_ntohs(udp->dest_port);
    uint16_t length = net_ntohs(udp->length);

    if (length < sizeof(udp_header_t) || length > packet->size) {
        net_free_packet(packet);
        return;
    }

    // Find socket bound to destination port
    socket_t* sock = udp_find_socket(dest_port);
    if (!sock) {
        // TODO: Send ICMP port unreachable
        net_free_packet(packet);
        return;
    }

    // Verify checksum if present
    if (udp->checksum != 0) {
        uint16_t recv_checksum = udp->checksum;
        udp->checksum = 0;
        uint16_t calc_checksum = udp_checksum(sock->remote_addr, sock->local_addr, udp, length);
        udp->checksum = recv_checksum;

        if (recv_checksum != calc_checksum) {
            net_free_packet(packet);
            return;
        }
    }

    // Extract data
    size_t data_size = length - sizeof(udp_header_t);
    if (data_size > 0) {
        net_packet_t* data_packet = net_alloc_packet(data_size);
        if (data_packet) {
            uint8_t* src = packet->data + sizeof(udp_header_t);
            for (size_t i = 0; i < data_size; i++) {
                data_packet->data[i] = src[i];
            }
            data_packet->size = data_size;

            // Add to socket receive queue
            data_packet->next = sock->rx_queue;
            sock->rx_queue = data_packet;

            // Update socket with sender information
            sock->remote_port = src_port;
            // TODO: Get remote IP from IP header
        }
    }

    net_free_packet(packet);
}
