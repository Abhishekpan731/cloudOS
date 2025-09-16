#include "kernel/net.h"
#include "kernel/kernel.h"
#include "kernel/memory.h"

static uint16_t ip_id_counter = 1;

uint32_t ip_route(uint32_t dest_ip) {
    // Simple routing - find interface on same network
    net_interface_t* iface = NULL;

    // First try to find direct route (same network)
    net_interface_t* current = NULL; // TODO: Get interface list
    while (current) {
        if ((dest_ip & current->netmask) == (current->ip_addr & current->netmask)) {
            return dest_ip; // Direct route
        }
        current = current->next;
    }

    // Use default gateway if available
    current = NULL; // Reset
    while (current) {
        if (current->gateway != 0) {
            return current->gateway;
        }
        current = current->next;
    }

    return 0; // No route
}

int ip_send(uint32_t dest_ip, uint8_t protocol, const void* data, size_t size) {
    if (!data || size > (MTU_SIZE - sizeof(ip_header_t))) return -1;

    // Find appropriate interface
    net_interface_t* iface = NULL;
    net_interface_t* current = NULL; // TODO: Get interface list head

    while (current) {
        if (current->up && current->ip_addr != 0) {
            if ((dest_ip & current->netmask) == (current->ip_addr & current->netmask)) {
                iface = current;
                break;
            }
            if (!iface && current->gateway != 0) {
                iface = current; // Fallback to default route
            }
        }
        current = current->next;
    }

    if (!iface) return -1;

    net_packet_t* packet = net_alloc_packet(sizeof(ip_header_t) + size);
    if (!packet) return -1;

    ip_header_t* ip = (ip_header_t*)packet->data;

    // Fill IP header
    ip->version_ihl = (4 << 4) | 5; // Version 4, Header length 5 words (20 bytes)
    ip->tos = 0;
    ip->total_length = net_htons(sizeof(ip_header_t) + size);
    ip->identification = net_htons(ip_id_counter++);
    ip->flags_fragment = net_htons(0x4000); // Don't fragment
    ip->ttl = 64;
    ip->protocol = protocol;
    ip->checksum = 0; // Will be calculated later
    ip->src_addr = net_htonl(iface->ip_addr);
    ip->dest_addr = net_htonl(dest_ip);

    // Calculate checksum
    ip->checksum = net_checksum(ip, sizeof(ip_header_t));

    // Copy payload
    uint8_t* payload = packet->data + sizeof(ip_header_t);
    const uint8_t* src_data = (const uint8_t*)data;
    for (size_t i = 0; i < size; i++) {
        payload[i] = src_data[i];
    }

    packet->size = sizeof(ip_header_t) + size;

    // Determine next hop
    uint32_t next_hop = ip_route(dest_ip);
    if (next_hop == 0) {
        net_free_packet(packet);
        return -1;
    }

    // TODO: ARP resolution to get MAC address
    // For now, use broadcast MAC
    uint8_t dest_mac[ETH_ADDR_LEN] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

    int result = eth_send(iface, dest_mac, ETH_TYPE_IP, packet->data, packet->size);
    net_free_packet(packet);

    return result;
}

void ip_receive(net_interface_t* iface, net_packet_t* packet) {
    if (!iface || !packet || packet->size < sizeof(ip_header_t)) {
        net_free_packet(packet);
        return;
    }

    ip_header_t* ip = (ip_header_t*)packet->data;

    // Basic validation
    uint8_t version = (ip->version_ihl >> 4);
    uint8_t ihl = (ip->version_ihl & 0xF) * 4;

    if (version != 4 || ihl < sizeof(ip_header_t) || packet->size < ihl) {
        net_free_packet(packet);
        return;
    }

    uint16_t total_length = net_ntohs(ip->total_length);
    if (total_length > packet->size) {
        net_free_packet(packet);
        return;
    }

    // Check if packet is for us
    uint32_t dest_addr = net_ntohl(ip->dest_addr);
    if (dest_addr != iface->ip_addr && dest_addr != 0xFFFFFFFF) {
        // TODO: Implement IP forwarding
        net_free_packet(packet);
        return;
    }

    // Verify checksum
    uint16_t recv_checksum = ip->checksum;
    ip->checksum = 0;
    uint16_t calc_checksum = net_checksum(ip, ihl);
    ip->checksum = recv_checksum;

    if (recv_checksum != calc_checksum) {
        net_free_packet(packet);
        return;
    }

    // Create payload packet
    size_t payload_size = total_length - ihl;
    net_packet_t* payload_packet = net_alloc_packet(payload_size);
    if (!payload_packet) {
        net_free_packet(packet);
        return;
    }

    uint8_t* src = packet->data + ihl;
    for (size_t i = 0; i < payload_size; i++) {
        payload_packet->data[i] = src[i];
    }
    payload_packet->size = payload_size;

    // Process based on protocol
    switch (ip->protocol) {
        case IPPROTO_TCP:
            tcp_receive(iface, payload_packet);
            break;

        case IPPROTO_UDP:
            udp_receive(iface, payload_packet);
            break;

        case IPPROTO_ICMP:
            // TODO: Implement ICMP
            net_free_packet(payload_packet);
            break;

        default:
            // Unknown protocol
            net_free_packet(payload_packet);
            break;
    }

    net_free_packet(packet);
}
