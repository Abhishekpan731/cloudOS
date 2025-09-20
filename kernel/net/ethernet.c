#include "kernel/net.h"
#include "kernel/kernel.h"
#include "kernel/memory.h"

// Forward declarations for ARP functions
void arp_receive(net_interface_t *iface, net_packet_t *packet);

int eth_send(net_interface_t* iface, const uint8_t* dest_mac, uint16_t ethertype,
             const void* data, size_t size) {
    if (!iface || !dest_mac || !data || size > MTU_SIZE) return -1;

    net_packet_t* packet = net_alloc_packet(sizeof(eth_header_t) + size);
    if (!packet) return -1;

    eth_header_t* eth = (eth_header_t*)packet->data;

    // Fill ethernet header
    for (int i = 0; i < ETH_ADDR_LEN; i++) {
        eth->dest_mac[i] = dest_mac[i];
        eth->src_mac[i] = iface->mac_addr[i];
    }
    eth->ethertype = net_htons(ethertype);

    // Copy payload
    uint8_t* payload = packet->data + sizeof(eth_header_t);
    const uint8_t* src_data = (const uint8_t*)data;
    for (size_t i = 0; i < size; i++) {
        payload[i] = src_data[i];
    }

    packet->size = sizeof(eth_header_t) + size;

    int result = net_send_packet(iface, packet);
    net_free_packet(packet);

    return result;
}

void eth_receive(net_interface_t* iface, net_packet_t* packet) {
    if (!iface || !packet || packet->size < sizeof(eth_header_t)) return;

    eth_header_t* eth = (eth_header_t*)packet->data;
    uint16_t ethertype = net_ntohs(eth->ethertype);

    // Check if packet is for us (or broadcast)
    bool for_us = false;
    bool broadcast = true;

    for (int i = 0; i < ETH_ADDR_LEN; i++) {
        if (eth->dest_mac[i] != iface->mac_addr[i]) {
            for_us = false;
        } else {
            for_us = true;
        }

        if (eth->dest_mac[i] != 0xFF) {
            broadcast = false;
        }
    }

    if (!for_us && !broadcast) {
        net_free_packet(packet);
        return;
    }

    // Create new packet with payload only
    size_t payload_size = packet->size - sizeof(eth_header_t);
    net_packet_t* payload_packet = net_alloc_packet(payload_size);
    if (!payload_packet) {
        net_free_packet(packet);
        return;
    }

    uint8_t* src = packet->data + sizeof(eth_header_t);
    for (size_t i = 0; i < payload_size; i++) {
        payload_packet->data[i] = src[i];
    }
    payload_packet->size = payload_size;

    // Process based on ethertype
    switch (ethertype) {
        case ETH_TYPE_IP:
            ip_receive(iface, payload_packet);
            break;

        case ETH_TYPE_ARP:
            arp_receive(iface, payload_packet);
            break;

        default:
            // Unknown protocol
            net_free_packet(payload_packet);
            break;
    }

    net_free_packet(packet);
}
