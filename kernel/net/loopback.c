#include "kernel/net.h"
#include "kernel/kernel.h"
#include "kernel/memory.h"

static int loopback_send(net_interface_t* iface, net_packet_t* packet);
static int loopback_receive(net_interface_t* iface, net_packet_t* packet);

static net_interface_t loopback_interface = {
    .name = "lo",
    .mac_addr = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
    .ip_addr = 0x7F000001, // 127.0.0.1
    .netmask = 0xFF000000, // 255.0.0.0
    .gateway = 0,
    .up = true,
    .bytes_sent = 0,
    .bytes_received = 0,
    .packets_sent = 0,
    .packets_received = 0,
    .send = loopback_send,
    .receive = loopback_receive,
    .private_data = NULL,
    .next = NULL
};

int loopback_init(void) {
    return net_register_interface(&loopback_interface);
}

static int loopback_send(net_interface_t* iface, net_packet_t* packet) {
    if (!iface || !packet) return -1;

    // For loopback, immediately receive what we send
    net_packet_t* loop_packet = net_alloc_packet(packet->size);
    if (!loop_packet) return -1;

    // Copy packet data
    for (size_t i = 0; i < packet->size; i++) {
        loop_packet->data[i] = packet->data[i];
    }
    loop_packet->size = packet->size;

    // Process as received packet
    net_receive_packet(iface, loop_packet);

    return packet->size;
}

static int loopback_receive(net_interface_t* iface, net_packet_t* packet) {
    // This function is called by net_receive_packet, just process normally
    (void)iface;
    (void)packet;
    return 0;
}
