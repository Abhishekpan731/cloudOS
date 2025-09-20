/*
 * ICMP (Internet Control Message Protocol) Implementation
 * Network diagnostics and error reporting for IPv4
 */

#include "kernel/net.h"
#include "kernel/memory.h"
#include "kernel/kernel.h"

// Simple memcpy for kernel use
static void *memcpy(void *dest, const void *src, size_t n) {
    uint8_t *d = (uint8_t *)dest;
    const uint8_t *s = (const uint8_t *)src;
    for (size_t i = 0; i < n; i++) {
        d[i] = s[i];
    }
    return dest;
}

// Simple memset for kernel use
static void *memset(void *s, int c, size_t n) {
    uint8_t *p = (uint8_t *)s;
    for (size_t i = 0; i < n; i++) {
        p[i] = (uint8_t)c;
    }
    return s;
}

// ICMP message types
#define ICMP_ECHO_REPLY        0
#define ICMP_DEST_UNREACHABLE  3
#define ICMP_SOURCE_QUENCH     4
#define ICMP_REDIRECT          5
#define ICMP_ECHO_REQUEST      8
#define ICMP_TIME_EXCEEDED     11
#define ICMP_PARAMETER_PROBLEM 12
#define ICMP_TIMESTAMP_REQUEST 13
#define ICMP_TIMESTAMP_REPLY   14
#define ICMP_INFO_REQUEST      15
#define ICMP_INFO_REPLY        16

// ICMP codes for Destination Unreachable
#define ICMP_NET_UNREACHABLE     0
#define ICMP_HOST_UNREACHABLE    1
#define ICMP_PROTOCOL_UNREACHABLE 2
#define ICMP_PORT_UNREACHABLE    3
#define ICMP_FRAGMENTATION_NEEDED 4
#define ICMP_SOURCE_ROUTE_FAILED 5

// ICMP header structure
typedef struct {
    uint8_t  type;           // ICMP message type
    uint8_t  code;           // ICMP message code
    uint16_t checksum;       // ICMP checksum
    union {
        struct {
            uint16_t identifier;  // Echo identifier
            uint16_t sequence;    // Echo sequence number
        } echo;
        struct {
            uint8_t  pointer;     // Parameter problem pointer
            uint8_t  unused[3];   // Unused bytes
        } param;
        uint32_t unused;          // For other message types
    } data;
    uint8_t  payload[];      // Variable-length payload
} __attribute__((packed)) icmp_header_t;

// ICMP statistics
static struct {
    uint64_t echo_requests_sent;
    uint64_t echo_requests_received;
    uint64_t echo_replies_sent;
    uint64_t echo_replies_received;
    uint64_t errors_sent;
    uint64_t errors_received;
} icmp_stats = {0};

// ICMP echo request/reply data
typedef struct {
    uint16_t identifier;
    uint16_t sequence;
    uint64_t timestamp;
    uint8_t  data[56];       // Standard ping data size
} icmp_echo_data_t;

// Calculate ICMP checksum
static uint16_t icmp_checksum(const icmp_header_t *icmp, size_t size) {
    uint32_t sum = 0;
    const uint16_t *buf = (const uint16_t *)icmp;

    // Sum all 16-bit words
    while (size > 1) {
        sum += *buf++;
        size -= 2;
    }

    // Add odd byte if present
    if (size == 1) {
        sum += *(const uint8_t *)buf;
    }

    // Add carry bits
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    return ~sum;
}

// Send ICMP echo request (ping)
int icmp_ping(uint32_t dest_ip, uint16_t identifier, uint16_t sequence,
              const void *data, size_t data_size) {
    if (data_size > 56) data_size = 56; // Limit to standard ping size

    size_t packet_size = sizeof(icmp_header_t) + data_size;
    net_packet_t *packet = net_alloc_packet(packet_size);
    if (!packet) return -1;

    icmp_header_t *icmp = (icmp_header_t *)packet->data;

    // Fill ICMP header for echo request
    icmp->type = ICMP_ECHO_REQUEST;
    icmp->code = 0;
    icmp->checksum = 0; // Will be calculated later
    icmp->data.echo.identifier = net_htons(identifier);
    icmp->data.echo.sequence = net_htons(sequence);

    // Copy data payload
    if (data && data_size > 0) {
        memcpy(icmp->payload, data, data_size);
    } else {
        // Fill with pattern for standard ping
        for (size_t i = 0; i < data_size; i++) {
            icmp->payload[i] = (uint8_t)(i & 0xFF);
        }
    }

    // Calculate checksum
    icmp->checksum = icmp_checksum(icmp, packet_size);

    packet->size = packet_size;

    // Send via IP layer
    int result = ip_send(dest_ip, IPPROTO_ICMP, packet->data, packet->size);
    net_free_packet(packet);

    if (result >= 0) {
        icmp_stats.echo_requests_sent++;
    }

    return result;
}

// Send ICMP echo reply
static int icmp_send_echo_reply(net_interface_t *iface, const icmp_header_t *request,
                               const ip_header_t *ip_hdr, size_t size) {
    if (!iface || !request || !ip_hdr) return -1;

    size_t reply_size = sizeof(icmp_header_t) + (size - sizeof(icmp_header_t));
    net_packet_t *packet = net_alloc_packet(reply_size);
    if (!packet) return -1;

    icmp_header_t *icmp = (icmp_header_t *)packet->data;

    // Fill ICMP header for echo reply
    icmp->type = ICMP_ECHO_REPLY;
    icmp->code = 0;
    icmp->checksum = 0; // Will be calculated later
    icmp->data.echo.identifier = request->data.echo.identifier;
    icmp->data.echo.sequence = request->data.echo.sequence;

    // Copy original payload
    size_t payload_size = size - sizeof(icmp_header_t);
    if (payload_size > 0) {
        memcpy(icmp->payload, request->payload, payload_size);
    }

    // Calculate checksum
    icmp->checksum = icmp_checksum(icmp, reply_size);

    packet->size = reply_size;

    // Send echo reply to original source
    int result = ip_send(net_ntohl(ip_hdr->src_addr), IPPROTO_ICMP,
                        packet->data, packet->size);
    net_free_packet(packet);

    if (result >= 0) {
        icmp_stats.echo_replies_sent++;
    }

    return result;
}

// Send ICMP destination unreachable
static int icmp_send_dest_unreachable(net_interface_t *iface, uint8_t code,
                                     const ip_header_t *orig_ip, const void *orig_payload,
                                     size_t payload_size) {
    if (!iface || !orig_ip) return -1;

    // Limit payload to first 28 bytes of original IP header + 8 bytes of data
    size_t copy_size = (sizeof(ip_header_t) + 8 < payload_size) ?
                      sizeof(ip_header_t) + 8 : payload_size;

    size_t packet_size = sizeof(icmp_header_t) + copy_size;
    net_packet_t *packet = net_alloc_packet(packet_size);
    if (!packet) return -1;

    icmp_header_t *icmp = (icmp_header_t *)packet->data;

    // Fill ICMP header
    icmp->type = ICMP_DEST_UNREACHABLE;
    icmp->code = code;
    icmp->checksum = 0; // Will be calculated later
    icmp->data.unused = 0;

    // Copy original IP header + 8 bytes of data
    uint8_t *payload_start = icmp->payload;
    memcpy(payload_start, orig_ip, copy_size);

    // Calculate checksum
    icmp->checksum = icmp_checksum(icmp, packet_size);

    packet->size = packet_size;

    // Send to original source
    int result = ip_send(net_ntohl(orig_ip->src_addr), IPPROTO_ICMP,
                        packet->data, packet->size);
    net_free_packet(packet);

    if (result >= 0) {
        icmp_stats.errors_sent++;
    }

    return result;
}

// Send ICMP time exceeded
static int icmp_send_time_exceeded(net_interface_t *iface, const ip_header_t *orig_ip,
                                  const void *orig_payload, size_t payload_size) {
    if (!iface || !orig_ip) return -1;

    // Copy original IP header + 8 bytes of data
    size_t copy_size = (sizeof(ip_header_t) + 8 < payload_size) ?
                      sizeof(ip_header_t) + 8 : payload_size;

    size_t packet_size = sizeof(icmp_header_t) + copy_size;
    net_packet_t *packet = net_alloc_packet(packet_size);
    if (!packet) return -1;

    icmp_header_t *icmp = (icmp_header_t *)packet->data;

    // Fill ICMP header
    icmp->type = ICMP_TIME_EXCEEDED;
    icmp->code = 0; // TTL exceeded in transit
    icmp->checksum = 0; // Will be calculated later
    icmp->data.unused = 0;

    // Copy original IP header + 8 bytes of data
    memcpy(icmp->payload, orig_ip, copy_size);

    // Calculate checksum
    icmp->checksum = icmp_checksum(icmp, packet_size);

    packet->size = packet_size;

    // Send to original source
    int result = ip_send(net_ntohl(orig_ip->src_addr), IPPROTO_ICMP,
                        packet->data, packet->size);
    net_free_packet(packet);

    if (result >= 0) {
        icmp_stats.errors_sent++;
    }

    return result;
}

// Send ICMP parameter problem
static int icmp_send_parameter_problem(net_interface_t *iface, uint8_t pointer,
                                      const ip_header_t *orig_ip, const void *orig_payload,
                                      size_t payload_size) {
    if (!iface || !orig_ip) return -1;

    // Copy original IP header + 8 bytes of data
    size_t copy_size = (sizeof(ip_header_t) + 8 < payload_size) ?
                      sizeof(ip_header_t) + 8 : payload_size;

    size_t packet_size = sizeof(icmp_header_t) + copy_size;
    net_packet_t *packet = net_alloc_packet(packet_size);
    if (!packet) return -1;

    icmp_header_t *icmp = (icmp_header_t *)packet->data;

    // Fill ICMP header
    icmp->type = ICMP_PARAMETER_PROBLEM;
    icmp->code = 0;
    icmp->checksum = 0; // Will be calculated later
    icmp->data.param.pointer = pointer;
    memset(icmp->data.param.unused, 0, 3);

    // Copy original IP header + 8 bytes of data
    memcpy(icmp->payload, orig_ip, copy_size);

    // Calculate checksum
    icmp->checksum = icmp_checksum(icmp, packet_size);

    packet->size = packet_size;

    // Send to original source
    int result = ip_send(net_ntohl(orig_ip->src_addr), IPPROTO_ICMP,
                        packet->data, packet->size);
    net_free_packet(packet);

    if (result >= 0) {
        icmp_stats.errors_sent++;
    }

    return result;
}

// Process incoming ICMP packet
void icmp_receive(net_interface_t *iface, net_packet_t *packet,
                  const ip_header_t *ip_hdr) {
    if (!iface || !packet || !ip_hdr || packet->size < sizeof(icmp_header_t)) {
        if (packet) net_free_packet(packet);
        return;
    }

    icmp_header_t *icmp = (icmp_header_t *)packet->data;
    size_t icmp_size = packet->size;

    // Verify ICMP checksum
    uint16_t received_checksum = icmp->checksum;
    icmp->checksum = 0;
    uint16_t calculated_checksum = icmp_checksum(icmp, icmp_size);
    icmp->checksum = received_checksum;

    if (received_checksum != calculated_checksum) {
        net_free_packet(packet);
        return;
    }

    // Process based on ICMP type
    switch (icmp->type) {
        case ICMP_ECHO_REQUEST:
            icmp_stats.echo_requests_received++;
            icmp_send_echo_reply(iface, icmp, ip_hdr, icmp_size);
            break;

        case ICMP_ECHO_REPLY:
            icmp_stats.echo_replies_received++;
            // TODO: Deliver to waiting ping process
            break;

        case ICMP_DEST_UNREACHABLE:
        case ICMP_TIME_EXCEEDED:
        case ICMP_PARAMETER_PROBLEM:
            icmp_stats.errors_received++;
            // TODO: Deliver error to appropriate socket/process
            break;

        default:
            // Unknown ICMP type - silently ignore
            break;
    }

    net_free_packet(packet);
}

// Generate ICMP error messages for various conditions
int icmp_send_error(net_interface_t *iface, uint8_t type, uint8_t code,
                   const ip_header_t *orig_ip, const void *orig_payload,
                   size_t payload_size) {
    switch (type) {
        case ICMP_DEST_UNREACHABLE:
            return icmp_send_dest_unreachable(iface, code, orig_ip,
                                            orig_payload, payload_size);

        case ICMP_TIME_EXCEEDED:
            return icmp_send_time_exceeded(iface, orig_ip,
                                         orig_payload, payload_size);

        case ICMP_PARAMETER_PROBLEM:
            return icmp_send_parameter_problem(iface, code, orig_ip,
                                             orig_payload, payload_size);

        default:
            return -1;
    }
}

// Initialize ICMP subsystem
int icmp_init(void) {
    kprintf("ICMP: Initializing Internet Control Message Protocol...\n");

    // Reset statistics
    memset(&icmp_stats, 0, sizeof(icmp_stats));

    kprintf("ICMP: Initialized\n");
    return 0;
}

// Get ICMP statistics
void icmp_get_stats(uint64_t *echo_requests_sent, uint64_t *echo_replies_sent,
                   uint64_t *echo_requests_received, uint64_t *echo_replies_received,
                   uint64_t *errors_sent, uint64_t *errors_received) {
    if (echo_requests_sent) *echo_requests_sent = icmp_stats.echo_requests_sent;
    if (echo_replies_sent) *echo_replies_sent = icmp_stats.echo_replies_sent;
    if (echo_requests_received) *echo_requests_received = icmp_stats.echo_requests_received;
    if (echo_replies_received) *echo_replies_received = icmp_stats.echo_replies_received;
    if (errors_sent) *errors_sent = icmp_stats.errors_sent;
    if (errors_received) *errors_received = icmp_stats.errors_received;
}

// Utility function to send ICMP port unreachable
int icmp_port_unreachable(net_interface_t *iface, const ip_header_t *orig_ip,
                         const void *orig_payload, size_t payload_size) {
    return icmp_send_dest_unreachable(iface, ICMP_PORT_UNREACHABLE,
                                    orig_ip, orig_payload, payload_size);
}

// Utility function to send ICMP host unreachable
int icmp_host_unreachable(net_interface_t *iface, const ip_header_t *orig_ip,
                         const void *orig_payload, size_t payload_size) {
    return icmp_send_dest_unreachable(iface, ICMP_HOST_UNREACHABLE,
                                    orig_ip, orig_payload, payload_size);
}

// Utility function to send ICMP network unreachable
int icmp_network_unreachable(net_interface_t *iface, const ip_header_t *orig_ip,
                            const void *orig_payload, size_t payload_size) {
    return icmp_send_dest_unreachable(iface, ICMP_NET_UNREACHABLE,
                                    orig_ip, orig_payload, payload_size);
}
