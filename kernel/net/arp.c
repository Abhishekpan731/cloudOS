/*
 * ARP (Address Resolution Protocol) Implementation
 * Ethernet address resolution for IPv4
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

// ARP constants
#define ARP_HARDWARE_TYPE_ETHERNET 0x0001
#define ARP_PROTOCOL_TYPE_IPV4     0x0800
#define ARP_OPCODE_REQUEST         0x0001
#define ARP_OPCODE_REPLY           0x0002

#define ARP_CACHE_SIZE 256
#define ARP_CACHE_TIMEOUT 300000 // 5 minutes in milliseconds

// ARP header structure
typedef struct {
    uint16_t hardware_type;    // Hardware type (Ethernet = 1)
    uint16_t protocol_type;    // Protocol type (IPv4 = 0x0800)
    uint8_t  hardware_len;     // Hardware address length (6 for Ethernet)
    uint8_t  protocol_len;     // Protocol address length (4 for IPv4)
    uint16_t opcode;           // ARP operation (request/reply)
    uint8_t  sender_mac[6];    // Sender hardware address
    uint32_t sender_ip;        // Sender protocol address
    uint8_t  target_mac[6];    // Target hardware address
    uint32_t target_ip;        // Target protocol address
} __attribute__((packed)) arp_header_t;

// ARP cache entry
typedef struct arp_cache_entry {
    uint32_t ip_addr;           // IP address
    uint8_t  mac_addr[6];       // MAC address
    uint64_t timestamp;         // Last used timestamp
    uint8_t  flags;             // Entry flags
    struct arp_cache_entry *next;
} arp_cache_entry_t;

// ARP cache
static arp_cache_entry_t *arp_cache[ARP_CACHE_SIZE];
static uint32_t arp_cache_count = 0;

// ARP statistics
static struct {
    uint64_t requests_sent;
    uint64_t replies_sent;
    uint64_t requests_received;
    uint64_t replies_received;
    uint64_t cache_hits;
    uint64_t cache_misses;
} arp_stats = {0};

// ARP cache hash function
static uint32_t arp_cache_hash(uint32_t ip_addr) {
    return (ip_addr % ARP_CACHE_SIZE);
}

// Find ARP cache entry
static arp_cache_entry_t *arp_cache_find(uint32_t ip_addr) {
    uint32_t hash = arp_cache_hash(ip_addr);
    arp_cache_entry_t *entry = arp_cache[hash];

    while (entry) {
        if (entry->ip_addr == ip_addr) {
            return entry;
        }
        entry = entry->next;
    }

    return NULL;
}

// Add or update ARP cache entry
static void arp_cache_add(uint32_t ip_addr, const uint8_t *mac_addr, uint8_t flags) {
    uint32_t hash = arp_cache_hash(ip_addr);
    arp_cache_entry_t *entry = arp_cache_find(ip_addr);

    if (entry) {
        // Update existing entry
        memcpy(entry->mac_addr, mac_addr, 6);
        entry->flags = flags;
        entry->timestamp = 0; // TODO: Get current time
        return;
    }

    // Create new entry
    entry = (arp_cache_entry_t *)kmalloc(sizeof(arp_cache_entry_t));
    if (!entry) return;

    entry->ip_addr = ip_addr;
    memcpy(entry->mac_addr, mac_addr, 6);
    entry->flags = flags;
    entry->timestamp = 0; // TODO: Get current time
    entry->next = arp_cache[hash];
    arp_cache[hash] = entry;
    arp_cache_count++;
}

// Remove ARP cache entry
static void arp_cache_remove(uint32_t ip_addr) {
    uint32_t hash = arp_cache_hash(ip_addr);
    arp_cache_entry_t *entry = arp_cache[hash];
    arp_cache_entry_t *prev = NULL;

    while (entry) {
        if (entry->ip_addr == ip_addr) {
            if (prev) {
                prev->next = entry->next;
            } else {
                arp_cache[hash] = entry->next;
            }
            kfree(entry);
            arp_cache_count--;
            return;
        }
        prev = entry;
        entry = entry->next;
    }
}

// Clean expired ARP cache entries
static void arp_cache_cleanup(void) {
    for (uint32_t i = 0; i < ARP_CACHE_SIZE; i++) {
        arp_cache_entry_t *entry = arp_cache[i];
        arp_cache_entry_t *prev = NULL;

        while (entry) {
            // TODO: Check if entry has expired
            // For now, just keep all entries
            prev = entry;
            entry = entry->next;
        }
    }
}

// Send ARP request
static int arp_send_request(net_interface_t *iface, uint32_t target_ip) {
    if (!iface) return -1;

    net_packet_t *packet = net_alloc_packet(sizeof(arp_header_t));
    if (!packet) return -1;

    arp_header_t *arp = (arp_header_t *)packet->data;

    // Fill ARP header for request
    arp->hardware_type = net_htons(ARP_HARDWARE_TYPE_ETHERNET);
    arp->protocol_type = net_htons(ARP_PROTOCOL_TYPE_IPV4);
    arp->hardware_len = 6;  // Ethernet MAC address length
    arp->protocol_len = 4;  // IPv4 address length
    arp->opcode = net_htons(ARP_OPCODE_REQUEST);

    // Sender information
    memcpy(arp->sender_mac, iface->mac_addr, 6);
    arp->sender_ip = net_htonl(iface->ip_addr);

    // Target information
    memset(arp->target_mac, 0x00, 6);  // Unknown target MAC
    arp->target_ip = net_htonl(target_ip);

    packet->size = sizeof(arp_header_t);

    // Send as broadcast Ethernet frame
    uint8_t broadcast_mac[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    int result = eth_send(iface, broadcast_mac, ETH_TYPE_ARP,
                         packet->data, packet->size);

    net_free_packet(packet);

    if (result >= 0) {
        arp_stats.requests_sent++;
    }

    return result;
}

// Send ARP reply
static int arp_send_reply(net_interface_t *iface, const arp_header_t *request) {
    if (!iface || !request) return -1;

    net_packet_t *packet = net_alloc_packet(sizeof(arp_header_t));
    if (!packet) return -1;

    arp_header_t *arp = (arp_header_t *)packet->data;

    // Fill ARP header for reply
    arp->hardware_type = net_htons(ARP_HARDWARE_TYPE_ETHERNET);
    arp->protocol_type = net_htons(ARP_PROTOCOL_TYPE_IPV4);
    arp->hardware_len = 6;
    arp->protocol_len = 4;
    arp->opcode = net_htons(ARP_OPCODE_REPLY);

    // Sender information (our interface)
    memcpy(arp->sender_mac, iface->mac_addr, 6);
    arp->sender_ip = net_htonl(iface->ip_addr);

    // Target information (from request sender)
    memcpy(arp->target_mac, request->sender_mac, 6);
    arp->target_ip = request->sender_ip;

    packet->size = sizeof(arp_header_t);

    // Send unicast Ethernet frame to requester
    int result = eth_send(iface, request->sender_mac, ETH_TYPE_ARP,
                         packet->data, packet->size);

    net_free_packet(packet);

    if (result >= 0) {
        arp_stats.replies_sent++;
    }

    return result;
}

// Resolve IP address to MAC address
int arp_resolve(net_interface_t *iface, uint32_t ip_addr, uint8_t *mac_addr) {
    if (!iface || !mac_addr) return -1;

    // Check ARP cache first
    arp_cache_entry_t *entry = arp_cache_find(ip_addr);
    if (entry) {
        memcpy(mac_addr, entry->mac_addr, 6);
        entry->timestamp = 0; // TODO: Update timestamp
        arp_stats.cache_hits++;
        return 0;
    }

    arp_stats.cache_misses++;

    // Send ARP request
    int result = arp_send_request(iface, ip_addr);
    if (result < 0) {
        return -1;
    }

    // TODO: Wait for ARP reply with timeout
    // For now, return error (synchronous resolution not implemented)
    return -1;
}

// Process incoming ARP packet
void arp_receive(net_interface_t *iface, net_packet_t *packet) {
    if (!iface || !packet || packet->size < sizeof(arp_header_t)) {
        if (packet) net_free_packet(packet);
        return;
    }

    arp_header_t *arp = (arp_header_t *)packet->data;

    // Verify ARP packet
    if (net_ntohs(arp->hardware_type) != ARP_HARDWARE_TYPE_ETHERNET ||
        net_ntohs(arp->protocol_type) != ARP_PROTOCOL_TYPE_IPV4 ||
        arp->hardware_len != 6 || arp->protocol_len != 4) {
        net_free_packet(packet);
        return;
    }

    uint16_t opcode = net_ntohs(arp->opcode);
    uint32_t sender_ip = net_ntohl(arp->sender_ip);
    uint32_t target_ip = net_ntohl(arp->target_ip);

    // Add sender to ARP cache
    arp_cache_add(sender_ip, arp->sender_mac, 0);

    // Process based on opcode
    switch (opcode) {
        case ARP_OPCODE_REQUEST:
            arp_stats.requests_received++;

            // Check if request is for us
            if (target_ip == iface->ip_addr) {
                arp_send_reply(iface, arp);
            }
            break;

        case ARP_OPCODE_REPLY:
            arp_stats.replies_received++;

            // Update cache with reply information
            arp_cache_add(sender_ip, arp->sender_mac, 0);
            break;

        default:
            // Unknown ARP opcode
            break;
    }

    net_free_packet(packet);
}

// Initialize ARP subsystem
int arp_init(void) {
    kprintf("ARP: Initializing Address Resolution Protocol...\n");

    // Clear ARP cache
    memset(arp_cache, 0, sizeof(arp_cache));

    kprintf("ARP: Initialized with cache size %u\n", ARP_CACHE_SIZE);
    return 0;
}

// Get ARP statistics
void arp_get_stats(uint64_t *requests_sent, uint64_t *replies_sent,
                   uint64_t *requests_received, uint64_t *replies_received,
                   uint64_t *cache_hits, uint64_t *cache_misses) {
    if (requests_sent) *requests_sent = arp_stats.requests_sent;
    if (replies_sent) *replies_sent = arp_stats.replies_sent;
    if (requests_received) *requests_received = arp_stats.requests_received;
    if (replies_received) *replies_received = arp_stats.replies_received;
    if (cache_hits) *cache_hits = arp_stats.cache_hits;
    if (cache_misses) *cache_misses = arp_stats.cache_misses;
}

// Print ARP cache
void arp_print_cache(void) {
    kprintf("ARP Cache Contents:\n");
    kprintf("IP Address      MAC Address       Flags\n");
    kprintf("----------------------------------------\n");

    for (uint32_t i = 0; i < ARP_CACHE_SIZE; i++) {
        arp_cache_entry_t *entry = arp_cache[i];
        while (entry) {
            kprintf("%d.%d.%d.%d    %02x:%02x:%02x:%02x:%02x:%02x  %02x\n",
                   (entry->ip_addr >> 24) & 0xFF,
                   (entry->ip_addr >> 16) & 0xFF,
                   (entry->ip_addr >> 8) & 0xFF,
                   entry->ip_addr & 0xFF,
                   entry->mac_addr[0], entry->mac_addr[1], entry->mac_addr[2],
                   entry->mac_addr[3], entry->mac_addr[4], entry->mac_addr[5],
                   entry->flags);
            entry = entry->next;
        }
    }
}

// Add static ARP entry
int arp_add_static(uint32_t ip_addr, const uint8_t *mac_addr) {
    if (!mac_addr) return -1;

    arp_cache_add(ip_addr, mac_addr, 0x01); // Static flag
    return 0;
}

// Delete ARP entry
int arp_delete(uint32_t ip_addr) {
    arp_cache_remove(ip_addr);
    return 0;
}
