# CloudOS Network Stack Design Document

## Overview

The CloudOS network stack provides a comprehensive, high-performance networking subsystem designed for cloud-native workloads. This document details the layered network architecture, protocol implementations, device drivers, and advanced networking features including virtualization, security, and performance optimization.

## Network Architecture

### OSI Model Implementation

```text
CloudOS Network Stack Architecture:
┌─────────────────────────────────────────────────────────────┐
│                    Application Layer                        │
│  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐           │
│  │ HTTP/HTTPS  │ │ DNS         │ │ DHCP        │           │
│  │ FTP         │ │ NTP         │ │ SSH         │           │
│  │             │ │             │ │             │           │
│  └──────┬──────┘ └──────┬──────┘ └──────┬──────┘           │
│         │                │                │                │
├─────────┼────────────────┼────────────────┼────────────────┤
│  ┌──────▼──────┐                                           │
│  │ Transport   │                                           │
│  │ Layer       │                                           │
│  │ (TCP/UDP)   │                                           │
│  └──────┬──────┘                                           │
│         │                                                  │
├─────────┼──────────────────────────────────────────────────┤
│  ┌──────▼──────┐ ┌─────────────┐ ┌─────────────┐           │
│  │ Network     │ │ ICMP        │ │ IGMP        │           │
│  │ Layer (IP)  │ │             │ │             │           │
│  │             │ │             │ │             │           │
│  └──────┬──────┘ └──────┬──────┘ └──────┬──────┘           │
│         │                │                │                │
├─────────┼────────────────┼────────────────┼────────────────┤
│  ┌──────▼──────┐                                           │
│  │ Data Link   │                                           │
│  │ Layer       │                                           │
│  │ (Ethernet)  │                                           │
│  └──────┬──────┘                                           │
│         │                                                  │
├─────────┼──────────────────────────────────────────────────┤
│  ┌──────▼──────┐ ┌─────────────┐ ┌─────────────┐           │
│  │ Physical    │ │ Device      │ │ Network     │           │
│  │ Layer       │ │ Drivers     │ │ Interfaces  │           │
│  │             │ │             │ │             │           │
│  └─────────────┘ └─────────────┘ └─────────────┘           │
└─────────────────────────────────────────────────────────────┘
```

### Core Network Components

#### Network Interface Layer

```c
// Network device structure
struct net_device {
    char name[IFNAMSIZ];               // Device name
    struct hlist_node name_hlist;      // Name hash list
    struct hlist_node index_hlist;     // Index hash list

    unsigned long mem_end;             // Shared memory end
    unsigned long mem_start;           // Shared memory start
    unsigned long base_addr;           // Device I/O address
    int irq;                           // Device IRQ number

    unsigned long state;               // Device state

    struct list_head dev_list;         // Device list
    struct list_head napi_list;        // NAPI list

    unsigned int flags;                // Device flags
    unsigned int priv_flags;           // Private flags
    unsigned short gflags;             // Generic flags
    unsigned short type;               // Hardware type

    unsigned int mtu;                  // Maximum transmission unit
    unsigned short hard_header_len;    // Hardware header length
    unsigned char perm_addr[MAX_ADDR_LEN]; // Permanent hardware address
    unsigned char addr_assign_type;    // Address assignment type
    unsigned char addr_len;            // Hardware address length
    unsigned char dev_addr[MAX_ADDR_LEN]; // Device hardware address

    struct netdev_hw_addr_list uc;     // Unicast addresses
    struct netdev_hw_addr_list mc;     // Multicast addresses
    struct netdev_hw_addr_list dev_addrs; // Device addresses

    unsigned char broadcast[MAX_ADDR_LEN]; // Broadcast address

    struct netdev_queue *_tx;          // Transmit queues
    unsigned int num_tx_queues;        // Number of TX queues
    unsigned int real_num_tx_queues;   // Real number of TX queues

    struct Qdisc *qdisc;               // Queue discipline
    struct netdev_queue *ingress_queue; // Ingress queue

    unsigned long tx_dropped;          // Dropped TX packets
    unsigned long tx_packets;          // Transmitted packets
    unsigned long tx_bytes;            // Transmitted bytes
    unsigned long rx_packets;          // Received packets
    unsigned long rx_bytes;            // Received bytes
    unsigned long rx_dropped;          // Dropped RX packets
    unsigned long rx_errors;           // Receive errors

    unsigned long last_rx;             // Last receive timestamp

    const struct net_device_ops *netdev_ops; // Network device operations
    const struct ethtool_ops *ethtool_ops; // Ethtool operations

    struct header_ops *header_ops;     // Header operations

    unsigned int watchdog_timeo;       // Watchdog timeout
    struct timer_list watchdog_timer;  // Watchdog timer

    int (*ndo_init)(struct net_device *); // Initialization function
    void (*ndo_uninit)(struct net_device *); // Uninitialization function
    u32 (*ndo_get_stats64)(struct net_device *, struct rtnl_link_stats64 *); // Get statistics

    struct device dev;                 // Device structure
    struct phy_device *phydev;         // PHY device

    struct lock_class_key *qdisc_tx_busylock; // Qdisc TX busy lock

    struct netdev_hw_addr_list vf_uc;  // VF unicast addresses
    struct netdev_hw_addr_list vf_mc;  // VF multicast addresses

    int ifindex;                       // Interface index
    int iflink;                        // Link interface

    struct net *nd_net;                // Network namespace

    void *priv;                        // Private data
};
```

#### Network Protocol Layer

```c
// Socket structure
struct socket {
    socket_state state;                // Socket state
    short type;                        // Socket type
    unsigned long flags;               // Socket flags

    const struct proto_ops *ops;       // Protocol operations
    struct fasync_struct *fasync_list; // Async I/O
    struct file *file;                 // Associated file
    struct sock *sk;                   // Socket kernel structure
    wait_queue_head_t wait;            // Wait queue

    short rcvlowat;                    // Receive low water mark
    struct sockaddr_storage addr;      // Socket address
};

// Socket kernel structure
struct sock {
    struct sock_common __sk_common;    // Common socket fields
    socket_state sk_state;             // Socket state
    u16 sk_type;                       // Socket type
    u16 sk_protocol;                   // Protocol
    unsigned long sk_flags;            // Socket flags

    int sk_rcvbuf;                     // Receive buffer size
    int sk_sndbuf;                     // Send buffer size

    struct sk_buff_head sk_receive_queue; // Receive queue
    struct sk_buff_head sk_write_queue; // Write queue
    struct sk_buff_head sk_error_queue; // Error queue

    struct proto *sk_prot;             // Protocol
    struct proto *sk_prot_creator;     // Protocol creator

    rwlock_t sk_callback_lock;         // Callback lock
    int sk_err;                        // Last error
    unsigned long sk_lingertime;       // Linger time

    struct pid *sk_peer_pid;           // Peer PID
    const struct cred *sk_peer_cred;   // Peer credentials

    long sk_rcvtimeo;                  // Receive timeout
    long sk_sndtimeo;                  // Send timeout

    void *sk_user_data;                // User data
    struct sk_filter *sk_filter;       // Socket filter

    struct {
        atomic_t rmem_alloc;           // Receive memory allocated
        int len;                       // Data length
        struct sk_buff *head;          // Head of buffer list
        struct sk_buff *tail;          // Tail of buffer list
    } sk_backlog;

    u32 sk_priority;                   // Socket priority
    struct ucred sk_peer_ucred;        // Peer credentials
    u32 sk_mark;                       // Socket mark

    struct dst_entry *sk_dst_cache;    // Destination cache
    struct dst_entry *sk_dst_pending;  // Pending destination

    struct sk_buff_head sk_omem_alloc; // Out of memory queue
    int sk_omem_alloc;                 // Out of memory allocations

    unsigned long sk_pacing_rate;      // Pacing rate
    unsigned long sk_max_pacing_rate;  // Maximum pacing rate

    struct page_frag sk_frag;          // Page fragment

    netdev_features_t sk_route_caps;   // Route capabilities
    netdev_features_t sk_route_nocaps; // Route no capabilities

    int sk_gso_type;                   // GSO type
    unsigned int sk_gso_max_size;      // GSO maximum size
    gfp_t sk_allocation;               // Allocation flags
    u32 sk_txhash;                     // TX hash

    u8 sk_pacing_shift;                // Pacing shift
    unsigned long sk_pmtu;             // Path MTU
    struct rcu_head sk_rcu;            // RCU head
};
```

## Transport Layer Protocols

### TCP Implementation

```c
// TCP socket structure
struct tcp_sock {
    struct inet_connection_sock inet_conn; // Internet connection sock
    u16 tcp_header_len;               // TCP header length
    u16 xmit_size_goal_segs;          // Transmit size goal segments
    u32 rcv_nxt;                      // Receive next
    u32 copied_seq;                   // Copied sequence
    u32 rcv_wup;                      // Receive window update
    u32 snd_nxt;                      // Send next
    u32 snd_una;                      // Send unacknowledged
    u32 snd_sml;                      // Send small
    u32 rcv_tstamp;                   // Receive timestamp
    u32 lsndtime;                     // Last send time

    u32 tsoffset;                     // Timestamp offset
    u32 snd_wl1;                      // Send window left 1
    u32 snd_wnd;                      // Send window
    u32 max_window;                   // Maximum window
    u32 mss_cache;                    // MSS cache
    u32 window_clamp;                 // Window clamp
    u32 rcv_ssthresh;                 // Receive slow start threshold
    u16 advmss;                       // Advertised MSS
    u8 unused;                        // Unused
    u8 nonagle;                       // Nagle algorithm
    u8 ecn_flags;                     // ECN flags
    u8 repair;                        // Repair mode
    u8 frto;                          // F-RTO
    u8 frto_counter;                  // F-RTO counter
    u32 undo_marker;                  // Undo marker
    u32 undo_retrans;                 // Undo retransmissions
    u8 reordering;                    // Reordering
    u8 keepalive_probes;              // Keepalive probes

    u32 rcv_rtt_est;                  // Receive RTT estimate
    u32 rcv_rtt_var;                  // Receive RTT variance
    u32 snd_ssthresh;                 // Send slow start threshold
    u32 snd_cwnd;                     // Send congestion window
    u32 snd_cwnd_cnt;                 // Send congestion window count
    u32 snd_cwnd_clamp;               // Send congestion window clamp
    u32 snd_cwnd_used;                // Send congestion window used
    u32 snd_cwnd_stamp;               // Send congestion window stamp
    u32 prior_cwnd;                   // Prior congestion window
    u32 prr_delivered;                // PRR delivered
    u32 prr_out;                      // PRR out
    u32 delivered;                    // Delivered
    u32 delivered_ce;                 // Delivered CE
    u32 app_limited;                  // App limited
    u32 lost;                         // Lost
    u32 retrans;                      // Retransmissions
    u32 total_retrans;                // Total retransmissions
    u32 pmtu_probe;                   // PMTU probe
    u32 probe_size;                   // Probe size
    u32 probe_timestamp;              // Probe timestamp

    struct hrtimer pacing_timer;      // Pacing timer
    struct hrtimer compressed_ack_timer; // Compressed ACK timer
    struct sk_buff *compressed_ack;   // Compressed ACK

    struct request_sock_queue rskq;   // Request socket queue
    struct fastopen_queue fastopenq;  // Fast open queue

    struct work_struct work;          // Work structure
    int (*af_specific)(struct sock *, struct sk_buff *, int); // AF specific
    struct tcp_congestion_ops *ca_ops; // Congestion control ops
    struct tcp_retransmit_queue retransmit_queue; // Retransmit queue
    struct tcp_ulp_ops *ulp_ops;      // ULP operations
    u32 saved_syn;                    // Saved SYN
    u32 syn_data;                     // SYN data
    u32 syn_fastopen;                 // SYN fast open
    u32 syn_fastopen_ch;              // SYN fast open cookie
    u32 syn_data_acked;               // SYN data acked
    u32 tcp_challenge_timestamp;      // Challenge timestamp
    u32 tcp_challenge_count;          // Challenge count
    u32 last_oow_ack_time;            // Last out of window ACK time
    u32 tlp_high_seq;                 // TLP high sequence
    u32 tlp_retrans;                  // TLP retransmissions
    u32 tlp_start_seq;                // TLP start sequence
    u8 tlp_retrans_time;              // TLP retransmit time
};

// TCP state machine
enum tcp_state {
    TCP_ESTABLISHED = 1,
    TCP_SYN_SENT,
    TCP_SYN_RECV,
    TCP_FIN_WAIT1,
    TCP_FIN_WAIT2,
    TCP_TIME_WAIT,
    TCP_CLOSE,
    TCP_CLOSE_WAIT,
    TCP_LAST_ACK,
    TCP_LISTEN,
    TCP_CLOSING,
    TCP_NEW_SYN_RECV,
};

// TCP congestion control
struct tcp_congestion_ops {
    void (*init)(struct sock *);      // Initialize
    void (*release)(struct sock *);   // Release
    u32 (*ssthresh)(struct sock *);   // Slow start threshold
    void (*cong_avoid)(struct sock *, u32, u32); // Congestion avoidance
    void (*set_state)(struct sock *, u8); // Set state
    void (*cwnd_event)(struct sock *, enum tcp_ca_event); // Congestion window event
    void (*in_ack_event)(struct sock *, u32); // In ACK event
    void (*pkts_acked)(struct sock *, const struct ack_sample *); // Packets acked
    u32 (*undo_cwnd)(struct sock *);  // Undo congestion window
    void (*get_info)(struct sock *, u32, union tcp_cc_info *); // Get info
    char name[16];                    // Name
    struct module *owner;             // Owner
    struct list_head list;            // List
};
```

### UDP Implementation

```c
// UDP socket structure
struct udp_sock {
    struct inet_sock inet;            // Internet socket
    unsigned long udp_flags;          // UDP flags
    int pending;                      // Pending frames
    unsigned int corkflag;            // Cork flag
    __u16 encap_type;                 // Encapsulation type
    __u16 len;                        // Length
    __u16 pcslen;                     // PCS length
    __u16 pcrlen;                     // PCR length
    __u16 pcflglen;                   // PCF length
    __u16 gso_size;                   // GSO size
    int (*encap_rcv)(struct sock *, struct sk_buff *); // Encapsulation receive
    void (*encap_err_lookup)(struct sock *, struct sk_buff *); // Encapsulation error lookup
    struct sk_buff *(*encap_err_rcv)(struct sock *, struct sk_buff *); // Encapsulation error receive
    struct udp_offload udp_offload;   // UDP offload
    u32 gro_enabled;                  // GRO enabled
};

// UDP receive
int udp_recvmsg(struct sock *sk, struct msghdr *msg, size_t len, int noblock,
                int flags, int *addr_len) {
    struct inet_sock *inet = inet_sk(sk);
    struct udp_sock *up = udp_sk(sk);
    int peeked, off = 0;
    int err;
    int is_udplite = IS_UDPLITE(sk);
    bool checksum_valid = false;

    if (flags & MSG_ERRQUEUE) return inet_recv_error(sk, msg, len, addr_len);

    try_again:
    peeked = flags & MSG_PEEK;
    off = sk_peek_offset(sk, peeked);

    if (!skb_queue_empty(&sk->sk_receive_queue)) {
        struct sk_buff *skb = __skb_peek(&sk->sk_receive_queue);
        return udp_recvmsg_peek(sk, msg, len, flags, addr_len, skb, off,
                               &peeked, &checksum_valid);
    }

    if (up->pending) {
        struct sk_buff *skb = ip_recv_error(sk, msg, len, addr_len);
        if (!skb) goto try_again;
        return udp_recvmsg_peek(sk, msg, len, flags, addr_len, skb, off,
                               &peeked, &checksum_valid);
    }

    if (sk_can_busy_loop(sk)) {
        if (sk_busy_loop(sk, flags & MSG_DONTWAIT)) goto try_again;
    }

    err = sock_error(sk);
    if (err) return -err;

    if (sk->sk_state == TCP_CLOSE && !sock_flag(sk, SOCK_DONE)) {
        err = -ENOTCONN;
        goto out;
    }

    err = sk_wait_data(sk, &timeo, NULL);
    if (err < 0) goto out;

    if (sk->sk_state == TCP_CLOSE) {
        err = -ENOTCONN;
        goto out;
    }

    goto try_again;

out:
    return err;
}
```

## Network Layer Protocols

### IP Protocol Implementation

```c
// IP options structure
struct ip_options {
    __be32 faddr;                      // First hop address
    __be32 nexthop;                    // Next hop address
    unsigned char optlen;             // Option length
    unsigned char srr;                // Strict source route
    unsigned char rr;                 // Record route
    unsigned char ts;                 // Timestamp
    unsigned char is_strictroute:1,   // Strict route
                  is_changed:1,       // Changed
                  is_setbyuser:1,     // Set by user
                  srr_is_hit:1,       // SRR hit
                  is_changed_set:1,   // Changed set
                  rr_needaddr:1,      // RR needs address
                  ts_needtime:1,      // TS needs time
                  ts_needaddr:1;      // TS needs address
    unsigned char router_alert;       // Router alert
    unsigned char cipso;              // CIPSO
    unsigned char __pad2;             // Padding
    unsigned char __data[0];          // Option data
};

// IP fragmentation
struct ipfrag {
    struct inet_frag_queue q;         // Fragment queue
    __be16 id;                        // Fragment ID
    u32 user;                         // User ID
    struct ip *ip;                    // IP header
    struct sk_buff *skb;              // Socket buffer
    int len;                          // Length
    int meat;                         // Meat
    __be32 saddr;                     // Source address
    __be32 daddr;                     // Destination address
    struct list_head list;            // List
    struct rcu_head rcu;              // RCU head
};

// IP forwarding
int ip_forward(struct sk_buff *skb) {
    struct iphdr *iph = ip_hdr(skb);
    struct net_device *dev = skb->dev;
    struct rtable *rt;
    int err;

    // Check TTL
    if (iph->ttl <= 1) {
        icmp_send(skb, ICMP_TIME_EXCEEDED, ICMP_EXC_TTL, 0);
        goto drop;
    }

    // Decrement TTL
    ip_decrease_ttl(iph);

    // Find route
    rt = ip_route_output_key(dev_net(dev), &iph->daddr, &iph->saddr,
                            iph->tos, 0, 0, 0, 0, 0);
    if (IS_ERR(rt)) goto drop;

    // Check if route is local
    if (rt->rt_type == RTN_LOCAL) {
        icmp_send(skb, ICMP_DEST_UNREACH, ICMP_PORT_UNREACH, 0);
        ip_rt_put(rt);
        goto drop;
    }

    // Forward packet
    return ip_forward_finish(rt, skb);

drop:
    kfree_skb(skb);
    return -EINVAL;
}
```

### ICMP Protocol Implementation

```c
// ICMP control structure
struct icmp_control {
    void (*handler)(struct sk_buff *); // Handler function
    short error;                       // Error code
};

// ICMP message types
#define ICMP_ECHOREPLY      0   /* Echo Reply */
#define ICMP_DEST_UNREACH   3   /* Destination Unreachable */
#define ICMP_SOURCE_QUENCH  4   /* Source Quench */
#define ICMP_REDIRECT       5   /* Redirect (change route) */
#define ICMP_ECHO           8   /* Echo Request */
#define ICMP_TIME_EXCEEDED  11  /* Time Exceeded */
#define ICMP_PARAMETERPROB  12  /* Parameter Problem */
#define ICMP_TIMESTAMP      13  /* Timestamp Request */
#define ICMP_TIMESTAMPREPLY 14  /* Timestamp Reply */
#define ICMP_INFO_REQUEST   15  /* Information Request */
#define ICMP_INFO_REPLY     16  /* Information Reply */
#define ICMP_ADDRESS        17  /* Address Mask Request */
#define ICMP_ADDRESSREPLY   18  /* Address Mask Reply */

// ICMP handler
void icmp_reply(struct icmp_bxm *icmp_param, struct sk_buff *skb) {
    struct icmp_bxm *icmp = icmp_param;
    struct sk_buff *skb2 = skb_copy(skb, GFP_ATOMIC);

    if (!skb2) return;

    // Build ICMP reply
    icmp->data.icmph.type = icmp->data.icmph.code = 0;
    icmp->data.icmph.checksum = 0;

    // Swap addresses
    swap(icmp->data.icmph.un.echo.id, icmp->data.icmph.un.echo.sequence);

    // Send reply
    icmp_push_reply(icmp, &skb2, &icmp->data.icmph, skb2->len);

    icmp_reply_queue(icmp, skb2);
}

// ICMP error handling
void icmp_send(struct sk_buff *skb_in, int type, int code, __be32 info) {
    struct iphdr *iph;
    int room;
    struct icmp_bxm icmp_param;
    struct sk_buff *skb = skb_in;

    // Check if we should send ICMP
    if (skb->len < sizeof(struct iphdr)) goto out;

    // Get IP header
    iph = (struct iphdr *)skb->data;

    // Don't send ICMP for ICMP
    if (iph->protocol == IPPROTO_ICMP) {
        struct icmphdr *icmph = (struct icmphdr *)(skb->data + (iph->ihl << 2));
        if (icmph->type != ICMP_ECHO && icmph->type != ICMP_ECHOREPLY &&
            icmph->type != ICMP_TIMESTAMP && icmph->type != ICMP_TIMESTAMPREPLY &&
            icmph->type != ICMP_INFO_REQUEST && icmph->type != ICMP_INFO_REPLY)
            goto out;
    }

    // Build ICMP error
    icmp_param.data.icmph.type = type;
    icmp_param.data.icmph.code = code;
    icmp_param.data.icmph.un.gateway = info;
    icmp_param.data.icmph.checksum = 0;

    // Send ICMP error
    icmp_reply(&icmp_param, skb);

out:
    return;
}
```

## Data Link Layer

### Ethernet Implementation

```c
// Ethernet header
struct ethhdr {
    unsigned char h_dest[ETH_ALEN];    // Destination address
    unsigned char h_source[ETH_ALEN];  // Source address
    __be16 h_proto;                    // Protocol
} __attribute__((packed));

// Ethernet device operations
struct net_device_ops {
    int (*ndo_init)(struct net_device *); // Initialize
    void (*ndo_uninit)(struct net_device *); // Uninitialize
    int (*ndo_open)(struct net_device *); // Open
    int (*ndo_stop)(struct net_device *); // Stop
    netdev_tx_t (*ndo_start_xmit)(struct sk_buff *, struct net_device *); // Start transmit
    u16 (*ndo_select_queue)(struct net_device *, struct sk_buff *, struct net_device *); // Select queue
    void (*ndo_change_rx_flags)(struct net_device *, int); // Change RX flags
    void (*ndo_set_rx_mode)(struct net_device *); // Set RX mode
    int (*ndo_set_mac_address)(struct net_device *, void *); // Set MAC address
    int (*ndo_validate_addr)(struct net_device *); // Validate address
    int (*ndo_do_ioctl)(struct net_device *, struct ifreq *, int); // Do ioctl
    int (*ndo_set_config)(struct net_device *, struct ifmap *); // Set config
    int (*ndo_change_mtu)(struct net_device *, int); // Change MTU
    int (*ndo_neigh_setup)(struct net_device *, struct neigh_parms *); // Neighbor setup
    void (*ndo_tx_timeout)(struct net_device *, unsigned int); // TX timeout
    struct rtnl_link_stats64 *(*ndo_get_stats64)(struct net_device *, struct rtnl_link_stats64 *); // Get stats
    int (*ndo_has_offload)(struct net_device *, netdev_features_t); // Has offload
    int (*ndo_set_vf_mac)(struct net_device *, int, u8 *); // Set VF MAC
    int (*ndo_set_vf_vlan)(struct net_device *, int, u16, u8); // Set VF VLAN
    int (*ndo_set_vf_rate)(struct net_device *, int, int, int); // Set VF rate
    int (*ndo_set_vf_spoofchk)(struct net_device *, int, bool); // Set VF spoof check
    int (*ndo_get_vf_config)(struct net_device *, int, struct ifla_vf_info *); // Get VF config
    int (*ndo_set_vf_link_state)(struct net_device *, int, int); // Set VF link state
    int (*ndo_get_vf_stats)(struct net_device *, int, struct ifla_vf_stats *); // Get VF stats
    int (*ndo_set_vf_port)(struct net_device *, int, struct nlattr **); // Set VF port
    int (*ndo_get_vf_port)(struct net_device *, int, struct sk_buff *); // Get VF port
    int (*ndo_setup_tc)(struct net_device *, u32, u32, struct tc_to_netdev *); // Setup TC
    int (*ndo_add_slave)(struct net_device *, struct net_device *, struct nlattr **); // Add slave
    int (*ndo_del_slave)(struct net_device *, struct net_device *); // Delete slave
    netdev_features_t (*ndo_fix_features)(struct net_device *, netdev_features_t); // Fix features
    int (*ndo_set_features)(struct net_device *, netdev_features_t); // Set features
    int (*ndo_neigh_construct)(struct net_device *, struct neighbour *); // Neighbor construct
    void (*ndo_neigh_destroy)(struct net_device *, struct neighbour *); // Neighbor destroy
    int (*ndo_fdb_add)(struct net_device *, unsigned char *, u16, u16); // FDB add
    int (*ndo_fdb_del)(struct net_device *, const unsigned char *, u16); // FDB del
    int (*ndo_fdb_dump)(struct net_device *, struct sk_buff *, struct netlink_callback *); // FDB dump
    int (*ndo_bridge_setlink)(struct net_device *, struct nlmsghdr *, u16); // Bridge setlink
    int (*ndo_bridge_getlink)(struct sk_buff *, u32, u32, struct net_device *, u32, int); // Bridge getlink
    int (*ndo_bridge_dellink)(struct net_device *, struct nlmsghdr *, u16); // Bridge dellink
    int (*ndo_change_carrier)(struct net_device *, bool); // Change carrier
    int (*ndo_get_phys_port_id)(struct net_device *, struct netdev_phys_item_id *); // Get phys port ID
    int (*ndo_get_phys_port_name)(struct net_device *, char *, size_t); // Get phys port name
    int (*ndo_dfwd_add_station)(struct net_device *, struct net_device *); // DFWD add station
    int (*ndo_dfwd_del_station)(struct net_device *, struct net_device *); // DFWD del station
    netdev_tx_t (*ndo_dfwd_start_xmit)(struct sk_buff *, struct net_device *, struct net_device *); // DFWD start xmit
    int (*ndo_get_lock_subclass)(struct net_device *); // Get lock subclass
};

// Ethernet packet transmission
netdev_tx_t eth_start_xmit(struct sk_buff *skb, struct net_device *dev) {
    struct ethhdr *eth = (struct ethhdr *)skb->data;
    unsigned short proto = ntohs(eth->h_proto);
    int ret;

    // Check if device is up
    if (unlikely(!(dev->flags & IFF_UP))) {
        dev_kfree_skb(skb);
        return NETDEV_TX_OK;
    }

    // Handle VLAN
    if (proto == ETH_P_8021Q) {
        ret = vlan_start_xmit(skb, dev);
        if (ret) goto out;
    }

    // Transmit packet
    ret = dev_hard_start_xmit(skb, dev, NULL);

out:
    return ret;
}
```

## Network Device Drivers

### Generic Network Driver Framework

```c
// Network driver structure
struct net_driver {
    const char *name;                  // Driver name
    const char *version;               // Driver version
    const char *author;                // Driver author

    int (*probe)(struct pci_dev *, const struct pci_device_id *); // Probe
    void (*remove)(struct pci_dev *); // Remove
    int (*suspend)(struct pci_dev *, pm_message_t); // Suspend
    int (*resume)(struct pci_dev *);  // Resume

    struct pci_device_id *id_table;    // PCI ID table
    struct pci_driver pci_driver;      // PCI driver

    struct net_device_ops *netdev_ops; // Network device ops
    struct ethtool_ops *ethtool_ops;   // Ethtool ops

    unsigned int features;             // Driver features
    unsigned int flags;                // Driver flags
};

// Driver probe function
static int net_driver_probe(struct pci_dev *pdev, const struct pci_device_id *ent) {
    struct net_device *netdev;
    struct net_driver *driver = (struct net_driver *)ent->driver_data;
    int err;

    // Enable PCI device
    err = pci_enable_device(pdev);
    if (err) return err;

    // Request regions
    err = pci_request_regions(pdev, driver->name);
    if (err) goto err_disable_device;

    // Allocate network device
    netdev = alloc_etherdev(sizeof(struct net_private));
    if (!netdev) {
        err = -ENOMEM;
        goto err_release_regions;
    }

    // Initialize private data
    struct net_private *priv = netdev_priv(netdev);
    priv->pdev = pdev;
    priv->driver = driver;

    // Set device operations
    netdev->netdev_ops = driver->netdev_ops;
    netdev->ethtool_ops = driver->ethtool_ops;

    // Set device features
    netdev->features = driver->features;
    netdev->hw_features = driver->features;

    // Set device information
    pci_set_drvdata(pdev, netdev);

    // Register network device
    err = register_netdev(netdev);
    if (err) goto err_free_netdev;

    return 0;

err_free_netdev:
    free_netdev(netdev);
err_release_regions:
    pci_release_regions(pdev);
err_disable_device:
    pci_disable_device(pdev);
    return err;
}
```

## Advanced Networking Features

### Network Virtualization

```c
// Virtual network interface
struct vnet_device {
    struct net_device netdev;          // Base network device
    struct vnet_port *port;            // Virtual port
    struct hlist_node hlist;           // Hash list
    u32 id;                            // Virtual device ID
    u32 flags;                         // Virtual device flags
};

// Virtual network port
struct vnet_port {
    struct hlist_head devices;         // Virtual devices
    struct net_device *real_dev;       // Real network device
    struct vnet_bridge *bridge;        // Virtual bridge
    spinlock_t lock;                   // Port lock
    u32 id;                            // Port ID
    u32 flags;                         // Port flags
};

// Virtual bridge
struct vnet_bridge {
    struct hlist_head ports;           // Bridge ports
    struct net_device *bridge_dev;     // Bridge device
    spinlock_t lock;                   // Bridge lock
    u32 id;                            // Bridge ID
    u32 flags;                         // Bridge flags
};

// Packet forwarding in virtual network
int vnet_forward_packet(struct sk_buff *skb, struct vnet_port *in_port) {
    struct vnet_bridge *bridge = in_port->bridge;
    struct vnet_port *out_port;
    struct ethhdr *eth = eth_hdr(skb);
    int ret = 0;

    // Learn source MAC address
    vnet_learn_mac(bridge, eth->h_source, in_port);

    // Find destination port
    out_port = vnet_lookup_mac(bridge, eth->h_dest);
    if (!out_port) {
        // Flood packet to all ports
        vnet_flood_packet(skb, bridge, in_port);
        goto out;
    }

    // Forward packet to destination port
    if (out_port != in_port) {
        ret = vnet_send_packet(skb, out_port);
    } else {
        // Packet is for local delivery
        kfree_skb(skb);
    }

out:
    return ret;
}
```

### Network Security

```c
// Network firewall rule
struct net_filter_rule {
    u32 priority;                      // Rule priority
    u32 action;                        // Rule action
    struct net_filter_match *match;    // Match criteria
    struct list_head list;             // Rule list
};

// Network filter match
struct net_filter_match {
    u32 protocol;                      // Protocol
    struct in_addr src_addr;           // Source address
    struct in_addr dst_addr;           // Destination address
    u16 src_port;                      // Source port
    u16 dst_port;                      // Destination port
    u32 flags;                         // Match flags
};

// Packet filtering
int net_filter_packet(struct sk_buff *skb, struct net_device *dev) {
    struct net_filter_rule *rule;
    struct iphdr *iph = ip_hdr(skb);
    int ret = NF_ACCEPT;

    // Traverse filter rules
    list_for_each_entry(rule, &dev->filter_rules, list) {
        // Check if rule matches
        if (net_filter_match_packet(rule->match, skb)) {
            // Apply rule action
            ret = rule->action;
            break;
        }
    }

    return ret;
}

// Network address translation
struct nat_entry {
    struct in_addr local_addr;         // Local address
    u16 local_port;                    // Local port
    struct in_addr global_addr;        // Global address
    u16 global_port;                   // Global port
    u32 protocol;                      // Protocol
    unsigned long expires;             // Expiration time
    struct list_head list;             // Entry list
};

// NAT packet translation
int nat_translate_packet(struct sk_buff *skb, int direction) {
    struct iphdr *iph = ip_hdr(skb);
    struct nat_entry *entry;
    int ret = 0;

    // Find NAT entry
    entry = nat_lookup_entry(iph, direction);
    if (!entry) {
        ret = -ENOENT;
        goto out;
    }

    // Translate addresses
    if (direction == NAT_OUTBOUND) {
        iph->saddr = entry->global_addr.s_addr;
        if (iph->protocol == IPPROTO_TCP || iph->protocol == IPPROTO_UDP) {
            struct tcphdr *tcph = tcp_hdr(skb);
            tcph->source = htons(entry->global_port);
        }
    } else {
        iph->daddr = entry->local_addr.s_addr;
        if (iph->protocol == IPPROTO_TCP || iph->protocol == IPPROTO_UDP) {
            struct tcphdr *tcph = tcp_hdr(skb);
            tcph->dest = htons(entry->local_port);
        }
    }

    // Update checksums
    iph->check = 0;
    iph->check = ip_fast_csum((unsigned char *)iph, iph->ihl);

    if (iph->protocol == IPPROTO_TCP) {
        struct tcphdr *tcph = tcp_hdr(skb);
        tcph->check = 0;
        tcph->check = tcp_v4_check(skb->len - (iph->ihl << 2),
                                  iph->saddr, iph->daddr,
                                  csum_partial((char *)tcph, skb->len - (iph->ihl << 2), 0));
    }

out:
    return ret;
}
```

## Performance Optimization

### Packet Processing Acceleration

```c
// Receive packet steering
struct rps_map {
    unsigned int len;                  // Map length
    struct rps_dev_flow_table *table;  // Flow table
    struct callback_head rcu;          // RCU head
};

// RPS processing
int rps_process_packet(struct rps_map *map, struct sk_buff *skb) {
    u32 hash = skb_get_hash(skb);
    u16 index = hash & (map->len - 1);
    struct rps_dev_flow *flow = &map->table->flows[index];
    int cpu;

    // Get target CPU
    cpu = flow->cpu;
    if (cpu == RPS_NO_CPU) {
        // Assign CPU
        cpu = rps_select_cpu(map, hash);
        flow->cpu = cpu;
    }

    // Enqueue packet for target CPU
    return rps_enqueue_packet(cpu, skb);
}

// Transmit packet steering
struct xps_map {
    unsigned int len;                  // Map length
    unsigned int *cpus_map;            // CPU map
    struct callback_head rcu;          // RCU head
};

// XPS processing
int xps_select_queue(struct xps_map *map, struct sk_buff *skb) {
    u32 hash = skb_get_hash(skb);
    int queue;

    // Select queue based on hash
    queue = hash % map->len;

    // Check if CPU can use this queue
    if (!(map->cpus_map[queue] & (1 << smp_processor_id()))) {
        // Find alternative queue
        queue = xps_find_queue(map, smp_processor_id());
    }

    return queue;
}
```

### Network Offloading

```c
// TCP segmentation offload
struct tso_state {
    struct sk_buff *skb;               // Original SKB
    int seqnum;                        // Sequence number
    int ipv4_id;                       // IPv4 ID
    int tcp_seqnum;                    // TCP sequence number
    int header_len;                    // Header length
    int payload_len;                   // Payload length
    int mss;                           // Maximum segment size
};

// TSO packet segmentation
int tso_segment_packet(struct sk_buff *skb, struct tso_state *state) {
    struct sk_buff *segs = NULL;
    struct sk_buff *nskb;
    int ret = 0;

    // Check if TSO is needed
    if (skb->len <= state->mss) {
        return 0;
    }

    // Segment packet
    while (skb->len > state->mss) {
        // Allocate new SKB
        nskb = alloc_skb(state->header_len + state->mss, GFP_ATOMIC);
        if (!nskb) {
            ret = -ENOMEM;
            goto out;
        }

        // Copy headers
        skb_copy_header(nskb, skb);
        memcpy(nskb->data, skb->data, state->header_len);

        // Copy payload
        memcpy(nskb->data + state->header_len,
               skb->data + state->header_len, state->mss);

        // Update lengths
        nskb->len = state->header_len + state->mss;
        nskb->data_len = state->mss;
        skb->len -= state->mss;
        skb->data_len -= state->mss;

        // Update headers
        tso_update_headers(nskb, state);

        // Add to segment list
        if (!segs) {
            segs = nskb;
        } else {
            segs->next = nskb;
        }

        state->tcp_seqnum += state->mss;
        state->ipv4_id++;
    }

out:
    return ret;
}
```

## Future Enhancements

### Planned Features

- **Advanced Routing**: BGP, OSPF, and MPLS support
- **Network Function Virtualization**: NFV infrastructure
- **Software Defined Networking**: OpenFlow and SDN support
- **Network Security**: Advanced firewall and IDS/IPS
- **Quality of Service**: Traffic shaping and prioritization
- **Network Monitoring**: Advanced analytics and telemetry
- **Container Networking**: Kubernetes CNI plugins
- **Edge Computing**: Distributed network processing

---

## Document Information

**CloudOS Network Stack Design Document**
*Comprehensive guide for network architecture, protocols, and performance optimization*
