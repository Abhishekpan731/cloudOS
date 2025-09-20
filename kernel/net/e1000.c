/*
 * Intel e1000 Network Driver
 * Driver for Intel 8254x Gigabit Ethernet Controller
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

// Simple strcpy for kernel use
static char *strcpy(char *dest, const char *src) {
    char *d = dest;
    while ((*d++ = *src++));
    return dest;
}

// PCI device structure (simplified for e1000)
typedef struct
{
    uint16_t vendor_id;
    uint16_t device_id;
    uint8_t bus;
    uint8_t slot;
    uint8_t function;
} pci_device_t;

// PCI functions (simplified)
static uint32_t pci_get_bar_address(pci_device_t *dev, int bar)
{
    (void)dev;
    (void)bar;
    return 0xFEBC0000; // Dummy MMIO address
}

// e1000 register offsets
#define E1000_CTRL 0x0000     // Device Control Register
#define E1000_STATUS 0x0008   // Device Status Register
#define E1000_EECD 0x0010     // EEPROM/Flash Control/Data
#define E1000_EERD 0x0014     // EEPROM Read Register
#define E1000_CTRL_EXT 0x0018 // Extended Device Control Register
#define E1000_MDIC 0x0020     // MDI Control Register
#define E1000_FCAL 0x0028     // Flow Control Address Low
#define E1000_FCAH 0x002C     // Flow Control Address High
#define E1000_FCT 0x0030      // Flow Control Type
#define E1000_VET 0x0038      // VLAN Ether Type
#define E1000_ICR 0x00C0      // Interrupt Cause Read
#define E1000_ITR 0x00C4      // Interrupt Throttling Rate
#define E1000_ICS 0x00C8      // Interrupt Cause Set
#define E1000_IMS 0x00D0      // Interrupt Mask Set/Read
#define E1000_IMC 0x00D8      // Interrupt Mask Clear
#define E1000_IAM 0x00E0      // Interrupt Acknowledge Auto Mask
#define E1000_RCTL 0x0100     // Receive Control Register
#define E1000_FCTTV 0x0170    // Flow Control Transmit Timer Value
#define E1000_TXCW 0x0178     // Transmit Configuration Word
#define E1000_RXCW 0x0180     // Receive Configuration Word
#define E1000_TCTL 0x0400     // Transmit Control Register
#define E1000_TIPG 0x0410     // Transmit Inter Packet Gap
#define E1000_AIT 0x0458      // Adaptive IFS Throttle
#define E1000_LEDCTL 0x0E00   // LED Control
#define E1000_PBA 0x1000      // Packet Buffer Allocation
#define E1000_FCRTL 0x2160    // Flow Control Receive Threshold Low
#define E1000_FCRTH 0x2168    // Flow Control Receive Threshold High
#define E1000_RDBAL 0x2800    // Receive Descriptor Base Address Low
#define E1000_RDBAH 0x2804    // Receive Descriptor Base Address High
#define E1000_RDRLEN 0x2808   // Receive Descriptor Length
#define E1000_RDH 0x2810      // Receive Descriptor Head
#define E1000_RDT 0x2818      // Receive Descriptor Tail
#define E1000_RDTR 0x2820     // Receive Delay Timer
#define E1000_RDBAL0 E1000_RDBAL
#define E1000_RDBAH0 E1000_RDBAH
#define E1000_RDRLEN0 E1000_RDRLEN
#define E1000_RDH0 E1000_RDH
#define E1000_RDT0 E1000_RDT
#define E1000_RDTR0 E1000_RDTR
#define E1000_TDBAL 0x3800  // Transmit Descriptor Base Address Low
#define E1000_TDBAH 0x3804  // Transmit Descriptor Base Address High
#define E1000_TDLEN 0x3808  // Transmit Descriptor Length
#define E1000_TDH 0x3810    // Transmit Descriptor Head
#define E1000_TDT 0x3818    // Transmit Descriptor Tail
#define E1000_TIDV 0x3820   // Transmit Interrupt Delay Value
#define E1000_TXDCTL 0x3828 // Transmit Descriptor Control
#define E1000_TADV 0x382C   // Transmit Absolute Interrupt Delay Value
#define E1000_TDBAL0 E1000_TDBAL
#define E1000_TDBAH0 E1000_TDBAH
#define E1000_TDLEN0 E1000_TDLEN
#define E1000_TDH0 E1000_TDH
#define E1000_TDT0 E1000_TDT
#define E1000_TIDV0 E1000_TIDV
#define E1000_TXDCTL0 E1000_TXDCTL
#define E1000_TADV0 E1000_TADV
#define E1000_MTA 0x5200 // Multicast Table Array
#define E1000_RAL 0x5400 // Receive Address Low
#define E1000_RAH 0x5404 // Receive Address High

// Receive/Transmit Descriptor structures
typedef struct
{
    volatile uint64_t addr;    // Buffer address
    volatile uint16_t length;  // Buffer length
    volatile uint16_t csum;    // Checksum
    volatile uint8_t status;   // Status
    volatile uint8_t errors;   // Errors
    volatile uint16_t special; // Special
} __attribute__((packed)) e1000_rx_desc_t;

typedef struct
{
    volatile uint64_t addr;    // Buffer address
    volatile uint16_t length;  // Buffer length
    volatile uint8_t cso;      // Checksum offset
    volatile uint8_t cmd;      // Command
    volatile uint8_t status;   // Status
    volatile uint8_t css;      // Checksum start
    volatile uint16_t special; // Special
} __attribute__((packed)) e1000_tx_desc_t;

// e1000 device structure
typedef struct
{
    volatile uint8_t *mmio_base;    // MMIO base address
    uint8_t mac_addr[6];   // MAC address
    uint32_t rx_ring_size; // Receive ring size
    uint32_t tx_ring_size; // Transmit ring size

    // Receive ring
    e1000_rx_desc_t *rx_descriptors;
    uint8_t *rx_buffers;
    uint32_t rx_cur; // Current receive descriptor

    // Transmit ring
    e1000_tx_desc_t *tx_descriptors;
    uint8_t *tx_buffers;
    uint32_t tx_cur; // Current transmit descriptor

    // Statistics
    uint64_t rx_packets;
    uint64_t tx_packets;
    uint64_t rx_errors;
    uint64_t tx_errors;
} e1000_device_t;

// Control register bits
#define E1000_CTRL_FD 0x00000001        // Full Duplex
#define E1000_CTRL_LRST 0x00000008      // Link Reset
#define E1000_CTRL_ASDE 0x00000020      // Auto-Speed Detection Enable
#define E1000_CTRL_SLU 0x00000040       // Set Link Up
#define E1000_CTRL_ILOS 0x00000080      // Invert Loss-of-Signal
#define E1000_CTRL_SPD_SEL 0x00000300   // Speed Selection
#define E1000_CTRL_SPD_10 0x00000000    // 10 Mbps
#define E1000_CTRL_SPD_100 0x00000100   // 100 Mbps
#define E1000_CTRL_SPD_1000 0x00000200  // 1000 Mbps
#define E1000_CTRL_FRCSPD 0x00000800    // Force Speed
#define E1000_CTRL_FRCDPLX 0x00001000   // Force Duplex
#define E1000_CTRL_SWDPINSel 0x00040000 // Software Defined Pins Select
#define E1000_CTRL_SWDPIN0 0x00080000   // Software Defined Pin 0
#define E1000_CTRL_RST 0x04000000       // Device Reset
#define E1000_CTRL_RFCE 0x08000000      // Receive Flow Control Enable
#define E1000_CTRL_TFCE 0x10000000      // Transmit Flow Control Enable

// Receive Control register bits
#define E1000_RCTL_EN 0x00000002    // Receiver Enable
#define E1000_RCTL_SBP 0x00000004   // Store Bad Packets
#define E1000_RCTL_UPE 0x00000008   // Unicast Promiscuous Enabled
#define E1000_RCTL_MPE 0x00000010   // Multicast Promiscuous Enabled
#define E1000_RCTL_LPE 0x00000020   // Long Packet Reception Enable
#define E1000_RCTL_LBM 0x000000C0   // Loopback Mode
#define E1000_RCTL_RDMTS 0x00000300 // Receive Descriptor Minimum Threshold Size
#define E1000_RCTL_MO 0x00003000    // Multicast Offset
#define E1000_RCTL_BAM 0x00008000   // Broadcast Accept Mode
#define E1000_RCTL_BSIZE 0x00030000 // Receive Buffer Size
#define E1000_RCTL_VFE 0x00040000   // VLAN Filter Enable
#define E1000_RCTL_CFIEN 0x00080000 // Canonical Form Indicator Enable
#define E1000_RCTL_CFI 0x00100000   // Canonical Form Indicator bit value
#define E1000_RCTL_DPF 0x00400000   // Discard Pause Frames
#define E1000_RCTL_PMCF 0x00800000  // Pass MAC Control Frames
#define E1000_RCTL_SECRC 0x04000000 // Strip Ethernet CRC

// Transmit Control register bits
#define E1000_TCTL_EN 0x00000002     // Transmit Enable
#define E1000_TCTL_PSP 0x00000008    // Pad Short Packets
#define E1000_TCTL_CT 0x00000FF0     // Collision Threshold
#define E1000_TCTL_COLD 0x003FF000   // Collision Distance
#define E1000_TCTL_SWXOFF 0x00400000 // Software XOFF Transmission
#define E1000_TCTL_RTLC 0x01000000   // Re-transmit on Late Collision

// Register access functions
static uint32_t e1000_read_reg(e1000_device_t *dev, uint32_t reg)
{
    volatile uint32_t *reg_ptr = (volatile uint32_t *)(dev->mmio_base + reg);
    return *reg_ptr;
}

static void e1000_write_reg(e1000_device_t *dev, uint32_t reg, uint32_t value)
{
    volatile uint32_t *reg_ptr = (volatile uint32_t *)(dev->mmio_base + reg);
    *reg_ptr = value;
}

// EEPROM access functions
static uint16_t e1000_eeprom_read(e1000_device_t *dev, uint8_t addr)
{
    uint32_t tmp = 0;

    // Request EEPROM read
    e1000_write_reg(dev, E1000_EERD, (addr << 8) | 0x1);

    // Wait for completion
    while (((tmp = e1000_read_reg(dev, E1000_EERD)) & 0x10) == 0)
        ;

    return (uint16_t)(tmp >> 16);
}

// Read MAC address from EEPROM
static void e1000_read_mac_addr(e1000_device_t *dev)
{
    uint32_t mac_low = e1000_eeprom_read(dev, 0);
    uint32_t mac_high = e1000_eeprom_read(dev, 1);

    dev->mac_addr[0] = (mac_low >> 0) & 0xFF;
    dev->mac_addr[1] = (mac_low >> 8) & 0xFF;
    dev->mac_addr[2] = (mac_high >> 0) & 0xFF;
    dev->mac_addr[3] = (mac_high >> 8) & 0xFF;

    // For some cards, bytes 4-5 are in word 2
    uint32_t mac_extra = e1000_eeprom_read(dev, 2);
    dev->mac_addr[4] = (mac_extra >> 0) & 0xFF;
    dev->mac_addr[5] = (mac_extra >> 8) & 0xFF;
}

// Initialize receive ring
static int e1000_init_rx_ring(e1000_device_t *dev)
{
    // Allocate receive descriptors
    dev->rx_descriptors = (e1000_rx_desc_t *)kmalloc(dev->rx_ring_size * sizeof(e1000_rx_desc_t));
    if (!dev->rx_descriptors)
        return -1;

    // Allocate receive buffers
    dev->rx_buffers = (uint8_t *)kmalloc(dev->rx_ring_size * 2048);
    if (!dev->rx_buffers)
    {
        kfree(dev->rx_descriptors);
        return -1;
    }

    // Initialize receive descriptors
    for (uint32_t i = 0; i < dev->rx_ring_size; i++)
    {
        dev->rx_descriptors[i].addr = (uint64_t)&dev->rx_buffers[i * 2048];
        dev->rx_descriptors[i].status = 0;
    }

    // Set up receive ring registers
    e1000_write_reg(dev, E1000_RDBAL, (uint32_t)((uint64_t)dev->rx_descriptors & 0xFFFFFFFF));
    e1000_write_reg(dev, E1000_RDBAH, (uint32_t)((uint64_t)dev->rx_descriptors >> 32));
    e1000_write_reg(dev, E1000_RDRLEN, dev->rx_ring_size * sizeof(e1000_rx_desc_t));
    e1000_write_reg(dev, E1000_RDH, 0);
    e1000_write_reg(dev, E1000_RDT, dev->rx_ring_size - 1);

    dev->rx_cur = 0;
    return 0;
}

// Initialize transmit ring
static int e1000_init_tx_ring(e1000_device_t *dev)
{
    // Allocate transmit descriptors
    dev->tx_descriptors = (e1000_tx_desc_t *)kmalloc(dev->tx_ring_size * sizeof(e1000_tx_desc_t));
    if (!dev->tx_descriptors)
        return -1;

    // Allocate transmit buffers
    dev->tx_buffers = (uint8_t *)kmalloc(dev->tx_ring_size * 2048);
    if (!dev->tx_buffers)
    {
        kfree(dev->tx_descriptors);
        return -1;
    }

    // Initialize transmit descriptors
    for (uint32_t i = 0; i < dev->tx_ring_size; i++)
    {
        dev->tx_descriptors[i].addr = (uint64_t)&dev->tx_buffers[i * 2048];
        dev->tx_descriptors[i].cmd = 0;
        dev->tx_descriptors[i].status = 1; // Descriptor done
    }

    // Set up transmit ring registers
    e1000_write_reg(dev, E1000_TDBAL, (uint32_t)((uint64_t)dev->tx_descriptors & 0xFFFFFFFF));
    e1000_write_reg(dev, E1000_TDBAH, (uint32_t)((uint64_t)dev->tx_descriptors >> 32));
    e1000_write_reg(dev, E1000_TDLEN, dev->tx_ring_size * sizeof(e1000_tx_desc_t));
    e1000_write_reg(dev, E1000_TDH, 0);
    e1000_write_reg(dev, E1000_TDT, 0);

    dev->tx_cur = 0;
    return 0;
}

// Reset e1000 device
static void e1000_reset(e1000_device_t *dev)
{
    // Issue device reset
    e1000_write_reg(dev, E1000_CTRL, E1000_CTRL_RST);

    // Wait for reset to complete
    uint32_t timeout = 1000000;
    while ((e1000_read_reg(dev, E1000_CTRL) & E1000_CTRL_RST) && timeout--)
        ;

    // Clear interrupts
    e1000_write_reg(dev, E1000_IMC, 0xFFFFFFFF);
}

// Initialize e1000 device
static int e1000_init_device(e1000_device_t *dev)
{
    // Reset device
    e1000_reset(dev);

    // Read MAC address
    e1000_read_mac_addr(dev);

    // Initialize rings
    dev->rx_ring_size = 32;
    dev->tx_ring_size = 32;

    if (e1000_init_rx_ring(dev) != 0)
    {
        kprintf("e1000: Failed to initialize RX ring\n");
        return -1;
    }

    if (e1000_init_tx_ring(dev) != 0)
    {
        kprintf("e1000: Failed to initialize TX ring\n");
        kfree(dev->rx_descriptors);
        kfree(dev->rx_buffers);
        return -1;
    }

    // Configure receive control
    e1000_write_reg(dev, E1000_RCTL, E1000_RCTL_EN | E1000_RCTL_BAM);

    // Configure transmit control
    e1000_write_reg(dev, E1000_TCTL, E1000_TCTL_EN | E1000_TCTL_PSP);

    // Configure inter-packet gap
    e1000_write_reg(dev, E1000_TIPG, 0x0060200A); // IPGT=10, IPGR1=8, IPGR2=6

    // Set MAC address
    e1000_write_reg(dev, E1000_RAL, (dev->mac_addr[3] << 24) | (dev->mac_addr[2] << 16) | (dev->mac_addr[1] << 8) | dev->mac_addr[0]);
    e1000_write_reg(dev, E1000_RAH, (dev->mac_addr[5] << 8) | dev->mac_addr[4] | 0x80000000);

    // Enable interrupts
    e1000_write_reg(dev, E1000_IMS, 0x1F6DC); // Enable all interrupts
    e1000_write_reg(dev, E1000_ITR, 0);       // Disable interrupt throttling

    kprintf("e1000: Initialized device with MAC %02x:%02x:%02x:%02x:%02x:%02x\n",
            dev->mac_addr[0], dev->mac_addr[1], dev->mac_addr[2],
            dev->mac_addr[3], dev->mac_addr[4], dev->mac_addr[5]);

    return 0;
}

// Send packet
static int e1000_send_packet(net_interface_t *iface, net_packet_t *packet)
{
    e1000_device_t *dev = (e1000_device_t *)iface->private_data;

    if (packet->size > 1514)
        return -1; // Too large

    uint32_t next_tx = dev->tx_cur;
    e1000_tx_desc_t *desc = &dev->tx_descriptors[next_tx];

    // Wait for descriptor to be free
    uint32_t timeout = 100000;
    while ((desc->status & 0x1) == 0 && timeout--)
        ;

    if (timeout == 0)
        return -1; // Timeout

    // Copy packet data to transmit buffer
    uint8_t *tx_buf = &dev->tx_buffers[next_tx * 2048];
    memcpy(tx_buf, packet->data, packet->size);

    // Update descriptor
    desc->length = packet->size;
    desc->cmd = 0x9; // End of Packet | Report Status
    desc->status = 0;

    // Update tail pointer
    e1000_write_reg(dev, E1000_TDT, next_tx);

    dev->tx_cur = (next_tx + 1) % dev->tx_ring_size;
    dev->tx_packets++;

    return 0;
}

// Receive packet
static void e1000_receive_packet(net_interface_t *iface)
{
    e1000_device_t *dev = (e1000_device_t *)iface->private_data;

    while (1)
    {
        e1000_rx_desc_t *desc = &dev->rx_descriptors[dev->rx_cur];

        if ((desc->status & 0x1) == 0)
            break; // No packet available

        uint32_t packet_size = desc->length;

        if (packet_size > 0)
        {
            // Allocate packet and copy data
            net_packet_t *packet = net_alloc_packet(packet_size);
            if (packet)
            {
                uint8_t *rx_buf = &dev->rx_buffers[dev->rx_cur * 2048];
                memcpy(packet->data, rx_buf, packet_size);
                packet->size = packet_size;

                // Process packet
                net_receive_packet(iface, packet);
            }
        }

        // Clear descriptor status
        desc->status = 0;

        dev->rx_cur = (dev->rx_cur + 1) % dev->rx_ring_size;
        dev->rx_packets++;
    }
}

// PCI probe function
static int e1000_probe(pci_device_t *pci_dev)
{
    if (!pci_dev)
        return -1;

    // Check if this is an e1000 device
    if (pci_dev->vendor_id != 0x8086)
        return -1; // Not Intel

    // Check device IDs for e1000 variants
    uint16_t device_id = pci_dev->device_id;
    if (device_id != 0x100E && device_id != 0x100F && device_id != 0x1011 &&
        device_id != 0x1010 && device_id != 0x1012 && device_id != 0x101D)
    {
        return -1; // Not an e1000 variant
    }

    kprintf("e1000: Found device %04x:%04x\n", pci_dev->vendor_id, pci_dev->device_id);

    // Allocate device structure
    e1000_device_t *dev = (e1000_device_t *)kmalloc(sizeof(e1000_device_t));
    if (!dev)
        return -1;

    // Get MMIO base address
    dev->mmio_base = (volatile uint8_t *)((uintptr_t)pci_get_bar_address(pci_dev, 0));
    if (dev->mmio_base == 0)
    {
        kfree(dev);
        return -1;
    }

    // Initialize device
    if (e1000_init_device(dev) != 0)
    {
        kfree(dev);
        return -1;
    }

    // Create network interface
    net_interface_t *iface = (net_interface_t *)kmalloc(sizeof(net_interface_t));
    if (!iface)
    {
        // Cleanup would be needed here
        kfree(dev);
        return -1;
    }

    strcpy(iface->name, "eth0");
    memcpy(iface->mac_addr, dev->mac_addr, 6);
    iface->up = true;
    iface->send = e1000_send_packet;
    iface->private_data = dev;

    // Register interface
    if (net_register_interface(iface) != 0)
    {
        kfree(iface);
        kfree(dev);
        return -1;
    }

    return 0;
}

// Initialize e1000 driver
int e1000_init(void)
{
    kprintf("e1000: Initializing Intel e1000 driver...\n");

    // Probe for e1000 devices
    // In a real implementation, this would scan PCI bus
    // For now, we'll assume we found one and create it manually

    pci_device_t dummy_pci = {
        .vendor_id = 0x8086,
        .device_id = 0x100E,
        .bus = 0,
        .slot = 0,
        .function = 0};

    return e1000_probe(&dummy_pci);
}
