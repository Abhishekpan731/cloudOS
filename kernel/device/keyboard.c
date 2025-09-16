#include "kernel/device.h"
#include "kernel/kernel.h"
#include "kernel/hal.h"

#define KEYBOARD_DATA_PORT    0x60
#define KEYBOARD_STATUS_PORT  0x64
#define KEYBOARD_CMD_PORT     0x64

static char keyboard_buffer[256];
static uint8_t buffer_head = 0;
static uint8_t buffer_tail = 0;

static const char scancode_to_ascii[] = {
    0,  27, '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '-', '=', '\b',
    '\t', 'q', 'w', 'e', 'r', 't', 'y', 'u', 'i', 'o', 'p', '[', ']', '\n',
    0, 'a', 's', 'd', 'f', 'g', 'h', 'j', 'k', 'l', ';', '\'', '`',
    0, '\\', 'z', 'x', 'c', 'v', 'b', 'n', 'm', ',', '.', '/', 0,
    '*', 0, ' ', 0
};

static int keyboard_open(device_t* dev);
static int keyboard_close(device_t* dev);
static ssize_t keyboard_read(device_t* dev, void* buffer, size_t count, off_t offset);
static ssize_t keyboard_write(device_t* dev, const void* buffer, size_t count, off_t offset);
static int keyboard_ioctl(device_t* dev, unsigned int cmd, unsigned long arg);

static device_ops_t keyboard_ops = {
    .open = keyboard_open,
    .close = keyboard_close,
    .read = keyboard_read,
    .write = keyboard_write,
    .ioctl = keyboard_ioctl
};

device_t keyboard_device = {
    .major = DEVICE_MAJOR_KEYBOARD,
    .minor = 0,
    .name = "keyboard",
    .type = DEVICE_TYPE_CHAR,
    .ops = &keyboard_ops,
    .private_data = NULL,
    .flags = 0,
    .ref_count = 0,
    .next = NULL
};

static void keyboard_add_to_buffer(char c) {
    uint8_t next_head = (buffer_head + 1) % 256;
    if (next_head != buffer_tail) {
        keyboard_buffer[buffer_head] = c;
        buffer_head = next_head;
    }
}

void keyboard_interrupt_handler(void) {
    uint8_t scancode = hal_inb(KEYBOARD_DATA_PORT);

    // Only handle key press events (bit 7 clear)
    if (!(scancode & 0x80)) {
        if (scancode < sizeof(scancode_to_ascii)) {
            char c = scancode_to_ascii[scancode];
            if (c != 0) {
                keyboard_add_to_buffer(c);
            }
        }
    }
}

int keyboard_init(void) {
    // Initialize keyboard controller
#ifdef __x86_64__
    // Enable keyboard
    hal_outb(KEYBOARD_CMD_PORT, 0xAE);

    // Set scan code set 1
    hal_outb(KEYBOARD_DATA_PORT, 0xF0);
    hal_outb(KEYBOARD_DATA_PORT, 0x01);
#endif

    return device_register(&keyboard_device);
}

static int keyboard_open(device_t* dev) {
    (void)dev;
    return 0;
}

static int keyboard_close(device_t* dev) {
    (void)dev;
    return 0;
}

static ssize_t keyboard_read(device_t* dev, void* buffer, size_t count, off_t offset) {
    (void)dev;
    (void)offset;

    char* buf = (char*)buffer;
    size_t read_count = 0;

    while (read_count < count && buffer_tail != buffer_head) {
        buf[read_count] = keyboard_buffer[buffer_tail];
        buffer_tail = (buffer_tail + 1) % 256;
        read_count++;
    }

    return read_count;
}

static ssize_t keyboard_write(device_t* dev, const void* buffer, size_t count, off_t offset) {
    (void)dev;
    (void)buffer;
    (void)count;
    (void)offset;
    return -1; // Keyboard is read-only
}

static int keyboard_ioctl(device_t* dev, unsigned int cmd, unsigned long arg) {
    (void)dev;
    (void)cmd;
    (void)arg;
    return -1; // Not implemented
}
