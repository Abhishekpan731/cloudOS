#ifndef KERNEL_TYPES_H
#define KERNEL_TYPES_H

typedef unsigned char      uint8_t;
typedef unsigned short     uint16_t;
typedef unsigned int       uint32_t;
typedef unsigned long long uint64_t;

typedef signed char      int8_t;
typedef signed short     int16_t;
typedef signed int       int32_t;
typedef signed long long int64_t;

typedef uint64_t size_t;
typedef int64_t  ssize_t;
typedef uint64_t uintptr_t;
typedef int64_t  intptr_t;
typedef int64_t  off_t;

typedef uint8_t  bool;
#define true  1
#define false 0

#define NULL ((void*)0)

// File status structure
struct stat {
    uint64_t st_dev;      // Device ID
    uint64_t st_ino;      // Inode number
    uint32_t st_mode;     // File mode
    uint32_t st_nlink;    // Number of hard links
    uint32_t st_uid;      // User ID
    uint32_t st_gid;      // Group ID
    uint64_t st_size;     // File size in bytes
    uint64_t st_atime;    // Access time
    uint64_t st_mtime;    // Modification time
    uint64_t st_ctime;    // Creation time
    uint32_t st_blksize;  // Block size
    uint64_t st_blocks;   // Number of blocks
};

// File system statistics structure
struct statvfs {
    unsigned long f_bsize;    // File system block size
    unsigned long f_frsize;   // Fundamental file system block size
    uint64_t f_blocks;        // Total number of blocks on file system
    uint64_t f_bfree;         // Total number of free blocks
    uint64_t f_bavail;        // Number of free blocks available to non-privileged process
    uint64_t f_files;         // Total number of file serial numbers
    uint64_t f_ffree;         // Total number of free file serial numbers
    uint64_t f_favail;        // Number of file serial numbers available to non-privileged process
    unsigned long f_fsid;     // File system ID
    unsigned long f_flag;     // Bit mask of f_flag values
    unsigned long f_namemax;  // Maximum filename length
};

#endif
