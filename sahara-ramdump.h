/*
    Copyright 2023 Quectel Wireless Solutions Co.,Ltd

    Licensed under the Apache License, Version 2.0 (the "License");
    you may not use this file except in compliance with the License.
    You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

    Unless required by applicable law or agreed to in writing, software
    distributed under the License is distributed on an "AS IS" BASIS,
    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
    See the License for the specific language governing permissions and
    limitations under the License.
*/

#ifndef __SAHARA_RAMDUMP_H__
#define __SAHARA_RAMDUMP_H__
#define _GNU_SOURCE
#include <linux/usbdevice_fs.h>
#include <linux/usb/ch9.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <assert.h>
#include <ctype.h>
#include <dirent.h>
#include <err.h>
#include <getopt.h>
#include <libudev.h>
#include <poll.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stddef.h>
#include <errno.h>
#include <fcntl.h>

#define QUEC_SAHARA_MAX_COMMAND_ID 0x21
#define QUEC_SAHARA_HEADER_LEN 8 
#define QUEC_MAX_RAW_BUFFER_SIZE (32*1024)
#define QUEC_MISC_BUFFER_SIZE 2048

#define MAX_RETRY_COUNT 3

#define dbg(fmt, arg...)                                  \
    do                                                    \
    {                                                     \
        char log_buff[512];                               \
        snprintf(log_buff, sizeof(log_buff), fmt, ##arg); \
        printf("%s\n", log_buff);                         \
    } while (0)
#ifndef MIN
#define MIN(a, b) ((a) < (b) ? (a) : (b))
#endif

#define QUECTEL_DLOAD_DEBUG_STRLEN_BYTES 20

struct dload_debug_type
{
    uint32_t save_pref;
    uint32_t mem_base;
    uint32_t length;
    char     desc[20];
    char     filename[QUECTEL_DLOAD_DEBUG_STRLEN_BYTES];
};

struct dload_debug_type_64bit
{
    uint64_t save_pref;
    uint64_t mem_base;
    uint64_t length;
    char desc[QUECTEL_DLOAD_DEBUG_STRLEN_BYTES];
    char filename[QUECTEL_DLOAD_DEBUG_STRLEN_BYTES];
};

struct packet_memory_read_64bit_type
{
    uint64_t memory_addr;
    uint64_t memory_length;
};  

struct packet_memory_read_type
{
    uint32_t memory_addr;
    uint32_t memory_length;
};

struct sahara_pkt
{
    uint32_t cmd;
    uint32_t length;

    union
    {
        struct
        {
            uint32_t version;
            uint32_t compatible;
            uint32_t max_len;
            uint32_t mode;
        } hello_req;
        struct
        {
            uint32_t version;
            uint32_t compatible;
            uint32_t status;
            uint32_t mode;
            uint32_t reserved0;         // reserved field
            uint32_t reserved1;         // reserved field
            uint32_t reserved2;         // reserved field
            uint32_t reserved3;         // reserved field
            uint32_t reserved4;         // reserved field
            uint32_t reserved5;         // reserved field

        } hello_resp;
        struct
        {
            uint32_t image;
            uint32_t offset;
            uint32_t length;
        } read_req;
        struct
        {
            uint32_t image;
            uint32_t status;
        } eoi;
        struct
        {
        } done_req;
        struct
        {
            uint32_t status;
        } done_resp;
        struct
        {
            uint64_t image;
            uint64_t offset;
            uint64_t length;
        } read64_req;
        struct
        {
            uint32_t image_id; /* ID of image to be transferred */
            uint32_t end_flag; /* offset into image file to read data from */
            uint32_t successful;
        } packet_fw_update_end;
        struct
        {
            uint32_t image_id;    /* ID of image to be transferred */
            uint32_t data_offset; /* offset into image file to read data from */
            uint32_t data_length; /* length of data segment to be retreived */
            uint32_t percent;
        } packet_fw_update_process_report;
        struct
        {
            uint32_t memory_table_addr;
            uint32_t memory_table_length;
        } packet_memory_debug;
        struct
        {
            uint64_t memory_table_addr;
            uint64_t memory_table_length;
        } packet_memory_debug_64bit;
        struct packet_memory_read_type packet_memory_read;
        struct packet_memory_read_64bit_type packet_memory_read_64bit;
        struct dload_debug_type dload_debug;   
        struct dload_debug_type_64bit dload_debug_64bit;
    };
};

extern uint32_t qlog_le32(uint32_t v32);
extern uint64_t qlog_le64(uint64_t v64);

typedef struct com_port {
    long handle;
    bool (*write)(long handle, const void *buffer, const size_t bytes_to_send);
    bool (*read) (long handle, void *buffer, size_t bytes_to_read, size_t *bytes_read);

    int rx_timeout;
    size_t MAX_TO_READ;
    size_t MAX_TO_WRITE;
} com_port_t;


/*==========================================================================
DESCRIPTION

  This function is used to download the ramdump files using sahara protocol.
  It is expected that the device is already in memory dump download allowed 
  mode.

PARAMETERS
    path_to_save_files [in]: Path to dump the ramdump files.

    do_reset [in]: If the value is '1', reset will be triggered at the end 
    of ramdump collection.

RETURN VALUE
    True on success, else false.
==========================================================================*/
bool sahara_download_dump(const char *path_to_save_files, int do_reset);

/*==========================================================================
DESCRIPTION

  This function is used deinitialize the memory areas used for downloading
  the dump

PARAMETERS

    None

RETURN VALUE
    None
==========================================================================*/
void sahara_deinit();
#endif
