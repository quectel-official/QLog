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

#include <stdio.h>
#include <ctype.h>
#include <stdlib.h>
#ifndef __QUECTEL_QLOG_H
#define __QUECTEL_QLOG_H
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <termios.h>
#include <time.h>
#include <signal.h>
#include <assert.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <poll.h>
#include <netinet/in.h>
#include <pthread.h>
#include <dirent.h>
#include <sys/ioctl.h>
#include <linux/version.h>
#include <stdbool.h>
#if LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 20)
#include <linux/usb/ch9.h>
#else
#include <linux/usb_ch9.h>
#endif
#include <linux/usbdevice_fs.h>

typedef unsigned int uint32_t;
#define TFTP_F "tftp:"
#define FTP_F "ftp:"

#ifndef MIN
#define MIN(a, b) ((a) < (b) ? (a) : (b))
#endif

typedef struct
{
    int (*init_filter)(int fd, const char *conf, int built_in_filter_index);
    int (*clean_filter)(int fd);
    int (*logfile_create)(const char *logfile_dir, const char *logfile_suffix, unsigned logfile_seq);
    int (*logfile_init)(int logfd, unsigned logfile_seq);
    size_t (*logfile_save)(int logfd, const void *buf, size_t size);
    int (*logfile_close)(int logfd);
} qlog_ops_t;

extern qlog_ops_t mdm_qlog_ops;
extern qlog_ops_t tty2tcp_qlog_ops;
extern qlog_ops_t tcp_client_qlog_ops;
extern int g_is_qualcomm_chip;
extern int g_qualcomm_log_type;
extern int g_is_usb_disconnect;
extern int g_donot_split_logfile;
extern int use_qmdl2_v2;
extern int use_diag_qdss;
extern int use_diag_dpl;
extern int tty2tcp_sockfd;
extern unsigned g_rx_log_count;
extern unsigned qlog_exit_requested;
extern const char *g_tftp_server_ip;
extern const char *g_ftp_server_ip;
extern const char *g_ftp_server_usr;
extern const char *g_ftp_server_pass;
extern ssize_t mdm_send_cmd(int fd, const unsigned char *buf, ssize_t size, int sync);
extern int qlog_create_file_in_logdir(const char *filename);
extern size_t qlog_get_filesize_in_logidr(const char *filename);

extern uint16_t qlog_le16(uint16_t v16);
extern uint32_t qlog_le32(uint32_t v32);
extern uint64_t qlog_le64(uint64_t v64);
extern ssize_t qlog_poll_write(int fd, const void *buf, size_t size, unsigned timeout_mesc);
extern ssize_t qlog_poll_read(int fd, void *pbuf, size_t size, unsigned timeout_msec);
extern int qlog_logfile_create_fullname(int file_type, const char *fullname, long tftp_size, int is_dump);
extern size_t qlog_logfile_save(int logfd, const void *buf, size_t size);
extern int qlog_logfile_close(int logfd);
extern int qlog_logfile_close_qdb(int logfd);
extern int tftp_test_server(const char *serv_ip);
extern int tftp_write_request(const char *filename, long size);
extern int ftp_test_server(const char *ftp_server, const char *user, const char *pass);
extern int ftp_write_request(int index, const char *ftp_server, const char *user, const char *pass, const char *filename);

extern unsigned qlog_msecs(void);
extern int qlog_avail_space_for_dump(const char *dir, long need_MB);

extern bool sahara_download_dump(const char *path_to_save_files, int do_reset);
extern void sahara_deinit();
extern bool sahara_init_xprt_ext(long handle,
    bool (*port_write)(long, const void *, const size_t),
    bool (*port_read) (long, void *, size_t, size_t *)
);

bool sahara_init_xprt(long fd);

#define qlog_raw_log(fmt, arg...)                                      \
    do                                                                 \
    {                                                                  \
        unsigned msec = qlog_msecs();                                  \
        printf("\r[%03u.%03u] " fmt, msec / 1000, msec % 1000, ##arg); \
        fflush(stdout);                                                \
    } while (0)
#define qlog_dbg(fmt, arg...)                                        \
    do                                                               \
    {                                                                \
        unsigned msec = qlog_msecs();                                \
        printf("[%03u.%03u] " fmt, msec / 1000, msec % 1000, ##arg); \
        fflush(stdout);                                              \
    } while (0)
#define unused_result_write(_fd, _buf, _count) \
    do                                         \
    {                                          \
        if (write(_fd, _buf, _count) == -1)    \
        {                                      \
        }                                      \
    } while (0)
    
struct ql_usb_interface_info
{
    uint8_t bInterfaceNumber;
    uint8_t bInterfaceClass;
    uint8_t bInterfaceSubClass;
    uint8_t bInterfaceProtocol;
    uint8_t bNumEndpoints;
    uint8_t ep_in;
    uint8_t ep_out;
};

enum
{
    MDM_QDSS,
    RG500U_LOG,
    EC200U_AP,
};

struct ql_usb_device_info
{
    int idVendor;
    int idProduct;
    int bNumInterfaces;
    int busnum;
    int devnum;
    int major;
    int minor;
    int bcdDevice;
    int hardware; // 0 ~ usb, 'p' ~ pcie

    int dm_major;
    int dm_minor;
    char devname[32];
    char usbdevice_pah[256];
    char ttyDM[32];
    char ttyGENERAL[32]; // for all
    char ttyTHIRD[32];   // for dpl

    struct ql_usb_interface_info dm_intf;
    struct ql_usb_interface_info general_intf;
    struct ql_usb_interface_info third_intf;
    int general_type;
    int third_type;

    char is_dump;
};

#define QLOG_BUF_SIZE (64 * 1024) // TTYB_DEFAULT_MEM_LIMIT 65536 -> (640 * 1024UL) 7ab57b76ebf632bf2231ccabe26bea33868118c6
#define MAX_USB_DEV 8
extern struct ql_usb_device_info s_usb_device_info[];

extern int ql_match_dm_device(const char *devname, struct ql_usb_device_info *ql_dev);
extern int ql_find_quectel_modules(void);
extern int ql_usbfs_open_interface(const struct ql_usb_device_info *usb_dev, int intf);
extern int ql_usbfs_read(int usbfd, int ep_in, void *pbuf, unsigned len);
extern int ql_usbfs_write(int usbfd, int ep_out, const void *pbuf, unsigned len);

extern size_t kfifo_write(int idx, const void *buf, size_t size);
extern void kfifo_free(int idx);
extern int kfifo_alloc(int fd);
extern int kfifo_idx(int fd);
extern void ftp_quit(void);
extern int m_bVer_Obtained_change(void);
extern int qlog_com_catch_log(char *ttyDM, char *logdir, int logfile_sz, const char *(*qlog_time_name)(int));
extern void mdm_reset_global_variables(void);
#endif
