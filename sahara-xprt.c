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

#include "sahara-xprt.h"
#include <inttypes.h>
#include <pthread.h>

static com_port_t com_port = {
    -1, // handle
    NULL, // write
    NULL, // read

    5, // rx_timeout
    1024 * 64,
    1024 * 64,

};

const char *boot_sahara_cmd_id_str[QUEC_SAHARA_MAX_COMMAND_ID+1] = {
        "SAHARA_NO_CMD_ID",               // = 0x00,
        "SAHARA_HELLO_ID",                // = 0x01, // sent from target to host
        "SAHARA_HELLO_RESP_ID",           // = 0x02, // sent from host to target
        "SAHARA_READ_DATA_ID",            // = 0x03, // sent from target to host
        "SAHARA_END_IMAGE_TX_ID",         // = 0x04, // sent from target to host
        "SAHARA_DONE_ID",                 // = 0x05, // sent from host to target
        "SAHARA_DONE_RESP_ID",            // = 0x06, // sent from target to host
        "SAHARA_RESET_ID",                // = 0x07, // sent from host to target
        "SAHARA_RESET_RESP_ID",           // = 0x08, // sent from target to host
        "SAHARA_MEMORY_DEBUG_ID",         // = 0x09, // sent from target to host
        "SAHARA_MEMORY_READ_ID",          // = 0x0A, // sent from host to target
        "SAHARA_CMD_READY_ID",            // = 0x0B, // sent from target to host
        "SAHARA_CMD_SWITCH_MODE_ID",      // = 0x0C, // sent from host to target
        "SAHARA_CMD_EXEC_ID",             // = 0x0D, // sent from host to target
        "SAHARA_CMD_EXEC_RESP_ID",        // = 0x0E, // sent from target to host
        "SAHARA_CMD_EXEC_DATA_ID",        // = 0x0F, // sent from host to target
        "SAHARA_64_BITS_MEMORY_DEBUG_ID", // = 0x10, // sent from target to host
        "SAHARA_64_BITS_MEMORY_READ_ID",  // = 0x11, // sent from host to target
        "SAHARA_64_BITS_READ_DATA_ID",    // = 0x12,
        "NOP",                            // = 0x13,
        "NOP",
        "NOP",
        "NOP",
        "NOP",
        "NOP",
        "NOP",
        "NOP",
        "NOP",
        "NOP",
        "NOP",
        "NOP",
        "NOP",
        "QUEC_SAHARA_FW_UPDATE_PROCESS_REPORT_ID",
        "QUEC_SAHARA_FW_UPDATE_END_ID"
};

static uint8_t to_hex(uint8_t ch)
{
    ch &= 0xf;
    return ch <= 9 ? '0' + ch : 'a' + ch - 10;
}

static void print_hex_dump(const char *prefix, const void *buf, size_t len)
{
    const uint8_t *ptr = buf;
    size_t linelen;
    uint8_t ch;
    char line[16 * 3 + 16 + 1];
    int li;
    size_t i;
    size_t j;

    for (i = 0; i < len; i += 16)
    {
        linelen = MIN(16, len - i);
        li = 0;

        for (j = 0; j < linelen; j++)
        {
            ch = ptr[i + j];
            line[li++] = to_hex(ch >> 4);
            line[li++] = to_hex(ch);
            line[li++] = ' ';
        }

        for (; j < 16; j++)
        {
            line[li++] = ' ';
            line[li++] = ' ';
            line[li++] = ' ';
        }

        for (j = 0; j < linelen; j++)
        {
            ch = ptr[i + j];
            line[li++] = isprint(ch) ? ch : '.';
        }

        line[li] = '\0';

        printf("%s %04zx: %s\n", prefix, i, line);
    }
}


static bool __port_tx_data (int fd, const void *buffer, const size_t bytes_to_send)
{
    int temp_bytes_sent;
    size_t bytes_sent = 0;

    while (bytes_sent < bytes_to_send)
    {
        int retry_count = MAX_RETRY_COUNT;
		do
        {
			temp_bytes_sent = write (fd, buffer + bytes_sent, MIN(bytes_to_send - bytes_sent, com_port.MAX_TO_WRITE));
			if (-1 == temp_bytes_sent && (errno == EINTR || errno == EAGAIN))
            {
                retry_count--;
				sleep(1);
			}
            else
            {
				break;
			}
		} while(retry_count >= 0);
        
        if (temp_bytes_sent <= 0)
        {
            dbg("Write returned failure %d, errno %d, System error code: %s", temp_bytes_sent, errno, strerror (errno));
            return false;
        }
        else
        {
            bytes_sent += temp_bytes_sent;
        }
    }

    return true;
}

static bool port_tx_data (long fd, const void *buffer, const size_t bytes_to_send)
{
    return __port_tx_data (fd, buffer, bytes_to_send);
}

static bool __port_rx_data(int fd, void *buffer, size_t bytes_to_read, size_t *bytes_read)
{
    fd_set rfds;
    struct timeval tv;
    int retval = 0;
    // time out initializtion.
    tv.tv_sec  = com_port.rx_timeout >= 0 ? com_port.rx_timeout : 0;
    tv.tv_usec = 0;

    // Init read file descriptor
    FD_ZERO (&rfds);
    FD_SET (fd, &rfds);

    retval = select(fd + 1, &rfds, NULL, NULL, ((com_port.rx_timeout >= 0) ? (&tv) : (NULL)));    
    if (retval < 0)
    {
        dbg("select returned error: %d %s, fd: %d", retval, strerror (errno), fd);
        return false;
    }
    else if (retval == 0)
    {
        dbg("select api timed out.");
        return false;  
    } 

    retval = read (fd, buffer, MIN(bytes_to_read, com_port.MAX_TO_READ));
    if (retval <= 0) {
        dbg("Read/Write File descriptor returned error: %s, error code %d", strerror (errno), retval);
        return false;
    }

    if (NULL != bytes_read)
        *bytes_read = retval;
    
    return true;
}

static bool port_rx_data(long fd, void *buffer, size_t bytes_to_read, size_t *bytes_read)
{
    return __port_rx_data(fd, buffer, bytes_to_read, bytes_read);
}

bool sahara_rx_blockdata(void *buffer, size_t bytes_to_read)
{
    size_t temp_bytes_read = 0, bytes_read = 0;

    while (bytes_read < bytes_to_read)
    {
        if (false == com_port.read(com_port.handle, buffer + bytes_read, bytes_to_read - bytes_read, &temp_bytes_read))
        {
            dbg("Failed to read complete bytes. bytes_read = %zd, bytes_to_read = %zd", bytes_read, bytes_to_read);
            return false;
        }
        else
        {
            bytes_read += temp_bytes_read;
        }
    }
    return true;
}

bool sahara_rx_data(struct sahara_pkt *pkt)
{
    if(!pkt)
    {
        dbg("Memory not allocated for read buffer.");
        return false;
    }

    size_t bytes_read = 0;

    memset(pkt, 0x00, sizeof(struct sahara_pkt));

    void *sahara_pkt_header = (void *)pkt;
    void *sahara_pkt_body = ((void *)pkt) + QUEC_SAHARA_HEADER_LEN;    
        
   
    //receive header first     
    if (false == com_port.read(com_port.handle, sahara_pkt_header, QUEC_SAHARA_HEADER_LEN, &bytes_read))
    {
        dbg("Failed to read data");
        return false;
    }
        
    //Check we received all packets or not
    if (bytes_read != QUEC_SAHARA_HEADER_LEN)
    {
        dbg("Failed to read complete bytes. Only read upto %zd bytes", bytes_read);
        return false;
    }     

    if (qlog_le32(pkt->cmd) < QUEC_SAHARA_MAX_COMMAND_ID)
    {
        print_hex_dump("<-- SAHARA PKT", pkt, QUEC_SAHARA_HEADER_LEN);
        dbg("RECEIVED <-- %s", boot_sahara_cmd_id_str[qlog_le32(pkt->cmd)]);

        //Calculate the length of data packet.
        int data_len = qlog_le32(pkt->length) - QUEC_SAHARA_HEADER_LEN;

        if(0 == data_len)
            return true;

        //Receive remaining bytes in the sahara packet.
        if (false == com_port.read(com_port.handle, sahara_pkt_body, data_len, &bytes_read)) 
        {
            dbg("Failed to read data");
            return false;
        }

        //Check we received all packets or not
        if (bytes_read != data_len)
        {
            dbg("Failed to read complete bytes. Only read upto %zd bytes", bytes_read + QUEC_SAHARA_HEADER_LEN);
            return false;
        }            
    }
    else
    {
        dbg("RECEIVED <-- SAHARA_CMD_UNKONOW_%d", qlog_le32(pkt->cmd));
        return false;
    }
    return true;
}

bool sahara_tx_data (const struct sahara_pkt *pkt)
{
    if(!pkt)
    {
        dbg("Invalid packet found, not sending to modem.");
        return false;
    }

    print_hex_dump("--> SAHARA PKT", pkt, pkt->length);
    return com_port.write(com_port.handle, pkt, pkt->length);
}

bool sahara_init_xprt_ext(long handle,
    bool (*port_write)(long, const void *, const size_t),
    bool (*port_read) (long, void *, size_t bytes_to_read, size_t *)
)
{
    com_port.handle = handle;
    com_port.read = port_read;
    com_port.write = port_write;
    return true;
}

bool sahara_init_xprt(long fd)
{
    com_port.handle = fd;
    com_port.read = port_rx_data;
    com_port.write = port_tx_data;
    return true;
}
