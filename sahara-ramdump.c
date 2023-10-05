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

#include "sahara-ramdump.h"
#include "sahara-xprt.h"
#include <inttypes.h>
#include <pthread.h>
#include <sys/time.h>

const int sahara_hello_id = 0x01;
const int sahara_hello_resp_id = 0x02;
const int sahara_read_data_id = 0x03;
const int sahara_end_image_tx_id = 0x04;
const int sahara_done_id = 0x05;
const int sahara_done_resp_id = 0x06;
const int sahara_reset_id = 0x07;
const int sahara_reset_resp_id = 0x08;
const int sahara_memory_debug_id = 0x09;
const int sahara_memory_read_id = 0x0a;
const int sahara_cmd_ready_id = 0x0b;
const int sahara_cmd_switch_mode_id = 0x0c;
const int sahara_cmd_exec_id = 0x0d;
const int sahara_cmd_exec_resp_id = 0x0e;
const int sahara_cmd_exec_data_id = 0x0f;
const int sahara_64_bits_memory_debug_id = 0x10;
const int sahara_64_bits_memory_read_id = 0x11;
const int sahara_64_bits_read_data_id = 0x12;

const int sahara_state_wait_hello = 0;
const int sahara_state_wait_command = 1;
const int sahara_state_wait_memory_table = 2;
const int sahara_state_wait_memory_region = 3;
const int sahara_state_wait_done_resp = 4;
const int sahara_state_wait_reset_resp = 5;

const int sahara_mode_tx_pending = 0;
const int sahara_mode_tx_complete = 1;
const int sahara_mode_memory_debug = 2;
const int sahara_mode_command =3 ;

const int sahara_status_success = 0;

static bool ram_dump_64bit = false;
static int max_ram_dump_read = QUEC_MAX_RAW_BUFFER_SIZE;
static char *buffer = NULL;
static char *misc_buffer = NULL;

typedef struct
{
    const char *path_to_save_files;
    int verbose;
    int do_reset;
} kickstart_options_t;

static kickstart_options_t kickstart_options = {
    NULL, // path_to_save_files
    1,    // verbose
    1,
};

static void sahara_hello_response(struct sahara_pkt *pkt)
{  
    //Ensure incoming packet is valid.
    assert(pkt->length == 0x30);

    //Create a hello response packet.
    struct sahara_pkt resp;
    resp.cmd = qlog_le32(sahara_hello_resp_id); 
    resp.length = qlog_le32(sizeof(pkt->hello_resp) + QUEC_SAHARA_HEADER_LEN);
    resp.hello_resp.version = pkt->hello_req.version;
    resp.hello_resp.compatible = pkt->hello_req.compatible;
    resp.hello_resp.status = qlog_le32(sahara_status_success);
    resp.hello_resp.mode = pkt->hello_req.mode; 
    resp.hello_resp.reserved0 = qlog_le32(1);
    resp.hello_resp.reserved1 = qlog_le32(2);
    resp.hello_resp.reserved2 = qlog_le32(3);
    resp.hello_resp.reserved3 = qlog_le32(4);
    resp.hello_resp.reserved4 = qlog_le32(5);
    resp.hello_resp.reserved5 = qlog_le32(6);

    //Send the hello response packet to modem.
    dbg("SENDING --> SAHARA_HELLO_RESPONSE");
    sahara_tx_data(&resp);
    return;
}

static bool is_valid_memory_table(uint64_t memory_table_size)
{
    if (true == ram_dump_64bit && memory_table_size % sizeof(struct dload_debug_type) == 0)
    {
        return true;
    }
    else if (false == ram_dump_64bit && memory_table_size % sizeof(struct dload_debug_type) == 0)
    {
        return true;
    }
    else
    {
        return false;
    }
}

static bool send_memory_read_packet(struct sahara_pkt *ppkt, uint64_t memory_table_address, uint64_t memory_table_length)
{
    // dbg("SENDING -->  SAHARA_MEMORY_READ, address 0x%08"PRIX64", length 0x%08"PRIX64, memory_table_address, memory_table_length);

    if (true == ram_dump_64bit)
    {
        ppkt->cmd = qlog_le32(sahara_64_bits_memory_read_id);
        ppkt->length = qlog_le32(sizeof(struct packet_memory_read_64bit_type) + QUEC_SAHARA_HEADER_LEN);
        ppkt->packet_memory_read_64bit.memory_addr = qlog_le64(memory_table_address);
        ppkt->packet_memory_read_64bit.memory_length = qlog_le64(memory_table_length);        
    }
    else
    {
        ppkt->cmd = qlog_le32(sahara_memory_read_id);
        ppkt->length = qlog_le32(sizeof(struct packet_memory_read_type) + QUEC_SAHARA_HEADER_LEN);
        ppkt->packet_memory_read.memory_addr = qlog_le32((uint32_t)memory_table_address);
        ppkt->packet_memory_read.memory_length = qlog_le32((uint32_t)memory_table_length);
    }

    /* Send the Memory Read packet */
    if (false == sahara_tx_data(ppkt))
    {
        dbg("Sending MEMORY_READ packet failed");
        return false;
    }

    return true;
}

static int timeval_subtract(struct timeval *result, struct timeval *x, struct timeval *y)
{
    // Perform the carry for the later subtraction by updating y.
    if (x->tv_usec < y->tv_usec)
    {
        int nsec = (y->tv_usec - x->tv_usec) / 1000000 + 1;
        y->tv_usec -= 1000000 * nsec;
        y->tv_sec += nsec;
    }
    if (x->tv_usec - y->tv_usec > 1000000)
    {
        int nsec = (x->tv_usec - y->tv_usec) / 1000000;
        y->tv_usec += 1000000 * nsec;
        y->tv_sec -= nsec;
    }

    // Compute the time remaining to wait. tv_usec is certainly positive. */
    result->tv_sec = x->tv_sec - y->tv_sec;
    result->tv_usec = x->tv_usec - y->tv_usec;

    // Return 1 if result is negative.
    return x->tv_sec < y->tv_sec;
}

static void time_throughput_calculate(struct timeval *start_time, struct timeval *end_time, size_t size_bytes)
{
    struct timeval result;
    double TP = 0.0;

    if (size_bytes == 0)
    {
        dbg( "Cannot calculate throughput, size is 0");
        return;
    }
    timeval_subtract(&result, end_time, start_time);

    TP = (double)result.tv_usec / 1000000.0;
    TP += (double)result.tv_sec;

    if (TP > 0.0 && size_bytes > (1024 * 1024))
    {
        TP = (double)((double)size_bytes / TP) / (1024.0 * 1024.0);
        dbg("%.4f   transferred in %ld.%06ld seconds (%.4fMBps)", (double)size_bytes / 1024 / 1024, result.tv_sec, result.tv_usec, TP);
    }
    else
        dbg("%zd bytes transferred in %ld.%06ld seconds", size_bytes, result.tv_sec, result.tv_usec);
}

static bool send_reset_command()
{
    struct sahara_pkt reset;
    reset.cmd = qlog_le32(sahara_reset_id); 
    reset.length = qlog_le32(QUEC_SAHARA_HEADER_LEN);

    /* Send the Reset Request */
    dbg( "SENDING --> SAHARA_RESET");
    if (false == sahara_tx_data(&reset))
    {
        dbg("Sending RESET packet failed");
        return false;
    }

    return true;
}

void sahara_deinit()
{
    if (buffer)
    {
        free(buffer);
        buffer = NULL;
    }

    if(misc_buffer)
    {
        free(misc_buffer);
        misc_buffer = NULL;
    }
}

bool sahara_download_dump(const char *path_to_save_files, int do_reset)
{
    int i;
    int nBytes = 0;    
    int num_debug_entries = -1;
    int state = sahara_state_wait_hello;
    
    uint64_t memory_table_addr = 0;
    uint64_t memory_table_length = 0;

    kickstart_options.verbose = 1;
    kickstart_options.path_to_save_files = path_to_save_files;
    kickstart_options.do_reset = do_reset;

    struct sahara_pkt pkt;
    struct timeval time_start;
    struct timeval time_end;

    //Create memory for buffer.
    buffer = malloc (QUEC_MAX_RAW_BUFFER_SIZE);
    if(!buffer)
    {
        dbg( "Failed to allocate buffer memory.");  
        return false;
    }
    
    //Create memory for misc buffer.
    misc_buffer = malloc(QUEC_MISC_BUFFER_SIZE);
    if(!misc_buffer)
    {
        dbg( "Failed to allocate misc buffer memory.");  
        return false;
    }
    struct dload_debug_type_64bit *sahara_memory_table = (struct dload_debug_type_64bit *)misc_buffer;     

    while(1)
    {
        //sahara protocol state machine for downloading ramdump from device.
        switch(state)
        {
            case 0://sahara_state_wait_hello: 
                dbg( "STATE <-- SAHARA_WAIT_HELLO");  

                //First try to read sahara hello from the device.
                if(false == sahara_rx_data(&pkt))
                {
                    //Just poking the device if it is not responding.
                    pkt.length = 1;
                    sahara_tx_data(&pkt);
                    //Try to read sahara hello again
                    if(false == sahara_rx_data(&pkt))
                    {
                        dbg("Read Sahara packet failed.\n");
                        return false;
                    }
                }

                //Check if we received hello packet or not.
                if (qlog_le32(pkt.cmd) != 0x01)
                {
                    dbg("Received a different command: %x while waiting for hello packet\n", pkt.cmd);
                    if (false == send_reset_command())
                    {
                        dbg("Failed to send reset command");
                        return false;
                    }
                    return false;
                }

                //Log the received sahara mode of the device.
                int mode = qlog_le32(pkt.hello_req.mode);
                switch (mode) 
                {
                    case 0:
                        dbg("RECEIVED <-- SAHARA_MODE_IMAGE_TX_PENDING");
                        break;
                    case 1:
                        dbg("RECEIVED <-- SAHARA_MODE_IMAGE_TX_COMPLETE");
                        break;
                    case 2:
                        dbg("RECEIVED <-- SAHARA_MODE_MEMORY_DEBUG");
                        break;
                    case 3:
                        dbg("RECEIVED <-- SAHARA_MODE_COMMAND");
                        break;
                    default:
                        dbg("RECEIVED <-- SAHARA_MODE_0x%x", qlog_le32(pkt.hello_req.mode));
                    break;
                }

                //We are excpecting the module should be in memory debug mode.
                //Downloading the ramdump is only in this sahara mode.
                if(pkt.hello_req.mode != sahara_mode_memory_debug)
                {
                    dbg("Unexpected module state: %d", pkt.hello_req.mode);
                    return false;
                }

                //Send sahara hello response.
                sahara_hello_response(&pkt);

                //Change the sahara protocol state of the host
                state = sahara_state_wait_command;
                break;

            case 1://sahara_state_wait_command: 
                dbg( "STATE <-- SAHARA_WAIT_COMMAND");
                
                //Read the next sahara packet from the device.
                if(false == sahara_rx_data(&pkt))
                {
                    dbg("Read Sahara packet failed.\n");
                    return false;
                }

                // Check if the device still in memory debug mode
                if(qlog_le32(pkt.cmd) == sahara_memory_debug_id)
                {
                    dbg( "reading 32 bit memory table address and length.");
                    ram_dump_64bit = false;
                    
                    memory_table_addr = qlog_le32(pkt.packet_memory_debug.memory_table_addr);
                    memory_table_length = qlog_le32(pkt.packet_memory_debug.memory_table_length);                    
                }
                else if (qlog_le32(pkt.cmd) == sahara_64_bits_memory_debug_id )
                {
                    dbg( "reading 64 bit memory table address and length.");
                    ram_dump_64bit = true;

                    dbg( "Using 64 bit RAM dump mode");
                    memory_table_addr = qlog_le64(pkt.packet_memory_debug_64bit.memory_table_addr);
                    memory_table_length = qlog_le64(pkt.packet_memory_debug_64bit.memory_table_length);
                }
                else
                {
                    dbg( "RECEIVED <-- UNKNOWN COMMAND %d", qlog_le32(pkt.cmd));
                    if (qlog_le32(pkt.cmd) == sahara_hello_id)
                    {
                        dbg( "RECEIVED <-- SAHARA_HELLO");
                        continue;
                    }
                    else
                    {
                        //reset the device         
                        if (false == send_reset_command())
                        {
                            dbg("Failed to send reset command");
                            return false;
                        }
                        //Change the sahara protocol state of the host
                        state = sahara_state_wait_reset_resp;
                    }
                    break;
                }

                dbg("Memory Table Address: 0x%08"PRIX64", Memory Table Length: 0x%08"PRIX64, memory_table_addr, memory_table_length);    

                // Check if the received memory address is valid
                if (false == is_valid_memory_table(memory_table_length))
                {
                    dbg("Invalid memory table received");
                    if (false == send_reset_command())
                    {
                        dbg("Failed to send reset command");
                        return false;
                    }

                    //Change the sahara protocol state of the host
                    state = sahara_state_wait_reset_resp;
                    break;
                }

                // Now we are going to read the actual memory content.
                // For that first we need to send a memory read sahara packet and wait for the memory region table from device.
                if (memory_table_length > 0)
                {
                    if (false == send_memory_read_packet(&pkt, memory_table_addr, memory_table_length))
                    {
                        dbg("Invalid memory table received");
                        return false;
                    }

                    if (memory_table_length > QUEC_MAX_RAW_BUFFER_SIZE)
                    {
                        dbg("Memory table length is greater than size of intermediate buffer");
                        return false;
                    }
                }

                //Change the sahara protocol state of the host
                state = sahara_state_wait_memory_table;
                break;
                
            case 2://sahara_state_wait_memory_table: 
                dbg( "STATE <-- SAHARA_WAIT_MEMORY_TABLE");
                
                num_debug_entries = 0;
                //Check if we received valid memory table length.
                if (memory_table_length > 0)
                {
                    memset(buffer, 0 , QUEC_MAX_RAW_BUFFER_SIZE);
                    // Read the memory region table from device into the buffer.
                    if(false == sahara_rx_blockdata(buffer, (int)memory_table_length))
                    {
                        dbg("Read failed. Bytes received \n");
                        return false;
                    }

                    dbg("Memory Debug table received");
                    if(true == ram_dump_64bit)
                    {
                        memcpy(misc_buffer, buffer, (size_t)memory_table_length);
                        num_debug_entries = (int)(memory_table_length / sizeof(struct dload_debug_type_64bit));
                    }
                    else
                    {
                        //Calculate number of files in the received memory table.
                        num_debug_entries = (int)(memory_table_length / sizeof(struct dload_debug_type));
                        if (num_debug_entries * sizeof(struct dload_debug_type_64bit) > QUEC_MAX_RAW_BUFFER_SIZE)
                        {
                            dbg("Length of memory table converted to 64-bit entries is greater than size of intermediate buffer");
                            return false;
                        }

                        // Save the base memory address and length of each memory debug files from the table.
                        struct dload_debug_type *sahara_memory_table_rx = (struct dload_debug_type *)buffer;
                        for (i = 0; i < num_debug_entries; ++i)
                        {
                            sahara_memory_table[i].save_pref = (uint64_t)qlog_le32(sahara_memory_table_rx[i].save_pref);
                            sahara_memory_table[i].mem_base = (uint64_t)qlog_le32(sahara_memory_table_rx[i].mem_base);
                            sahara_memory_table[i].length = (uint64_t)qlog_le32(sahara_memory_table_rx[i].length);
                            strncpy(sahara_memory_table[i].filename, sahara_memory_table_rx[i].filename, QUECTEL_DLOAD_DEBUG_STRLEN_BYTES - 1);
                            strncpy(sahara_memory_table[i].desc, sahara_memory_table_rx[i].desc, QUECTEL_DLOAD_DEBUG_STRLEN_BYTES - 1);
                        } // end for (i = 0; i < num_debug_entries; ++i)
                    }
                }

                for (i = 0; i < num_debug_entries; i++)
                {
                    dbg("Base 0x%08"PRIX64" Len 0x%08"PRIX64", '%s', '%s'", 
                        sahara_memory_table[i].mem_base, 
                        sahara_memory_table[i].length, 
                        sahara_memory_table[i].filename, 
                        sahara_memory_table[i].desc);
                }
                state = sahara_state_wait_memory_region;
                break;

            case 3://sahara_state_wait_memory_region:
                dbg( "STATE <-- SAHARA_WAIT_MEMORY_REGION");

                //Loop through the memory region table which received th last sahara packet and 
                //download  raw buffer for all table enties(ramdump files).
                for (i = 0; i < num_debug_entries; i++)
                {
                    uint64_t cur = 0;
                    int fd = -1;
                    char full_filename[255] = {0};
                    
                    // Generate the output file name.
                    if (kickstart_options.path_to_save_files)
                    {
                        snprintf(full_filename,
                                 sizeof(full_filename),
                                 "%s/%s",
                                 kickstart_options.path_to_save_files,
                                 sahara_memory_table[i].filename);
                    }
                    else 
                    {
                        snprintf(full_filename,
                                 sizeof(full_filename),
                                 "%s",
                                 sahara_memory_table[i].filename);
                    }

                    // Open the file in disk to dump the buffer
                    fd = open(full_filename, O_CREAT | O_WRONLY | O_TRUNC, 0444);
                    if (fd == -1)
                    {
                        dbg("ERROR: Your file '%s' does not exist or cannot be created\n\n", 
                            sahara_memory_table[num_debug_entries].filename);
                        return false;
                    }
                    gettimeofday(&time_start, NULL);

                    // Determine the memory location and length to receive based on entires in memory region table.
                    // dbg("file: %s size:%lu", full_filename, sahara_memory_table[i].length);
                    while (cur < sahara_memory_table[i].length)
                    {
                        //Calculate the length of memory region.
                        uint64_t len = MIN((uint32_t)(sahara_memory_table[i].length - cur), max_ram_dump_read);

                        if (len < max_ram_dump_read || cur == 0 || (cur % (16 * 1024 * 1024)) == 0)
                            kickstart_options.verbose = 1;
                        else
                            kickstart_options.verbose = 0;

                        // send memroy read request command to the device to read that memory region.
                        memset(&pkt, 0x0, sizeof(struct sahara_pkt));   
                        if (false == send_memory_read_packet(&pkt, sahara_memory_table[i].mem_base + cur, len))
                        {
                            dbg("send_memory_read_packet failed: %s", strerror(errno));
                            close(fd);
                            return false;
                        }

                        //Now we are ready to read the actual memory region. Lets read the raw buffer.
                        memset(buffer, 0 , QUEC_MAX_RAW_BUFFER_SIZE);
                        if (false == sahara_rx_blockdata(buffer, (size_t)len))
                        {
                            if (max_ram_dump_read > (16 * 1024))
                            {
                                max_ram_dump_read = max_ram_dump_read / 2;
                                continue;
                            }
                            dbg("sahara_rx_blockdata failed.");
                            close(fd);
                            return false;
                        }

                        cur += len;
                        // dbg("Received %lu of 0x%08"PRIX64" bytes", cur, sahara_memory_table[i].length);

                        //Dump the buffer into a file.
                        nBytes = write(fd, buffer, len);
                        if (nBytes <= 0)
                        {
                            dbg("file write failed: %s", strerror(errno));
                            close(fd);
                            return false;
                        }
                        
                        if (nBytes != len)
                        {
                            dbg("Wrote only %d of 0x%08"PRIX64" bytes", nBytes, len);
                        }
                    }

                    kickstart_options.verbose = 1;
                    close(fd);
                    gettimeofday(&time_end, NULL);
                    time_throughput_calculate(&time_start, &time_end, sahara_memory_table[i].length);
                    dbg("Received file '%s'", sahara_memory_table[i].filename);
                }

                // Reset the device if required.
                if (kickstart_options.do_reset)
                {
                    dbg("kickstart option - reset enabled.");
                    if (false == send_reset_command())
                    {
                        dbg("Failed to send reset command");
                        return false;
                    }

                    state = sahara_state_wait_reset_resp;
                }
                else
                {
                    return true;
                }
                break;                

            case 4://sahara_state_wait_done_resp:
                dbg( "STATE <-- SAHARA_WAIT_DONE_RESP");
                return false;

            case 5://sahara_state_wait_reset_resp:
                dbg( "STATE <-- SAHARA_WAIT_RESET_RESP");

                // read the sahara packet. It expected that sahara rest command is already sent before coming here.
                if (true == sahara_rx_data(&pkt))
                {
                    if (sahara_reset_resp_id != qlog_le32(pkt.cmd))
                    {
                        dbg( "Waiting for reset response code %i, received %i instead.", sahara_reset_resp_id, qlog_le32(pkt.cmd));
                        continue;
                    }
                    else
                    {
                        dbg( "Successfully reset device");
                        return true;
                    }
                }
                else
                {
                    dbg("failed to read paket after sending resetting command");
                    return false;
                }                
            default:
                dbg("Unrecognized state %d", state);
                return false;
        } /* end of switch */
    } /* end of while (1) */
    return false;
}