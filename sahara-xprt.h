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

#ifndef __SAHARA_XPRT_H__
#define __SAHARA_XPRT_H__
#define _GNU_SOURCE
#include "sahara-ramdump.h"

/*==========================================================================
DESCRIPTION

  This function is used to initialize the transport methods of sahara protocol.
  Device must be enumerated and valid file descriptor must be passed to this 
  function.

PARAMETERS

    port_fd [in]: Valid usb file descriptor of the device to read and write.

RETURN VALUE
    True on success, else false.
==========================================================================*/
bool sahara_init_xprt(const int port_fd);

/*==========================================================================
DESCRIPTION

  This function is used to receive a sahara packet from the usb fd. First it
  will try to read sahara command packet, later it will read the remaining 
  bytes based on the length received in the command packet.

PARAMETERS

    pkt [in/out]: Pointer to sahara_pkt stucture type. Memory must be  
    allocated by the caller of this function.

RETURN VALUE
    True on success, else false.
==========================================================================*/
bool sahara_rx_data(struct sahara_pkt *pkt);

/*==========================================================================
DESCRIPTION

  This function is used to receive N number of bytes from the usb fd. It will 
  be a blocking call untill the complete bytes read or any error or timeout 
  happened during the read operaion.

PARAMETERS

    buffer [in/out]: Pointer to memory to store the read buffer. Memory must   
    be allocated by the caller of this function.

    bytes_to_read [in]: Number of bytes to be called.
    
RETURN VALUE
    True on success, else false.
==========================================================================*/
bool sahara_rx_blockdata(void *buffer, size_t bytes_to_read);

/*==========================================================================
DESCRIPTION

  This function is used to transmit a sahara packet to the usb fd. 

PARAMETERS

    pkt [in]: Pointer to sahara_pkt stucture type. 

RETURN VALUE
    True on success, else false.
==========================================================================*/
bool sahara_tx_data (const struct sahara_pkt *pkt);

#endif
