/**
 * @file    hra_pcap.h
 * @author  Titan IC Systems <support@titanicsystems.com>
 *
 * @section DESCRIPTION
 *
 * API's for interfacing with packet capture libraries.
 *
 * @section LICENSE
 *
 *   BSD LICENSE
 *
 *   Copyright (C) 2014-2019 Titan IC Systems Ltd. All rights reserved.
 *
 *   Redistribution and use in source and binary forms, with or without
 *   modification, are permitted provided that the following conditions
 *   are met:
 *
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in
 *       the documentation and/or other materials provided with the
 *       distribution.
 *     * Neither the name of Titan IC Systems Ltd. nor the names of its
 *       contributors may be used to endorse or promote products derived
 *       from this software without specific prior written permission.
 *
 *   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *   "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 *   A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 *   OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *   SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 *   LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 *   DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 *   THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *   (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 *   OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef _HRA_PCAP_H_
#define _HRA_PCAP_H_

/* Anonymous definition for hra_pcap struct and hra_pcap_buf. */
struct hra_pcap;
struct hra_pcap_buf;

/* Types of PCAP that the application can process. */
enum hra_pcap_type_e
{
    HRA_PCAP_TYPE_FILE,
    HRA_PCAP_TYPE_LIVE
};

/**
 * Access function for getting the 'type' of a given pcap structure.
 *
 * @param pcap   pointer to pcap context structure.
 * @return       PCAP type (live or file)
 */
enum hra_pcap_type_e hra_pcap_type(struct hra_pcap *pcap);

/**
 * Access function for getting the name string associated with
 * the given pcap structure.
 *
 * @param pcap   pointer to pcap context structure.
 * @return       pointer to pcap name string.
 */
char* hra_pcap_name(struct hra_pcap *pcap);

/**
 * Function for allocating an hra_pcap structure.
 *
 * @param type   what type of pcap capture (file or live)
 * @param name   name of pcap file, or live interface name.
 * @return       pointer to allocated structure, or NULL if alloc fails.
 */
struct hra_pcap* hra_pcap_alloc(enum hra_pcap_type_e type, char *name);

/**
 * Function for free'ing a pcap structure.
 *
 * @param pcap   Pointer to allocated structure, or NULL if alloc fails.
 */
void hra_pcap_free(struct hra_pcap *pcap);

/**
 * Function to allocate a structure for storing captured pcap packets.
 *
 * @return               pointer to allocated structure, or NULL if alloc fails.
 */
struct hra_pcap_buf* hra_pcap_buf_alloc(void);

/**
 * Given an hra_pcap_buf structure, return a pointer to the actual packet data.
 *
 * @param buf        pointer to pcap buffer structure.
 * @return           pointer to packet data within the structure.
 */
uint8_t* hra_pcap_buf_pkt_data(struct hra_pcap_buf *buf);

/**
 * Given an hra_pcap_buf structure, return the length of the packet data.
 *
 * @param buf        pointer to pcap buffer structure.
 * @return           length of packet data within the structure.
 */
uint32_t hra_pcap_buf_pkt_len(struct hra_pcap_buf *buf);

/**
 * Function to freeing pcap structures.
 *
 * @param buf        buf to be freed.
 */
void hra_pcap_buf_free(struct hra_pcap_buf *buf);

/**
 * Function for opening pcap capture on the given queue.
 *
 * @param pcap   pointer to pcap context structure.
 * @return       0 for sucess.  negtive value for error.
 */
int hra_pcap_open(struct hra_pcap *pcap);

/**
 * Close pcap capture for the given queue.
 *
 * @param queue   pointer to queue context structure.
 */
void hra_pcap_close(struct hra_pcap *pcap);

/**
 * Capture up to a given maximum number of packets on the given queue.
 * The function is passed an array of pointers.
 * As each packet is captured, a structure will be allocated to
 * store the data, and the array populated with a pointer to that structure.
 * The number of packets captured, i.e the number of array elements
 * populated, is returned.
 *
 * @param pcap       Pointer to pcap context structure.
 * @param rx_pkts    Array of pointers to pcap capture buffers.
 * @return           Number of packets captured/read.
 */
uint32_t hra_pcap_read(struct hra_pcap      *pcap,
                       struct hra_pcap_buf **rx_pkts,
                       uint32_t              max_pkts);
/**
 * Abort current pcap capture.
 *
 * @param pcap       Pointer to pcap context structure.
 * @return           None.
 */
void hra_pcap_sig(struct hra_pcap *pcap, int sig);

#endif  /*_HRA_PCAP_H_ */
