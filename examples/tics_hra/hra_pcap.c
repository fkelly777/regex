/**
 * @file    hra_pcap.c
 * @author  Titan IC Systems <support@titanicsystems.com>
 *
 * @section DESCRIPTION
 *
 *   Module for packet capture (pcap).
 *   At this time, this is a wrapper around libpcap.
 *   However, if additional mechanisms for packet capture are required,
 *   they should be implemented in this module to minimise refactoring
 *   elsewhere.
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
#include <inttypes.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <stdbool.h>
#include <pcap/pcap.h>

#include "hra_pcap.h"

/* Top level hra_pcap instance structure. */
struct hra_pcap {
    enum hra_pcap_type_e  type;
    char                 *name;
    pcap_t               *handle;

    /* Array of pcap buffer pointers for the current capture. */
    struct hra_pcap_buf **rx_pkts;
    int                   pkt_cnt_max,
                          pkt_cnt;
};

/*
 * A structure for storing pcap data that has been read.
 */
struct hra_pcap_buf {
    /*
     * This is a shadow copy of data returned from libpcap.
     * If some other capture mechanism was used, the internals
     * of that capture mechanism would be hidden in this structure
     * and the hra_pcap_xxx API's.
     */
    struct pcap_pkthdr pkt_hdr;
    u_char pkt_data[64 * 1024];
};

/*
 * Allocate an hra_pcap structure with the given type and interface name.
 */
struct hra_pcap*
hra_pcap_alloc(enum hra_pcap_type_e type, char *name)
{
    struct hra_pcap *pcap = malloc(sizeof(*pcap));
    if (pcap)
    {
        memset(pcap, 0x0, sizeof(*pcap));
        pcap->type = type;
        pcap->name = strdup(name);
    }
    return pcap;
}

/*
 * Free the given hra_pcap structure.
 */
void
hra_pcap_free(struct hra_pcap *pcap)
{
    if (pcap)
    {
        /* Defensive check.  Ensure the capture has been closed. */
        hra_pcap_close(pcap);
        if (pcap->name)
        {
            free(pcap->name);
        }
        free(pcap);
    }
}

/*
 * Allocate a buffer for capturing a single packet.
 */
struct hra_pcap_buf*
hra_pcap_buf_alloc(void)
{
    return (malloc(sizeof(struct hra_pcap_buf)));
}

/*
 * Free a pcap buffer.
 */
void
hra_pcap_buf_free(struct hra_pcap_buf *buf)
{
    free(buf);
    return;
}

/*
 * Return pointer to packet data within a pcap_buf.
 */
uint8_t* hra_pcap_buf_pkt_data(struct hra_pcap_buf *buf)
{
    return (uint8_t*)buf->pkt_data;
}

/*
 * Return length of packet data within a pcap_buf.
 */
uint32_t hra_pcap_buf_pkt_len(struct hra_pcap_buf *buf)
{
    return buf->pkt_hdr.len;
}

/*
 * Begin capture for the given pcap interface.
 */
int
hra_pcap_open(struct hra_pcap *pcap)
{
    int ret = 0;

    if (!pcap->handle)
    {
        if (pcap->name)
        {
            char errbuf[PCAP_ERRBUF_SIZE];
            if (pcap->type == HRA_PCAP_TYPE_FILE)
            {
                pcap->handle = pcap_open_offline(pcap->name, errbuf);
            }
            else if (pcap->type == HRA_PCAP_TYPE_LIVE)
            {
                pcap->handle = pcap_open_live(pcap->name,
                                              64 * 1024,  /* snaplen */
                                              1,          /* promiscous */
                                              10,         /* to_ms */
                                              errbuf);
            }
            else
            {
                printf("Error: %s %d, invalid pcap type %d\n", __FUNCTION__, __LINE__, pcap->type);
                ret = -1;
            }

            if (!pcap->handle)
            {
                printf("Error: Unable to open pcap file \"%s\": err %s\n",
                        pcap->name, errbuf);
                ret = -1;
            }
        }
        else
        {
            printf("Error: %s %d, no pcap file name provided.\n", __FUNCTION__, __LINE__);
            ret = -1;
        }
    }

    return (ret);
}

/*
 * Close/End capture for the given pcap interface.
 */
void
hra_pcap_close(struct hra_pcap *pcap)
{
    if (pcap->handle)
    {
        pcap_close(pcap->handle);
        pcap->handle = NULL;
    }
}

/*
 * Access function: return type of the given pcap structure.
 */
enum hra_pcap_type_e hra_pcap_type(struct hra_pcap *pcap)
{
    return pcap->type;
}

/*
 * Access function: return name of the given pcap structure.
 */
char* hra_pcap_name(struct hra_pcap *pcap)
{
    return pcap->name;
}

/*
 * For terminating a pcap_loop() execution.
 */
void hra_pcap_sig(struct hra_pcap *pcap, int sig)
{
    if (pcap->handle)
    {
        pcap_breakloop(pcap->handle);
    }
}

/*
 * Callback passed to pcap_loop() function.
 */
void hra_got_packet(u_char *user, const struct pcap_pkthdr *pkt_hdr, const u_char *pkt_data)
{
    struct hra_pcap *pcap = (struct hra_pcap*)user;
    struct hra_pcap_buf *hra_pcap_buf = hra_pcap_buf_alloc();

    if (hra_pcap_buf)
    {
        /* copy libpcap header structure and data buffer. */
        hra_pcap_buf->pkt_hdr = *pkt_hdr;  /* copy header structure. */
        assert(pkt_hdr->len <= sizeof(hra_pcap_buf->pkt_data));
        memcpy(hra_pcap_buf->pkt_data, pkt_data, pkt_hdr->len);
        pcap->rx_pkts[pcap->pkt_cnt++] = hra_pcap_buf;
    }
}


/*
 * Read up to to max packets from the given pcap interface.
 */
uint32_t
hra_pcap_read(struct hra_pcap      *pcap,
              struct hra_pcap_buf **rx_pkts,
              uint32_t              max_pkts)
{
    if (max_pkts)
    {
        pcap->rx_pkts = rx_pkts;
        pcap->pkt_cnt_max = max_pkts;
        pcap->pkt_cnt = 0;
        pcap_loop(pcap->handle, max_pkts, hra_got_packet, (u_char *)pcap);
        return pcap->pkt_cnt;
    }
    else
    {
        /*
         * Calling pcap_loop with 0 packets means it captures forever.
         * Our code doesn't cater for that.
         */
        exit(-1);
    }
}
