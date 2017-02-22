/* rltm.c
 * main function for dissect a realtime acquisition
 *
 * $Id: $
 *
 * Xplico - Internet Traffic Decoder
 * By Gianluca Costa <g.costa@xplico.org>
 * Copyright 2007-2009 Gianluca Costa & Andrea de Franceschi. Web: www.xplico.org
 *
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <pfring.h>
#include <string.h>
#include <dirent.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <linux/if.h>

#include "log.h"
#include "packet.h"
#include "dmemory.h"
#include "proto.h"
#include "flow.h"
#include "rltm_pfring.h"
#include "report.h"

/* external crash info */
extern unsigned long crash_pkt_cnt; 
extern char *crash_ref_name;

static int pcap_prot_id;
static unsigned long pkt_serial = 0;

#define HAVE_PF_RING

static int RltmParam(int argc, char *argv[], char *intf, char *filter)
{
    int c;
    short n;
    extern char *optarg;
    extern int optind, optopt;

    n = 0;
    while ((c = getopt(argc, argv, "i:f:")) != -1) {
        switch(c) {
        case 'i':
            strcpy(intf, optarg);
            n++;
            break;

        case 'f':
            strcpy(filter, optarg);
            break;

        case '?':
            printf("Error: unrecognized option: -%c\n", optopt);
            return -1;
        }
    }

    if (n != 1)
        return -1;

    return 0;
}


static void RltmDissector(const struct pfring_pkthdr *h, const u_char *bytes,  u_char *user)
{
    struct pcap_ref *ref = (struct pcap_ref *)user;
    packet *pkt;
    static time_t tm = 0;
    unsigned long len;

    pkt = PktNew();

    ref->cnt++;
    pkt->raw = DMemMalloc(h->caplen+sizeof(unsigned long)*2+sizeof(char *)+4);
    memcpy(pkt->raw, bytes, h->caplen);
    pkt->raw_len = h->caplen;
    /* align 4b */
    len = pkt->raw_len;
    len = len + 4 - (len%4);
    *((unsigned long *)&(pkt->raw[len])) = ref->dlt;
    *((unsigned long *)&(pkt->raw[len+sizeof(unsigned long)])) = ref->cnt;
    *((char **)(&(pkt->raw[len+sizeof(unsigned long)*2]))) = ref->dev;
    pkt->cap_sec = h->ts.tv_sec;
    pkt->cap_usec = h->ts.tv_usec;
    pkt->serial = pkt_serial;
    FlowSetGblTime(h->ts.tv_sec);
        
    /* crash info */
    crash_pkt_cnt = ref->cnt;
    
    /* decode */
    ProtDissec(pcap_prot_id, pkt);

    /* next serial number */
    pkt_serial++;

    if (time(NULL) > tm) {
        tm = time(NULL) + 30;
        ReportSplash();
    }
}

#ifdef XPL_CHECK_HW
#define BUFF_DIM   102400
#define BUFF2_DIM  1024
static int RltmCheckMac(void)
{
    struct ifreq ifr;
    unsigned char *pmac;
    int s, fd, ret, rd, i, j, offset, nxt, k;
    unsigned char buf[BUFF_DIM];
    char mac[BUFF2_DIM];
    unsigned char pattern[] = RLTM_CHECK_MAC_STR;
    int len;
    bool end;

    ret = -1;
    pmac = NULL;

    /* extract mac */
    s = socket(AF_INET,SOCK_DGRAM,0);
    if (s != -1) {
        strcpy(ifr.ifr_name, "eth0");
        /* get mac address of the interface */
        if (ioctl(s, SIOCGIFHWADDR, &ifr) < 0) {
            printf("ioctl SIOCGIFHWADDR non riuscita\n");
        }
        else {
            pmac = (unsigned char *)&ifr.ifr_ifru.ifru_hwaddr.sa_data[0];
            sprintf(mac, "%02X:%02X:%02X:%02X:%02X:%02X",
                   *pmac, *(pmac + 1), *(pmac + 2), *(pmac + 3),
                   *(pmac + 4), *(pmac + 5) );
        }
        close(s);
        
        /* find pattern in HD */
        fd = open(RLTM_DEVICE, O_RDONLY);
        if (fd != -1) {
            len = sizeof(pattern) - 2;
            offset = 0;
            end = FALSE;
            while (end != TRUE) {
                rd = read(fd, buf+offset, BUFF_DIM/2);
                if (rd <= 0) {
                    end = TRUE;
                    break;
                }
                rd += offset;
                offset = 0;
                j = len;
                nxt = -1;
                for (i=0; i<rd; i++) {
                    if (buf[i] == pattern[j]) {
                        if (j == len) {
                            nxt = i;
                            if (i + 50 > rd) {
                                offset = rd-i;
                                memcpy(buf, buf+i, offset);
                                break;
                            }
                        }
                        j--;
                        if (j == -1) {
                            /* check MAC */
                            k = 0;
                            while (mac[k] != '\0') {
                                if (mac[k] != buf[i+k+1])
                                    break;
                                k++;
                            }
                            if (mac[k] == '\0') {
                                ret = 0;
                                end = TRUE;
                            }
                            else {
                                j = len;
                                i = nxt;
                            }
                        }
                    }
                    else {
                        j = len;
                        if (nxt != -1)
                            i = nxt;
                        nxt = -1;
                    }
                }
            }
        }
    }

    return ret;
}
#endif


char* CaptDisOptions(void)
{
    return "{-i <interface>  [-f <filter>]}";
}


void CaptDisOptionsHelp(void)
{
    printf("\t-i interface: eth0, eth1, ...\n");
    printf("\t-f filter\n");
}



int CaptDisMain(int argc, char *argv[])
{
	char intrf[RLTM_PATH_DIM], filter_app[RLTM_PATH_DIM];
    pfring *cap_pfring = NULL;
    u_int32_t flags = PF_RING_PROMISC | PF_RING_LONG_HEADER;
    int ret;
    int ifindex = 0;
    struct pcap_ref ref;
    FILE *run;
    const u_char *pkt;
    struct pfring_pkthdr pfring_hdr;

#ifdef XPL_CHECK_HW
    /* check eth0 MAC */
    if (RltmCheckMac() != 0) {
        printf("Fallito\n");
        return -1;
    }
#endif
    
    /* pcapfile  protocol id */
    pcap_prot_id = ProtId("pcapf");
    if (pcap_prot_id == -1) {
        return -1;
    }
    
    run = fopen(RLTM_PID_FILE, "w+");
    if (run != NULL) {
        fprintf(run, "%i\n", getpid());
        fclose(run);
    }

    /* serial number of packet */
    pkt_serial = 1;

    /* interace & filter */
    intrf[0] = '\0';
    filter_app[0] = '\0';
    ret = RltmParam(argc, argv, intrf, filter_app);
    if (ret != 0) {
        return -1;
    }
    
    /* open device in promiscuous mode */
    cap_pfring = pfring_open(intrf, 20000, flags);
    if (cap_pfring == NULL) {
        printf("PFring Open Error: %s\n", strerror(errno));
        return -1;
    } else {
        /* compile and apply the filter */

    	/* set pfring mode*/
    	pfring_set_socket_mode(cap_pfring, send_and_recv_mode);

    	/* set capture packet direction */
    	pfring_set_direction(cap_pfring, rx_and_tx_direction);

    	/* set poll watermark */
    	pfring_set_poll_watermark(cap_pfring, 1);

    	/* set */
    	pfring_get_bound_device_ifindex(cap_pfring, &ifindex);

    	/* enable ring buffer */
    	ret = pfring_enable_ring(cap_pfring);
    	if(ret != 0){
    		printf("Pfring enbale ring fail\n");
    		return -1;
    	}

    	/* interface */
        ref.dev = intrf;
        
        /* data link type */
        ref.dlt = 1;
        
        /* packet counter */
        ref.cnt = 0;
        
        /* let pcap loop over the input, passing data to the decryptor */
        while(1){
         	memset(&pfring_hdr, '\0', sizeof(struct pfring_pkthdr));
         	if(pfring_recv(cap_pfring, (u_char**) &pkt, 0, &pfring_hdr, 1) < 0){
         		continue;
         	}
         	RltmDissector(&pfring_hdr, pkt, (u_char*)&ref);
        }
        pfring_close(cap_pfring);
    }

    return 0;
}

const char *CaptDisSource(void)
{
    return "Live Network Capture";
}
