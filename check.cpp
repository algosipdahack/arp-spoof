#include "myheader.h"

void* check_broadcast(Thread* send_t, Thread*targ_t,int cnt){/*check recover time*/

    while(1){
        for(int i = 0; i<cnt; i++){
            struct pcap_pkthdr* header;
            char * packet;

            int res = pcap_next_ex(send_t[i].handle, &header,(const u_char**)&packet);
            if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
                printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(send_t[i].handle));
            }

            int flag1, flag2,flag3;

            EthArpPacket* recv_packet = (EthArpPacket*)packet;
            EthIpPacket* ip_packet = (EthIpPacket*)packet;

            Thread tt[2] = {send_t[i],targ_t[i]};
            //arp((void*)&send_t[i]);
            //arp((void*)&targ_t[i]);

            if(recv_packet->eth_.type()!=0x806){//not the arp - relay
                for(Thread t :tt){
                    flag1 = recv_packet->eth_.smac() == t.sender->mac_ ? 1:0;
                    flag2 = recv_packet->eth_.dmac() == t.me->mac_ ? 1:0;
                    flag3 = ((EthIpPacket*)packet)->d_ip == (Ip)htonl(t.target->ip_) ? 1:0;

                    if(flag1&&flag2&&flag3){
                        u_char * relay_packet = (u_char*)malloc(header->caplen);
                        memcpy(relay_packet,packet,header->caplen);

                        ((EthHdr*)relay_packet)->smac_=Mac(t.me->mac_);
                        ((EthHdr*)relay_packet)->dmac_=Mac(t.target->mac_);

                        int res = pcap_sendpacket(t.handle, relay_packet, header->caplen);
                        if (res != 0) {
                            fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(t.handle));
                        }
                        free(relay_packet);
                    }
                }
                continue;
            }

            /* arp - reply(unicast+broadcast)*/
            for(Thread t :tt){
                flag1 = recv_packet->arp_.sip() == t.sender->ip_ ? 1:0;
                flag2 = recv_packet->arp_.tip() == t.target->ip_ ? 1:0;
                if((flag1&&flag2))
                    arp((void*)&t);
            }
        }
    }
}

