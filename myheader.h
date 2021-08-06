#ifndef MYHEADER_H
#define MYHEADER_H

#endif // MYHEADER_H
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <signal.h>
#include <errno.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <netinet/ether.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <cstdio>
#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include "ethhdr.h"
#include "arphdr.h"
#define BROADCAST "ff:ff:ff:ff:ff:ff"
#define NONE "00:00:00:00:00:00"

#pragma pack(push, 1)
struct EthArpPacket final {
    EthHdr eth_;
    ArpHdr arp_;
};
struct EthIpPacket {
    EthHdr eth_;
    char none[12];
    Ip s_ip;
    Ip d_ip;
};

struct Flow final{
    Ip ip_;
    Mac mac_;
};
typedef struct Thread{
    pcap_t* handle;
    Flow* me;
    Flow* sender;
    Flow* target;
    pthread_mutex_t mutx;
}thread;
#pragma pack(pop)

EthArpPacket FindMac(Ip target,pcap_t* handle,Flow me);
Ip getIPAddress(char*dev);
Mac getMacAddress(char* dev);
void* arp(void* tt);
void* check_broadcast(Thread* send_t, Thread*targ_t,int cnt);
void* attacker(void*t_t);
EthArpPacket define_packet(Mac dmac,Mac smac,Mac tmac,Ip sip,Ip tip);
void define_thread(Thread*t);
