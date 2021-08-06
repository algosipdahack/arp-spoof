#include "myheader.h"

void usage() {
    printf("syntax : send-arp <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]\n");
    printf("sample : send-arp wlan0 192.168.10.2 192.168.10.1\n");
}
int main(int argc, char* argv[]) {
    if (argc < 4) {
        usage();
        return -1;
    }
    pthread_mutex_t mutx;
    pthread_mutex_init(&mutx, NULL);

    char* dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
    if (handle == nullptr) {
        fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
        return -1;
    }

    struct Flow me,sender,target;
    me.ip_=getIPAddress(argv[1]);
    me.mac_ = getMacAddress(argv[1]);
    int cnt = (argc-2)/2;

    thread *send_t = (thread*)malloc(sizeof(thread)*cnt);
    thread *targ_t = (thread*)malloc(sizeof(thread)*cnt);

    for(int i = 1; i<=cnt; ++i){
        define_thread(&send_t[i]);
        define_thread(&targ_t[i]);
        send_t[i-1]={handle,&me,&target,&sender,mutx};
        targ_t[i-1]={handle,&me,&sender,&target,mutx};

        send_t[i-1].target->ip_ = Ip(argv[2*i]);
        targ_t[i-1].sender->ip_ = Ip(argv[2*i]);
        send_t[i-1].sender->ip_ = Ip(argv[1+2*i]);
        targ_t[i-1].target->ip_ = Ip(argv[1+2*i]);

        thread t[2] = {send_t[i-1],targ_t[i-1]};
        arp((void*)&send_t[i-1],(void*)&targ_t[i-1],(void*)&send_t[i-1]);
        arp((void*)&send_t[i-1],(void*)&targ_t[i-1],(void*)&targ_t[i-1]);
    }
    check_broadcast(send_t,targ_t,cnt);
    pcap_close(handle);
}
