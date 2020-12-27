#include <pcap.h>
#include <cstdio>
#include <sys/socket.h>
using namespace std;

int main(){
    char errbuf[PCAP_ERRBUF_SIZE];

    pcap_if_t* all_devs;

    int ret = pcap_findalldevs(&all_devs, errbuf);


    if (ret != 0) {
        fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
        return 2;
    }
    
    for (pcap_if_t* dev = all_devs; dev; dev = dev->next){
        printf("%s %s %u\n", dev->name, dev->description, dev->flags);

        int cnt = 0;
        for (pcap_addr_t* addr = dev->addresses; addr; addr = addr->next){
            cnt++;
            printf("%d ", addr->addr->sa_family == AF_PACKET);
            printf("%d ", addr->addr->sa_family == AF_INET);
            printf("%d ", addr->addr->sa_family == AF_INET6);
            printf("\n");
        }
    }

    return 0;
}