#include "header.h"

void handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data);

int main()
{
   pcap_t *handle;         /* Session handle */
   char *dev;         /* The device to sniff on */
   char errbuf[PCAP_ERRBUF_SIZE];   /* Error string */
   struct bpf_program fp;      /* The compiled filter */
   char filter_exp[] = "port 80";   /* The filter expression */
   bpf_u_int32 mask;      /* Our netmask */
   bpf_u_int32 net;      /* Our IP */


   /* Define the device */
   dev = pcap_lookupdev(errbuf);
   if (dev == NULL) {
       fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
       return(2);
   }
   /* Find the properties for the device */
   if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
       fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev, errbuf);
       net = 0;
       mask = 0;
   }
   /* Open the session in promiscuous mode */
   handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
   if (handle == NULL) {
       fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
       return(2);
   }
   /* Compile and apply the filter */
   if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
       fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
       return(2);
   }
   if (pcap_setfilter(handle, &fp) == -1) {
       fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
       return(2);
   }
   /* Grab a packet */
   while(1){
       struct pcap_pkthdr * hdr;
       const u_char * packet;
       const int res = pcap_next_ex(handle, &hdr, &packet);

       if(res<0)
           break;
       if(res==0)
           continue;

        pcap_loop(handle, 1, handler, NULL);

   }
   /* And close the session */
   pcap_close(handle);
   return(0);
}

void handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data)           //실제 캡처된 패킷 데이터
{
    ether_header *eh;
    ip_header *ih;
    tcp_header *th;
    u_int ip_len;
    /* retireve the position of the ip header */


    eh = (ether_header *)pkt_data;
    ih = (ip_header *)(pkt_data + 14); //14 = ethernet header
    ip_len = (ih->ver_ihl & 0xf) * 4;
    th = (tcp_header *) ( pkt_data + 14 + ip_len ); //14 = ethernet header

    printf("eth.smac : %x:%x:%x:%x:%x:%x\n", eh->src_host[0], eh->src_host[1], eh->src_host[2], eh->src_host[3], eh->src_host[4], eh->src_host[5]);
    printf("eth.dmac : %x:%x:%x:%x:%x:%x\n", eh->dst_host[0], eh->dst_host[1], eh->dst_host[2], eh->dst_host[3], eh->dst_host[4], eh->dst_host[5]);
    printf("ip.sip : %d.%d.%d.%d\n", ih->saddr[0], ih->saddr[1], ih->saddr[2], ih->saddr[3]);
    printf("IP dst : %d.%d.%d.%d\n", ih->daddr[0], ih->daddr[1], ih->daddr[2], ih->daddr[3]);
    printf("tcp.sport : %d\n", ntohs(th->sport));
    printf("tcp.dport : %d\n\n", ntohs(th->dport));
}
