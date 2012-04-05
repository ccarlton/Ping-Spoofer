#include <pcap.h>
#include <vector>

#include "Responder.cpp"
#include "ICMPResponder.cpp"
#include "ARPResponder.cpp"
#include "headers.h"

using namespace std;

class PCAPListener {
private:
    char *m_pcapDevice; 
    int m_socketfd;
    char *m_ipAddressString;
    pcap_t *m_handle;
    vector<Responder*> m_responderList;
    
public:
    PCAPListener(char *ipAddressString)
        : m_ipAddressString(ipAddressString)
    {
        m_responderList.push_back(new ICMPResponder());
        m_responderList.push_back(new ARPResponder());
    }
    ~PCAPListener() {
        std::vector<Responder*>::iterator itr;
        for ( itr = m_responderList.begin(); itr < m_responderList.end(); ++itr) {
            delete *itr; 
        }
    }
    
    int setup() {
        char errbuf[PCAP_ERRBUF_SIZE];

        m_pcapDevice = pcap_lookupdev(errbuf);
        if (m_pcapDevice == NULL) {
            fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
            return -1;
        } 
        return 0;
    }

    int filter() {
        char errbuf[PCAP_ERRBUF_SIZE];
        struct bpf_program fp;
        bpf_u_int32 mask;
        bpf_u_int32 net;
        char filter_exp[56] = "dst "; 
       
        strcat(filter_exp, m_ipAddressString);
   
        if (pcap_lookupnet(m_pcapDevice, &net, &mask, errbuf) == -1) {
            fprintf(stderr, "Can't get netmask for device %s\n", m_pcapDevice);
            return -1;
        }
    
        if ((m_handle  = pcap_open_live(m_pcapDevice, BUFSIZ, 1, 1000, errbuf)) == NULL) {
            fprintf(stderr, "Couldn't open device %s: %s\n", m_pcapDevice, errbuf);
            return -1;
        }
        
        if (pcap_compile(m_handle, &fp, filter_exp, 0, net) == -1) {
            fprintf(stderr, "couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(m_handle));
            return -1;
        }
        
        if (pcap_setfilter(m_handle, &fp) == -1) {
            fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(m_handle));
            return -1;
        }
        return 0;
    }

    int listen(int socketfd) {
        m_socketfd = socketfd;
        pcap_loop(m_handle, -1, packet_handler, (u_char *)this);
        return 0;
    }

    static void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
        vector<Responder*> responderList = ((PCAPListener *)args)->m_responderList;
        Responder *responder;
        //u_short type = (u_short)((struct eth_header *)packet->type);
 
        std::vector<Responder*>::iterator itr;
        for (itr = responderList.begin(); itr < responderList.end(); ++itr) {
            string type = (*itr)->get_type;
            if (!strcmp(type, "arp")) //&& type == ETHTYPE_ARP)
                responder = (*itr);
            else if (!strcmp(type, "icmp")) //&& type == ETHTYPE_IP)
                responder = (*itr); 
        }

        //responder->build_response(m_socketfd);
        ((PCAPListener *)args)->print_buf((u_char *)packet, header->len);
    }

    void print_buf(u_char *buf, int size) {
        int i;
        for (i=0; i<size; i++) 
            printf("%x ", buf[i]);
    }
};
