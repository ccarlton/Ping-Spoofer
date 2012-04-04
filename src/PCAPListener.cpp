#include <pcap.h>

class PCAPListener {
private:
    char *m_pcapDevice; 
    char *m_ipAddressString;
    pcap_t *m_handle;
    
public:
    PCAPListener(char *ipAddressString)
        : m_ipAddressString(ipAddressString)
    {}
    ~PCAPListener(){}
    
    int setup() {
        char errbuf[PCAP_ERRBUF_SIZE];

        m_pcapDevice = pcap_lookupdev(errbuf);
        if (m_pcapDevice == NULL) {
            fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
            return -1;
        } 
        printf("Device: %s\n", m_pcapDevice);
        printf("ip_stringarddr: : %s\n", m_ipAddressString);
        return 0;
    }

    int filter() {
        char errbuf[PCAP_ERRBUF_SIZE];
        struct bpf_program fp;
        bpf_u_int32 mask;
        bpf_u_int32 net;
        char filter_exp[56] = "dst "; 
       
        printf("in filter"); 
        strcat(filter_exp, m_ipAddressString);
        printf("Filter expression: %s\n", filter_exp);
   
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
    }

    int listen() {
        pcap_loop(m_handle, -1, packet_handler, NULL);
        return 0;
    }

    static void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
        printf("Got Packet\n");
    }
};
