#include "PCAPListener.cpp"
#include <vector>

#include "smartalloc.h"

using namespace std;

class PingSpoofer {
private:
    MacAddress *m_macAddress;
    PCAPListener *m_pcapListener;
    char *m_ipAddressString;
    int m_socketfd;

public:
    PingSpoofer(MacAddress *macAddress, char *ipAddressString)
        : m_macAddress(macAddress), m_ipAddressString(ipAddressString) 
    {
        m_pcapListener = new PCAPListener(m_ipAddressString);
        build_socket();
    }
    ~PingSpoofer() {
        delete m_pcapListener;
    } 

    void prepare_pcap() {
        m_pcapListener->setup();
        m_pcapListener->filter();    
    }

    void run() {
        m_pcapListener->listen(m_socketfd);
    }
    
    int build_socket() {
        if ((sockfd = socket(AF_INET, SOCK_PACKET, htons(ETH_P_RARP))) < 0) {
            perror("socket");
            return -1;
        } 
        m_socketfd = sockfd;
        return socketfd;
    }
 
};
