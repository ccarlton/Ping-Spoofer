#include "PCAPListener.cpp"
#include "Responder.cpp"
#include "ICMPResponder.cpp"
#include "ARPResponder.cpp"
#include <vector>

#include "smartalloc.h"

using namespace std;

class PingSpoofer {
private:
    MacAddress *m_macAddress;
    PCAPListener *m_pcapListener;
    char *m_ipAddressString;
    vector<Responder*> m_responderList;

public:
    PingSpoofer(MacAddress *macAddress, char *ipAddressString)
        : m_macAddress(macAddress), m_ipAddressString(ipAddressString) 
    {
        m_responderList.push_back(new ICMPResponder());
        m_responderList.push_back(new ARPResponder());
        m_pcapListener = new PCAPListener(m_ipAddressString);
    }
    ~PingSpoofer() {
        delete m_pcapListener;
        std::vector<Responder*>::iterator itr;
        for ( itr = m_responderList.begin(); itr < m_responderList.end(); ++itr) {
            delete *itr; 
        }
  
        m_responderList.clear();
    } 

    int prepare_pcap() {
        m_pcapListener->setup();
        m_pcapListener->filter();    
    }

    int run() {
        m_pcapListener->listen();
        printf("ran");
    }
 
};
