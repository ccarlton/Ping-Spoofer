#include <string>
#include <string.h>

class Responder {
private:
    const char *m_responseType;
    int m_socketfd;

public:
    Responder(const char *responseType)
        : m_responseType(responseType)
    {}
    ~Responder(){};

    const char *get_type() {
        return m_responseType;
    }

    void set_socket(int socketfd) {
        m_socketfd = socketfd;
    }

    void build_eth_header(u_char *packet, u_char *smac, u_char *dmac) {
    }

    char *formatConvertMac(char *asciiMac) {
        int  i, j;
        char *mac = (char*)calloc(6, 1);
        char *subString = (char*)calloc(13,1);
        unsigned int byte = 0;

        /* Format */
        for(i=0; (unsigned int)i<strlen(asciiMac); i++) {
            if (asciiMac[i] != 58) {
                memcpy(&subString[strlen(subString)], &asciiMac[i], 1);
            }
        }

        /* Convert */
        for (i=0; i<=12; i+=2) {
            sscanf(subString+i, "%2x", &byte);
            j = i == 0 ? 0 : i-(i/2);
            mac[j] = byte;
        }

        return mac;
    }
};
