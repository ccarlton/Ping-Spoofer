#include <string.h>
#include <iostream>
#include <string>

class MacAddress {
private:
    char *m_stringMacAddress;
    char m_macAddressBytes[6];
public:
    MacAddress(char *stringMacAddress)
        : m_stringMacAddress(stringMacAddress) 
    {}
    ~MacAddress() {}

    void parse_mac() {
        int i, j;
        char subString[13];
        unsigned int byte = 0;

        printf("String mac: %s\n", m_stringMacAddress);
        /* Format */
        for(i=0; i<strlen(m_stringMacAddress); i++) {
            if (m_stringMacAddress[i] != 58) {
                memcpy(&subString[strlen(subString)], &m_stringMacAddress[i], 1);
            }
        }
        /* Convert */
        for (i=0; i<=12; i+=2) {
            sscanf(subString+i, "%2x", &byte);
            j = i == 0 ? 0 : i-(i/2);
            m_macAddressBytes[j] = byte;
        }
    }
};
