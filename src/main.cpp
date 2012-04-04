#include <stdio.h>
#include <stdlib.h>

#include "main.h"
#include "MacAddress.cpp"
#include "PingSpoofer.cpp"

int main(int argc, char **argv) {
    if (argc < 3) {
        print_usage();
    }

    MacAddress *macAddress = new MacAddress(argv[1]);
    macAddress->parse_mac();
    PingSpoofer *pingSpoofer = new PingSpoofer(macAddress, argv[2]);
    pingSpoofer->prepare_pcap();
    
    delete pingSpoofer;
    delete macAddress;
}

void print_usage() {
    printf("Usage: ping_spoof <spoofed-mac-address> <spoofed-ip-address>\n");
    exit(EXIT_FAILURE);
}
