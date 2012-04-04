class ARPResponder : public Responder {
private:
    static const char RESPONSE_TYPE_ARP[];
public:
    ARPResponder()
        : Responder(RESPONSE_TYPE_ARP)
    {}
    ~ARPResponder(){}
};

const char ARPResponder::RESPONSE_TYPE_ARP[] = "arp";
