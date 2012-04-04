class ICMPResponder : public Responder {
private:
    static const char RESPONSE_TYPE_ICMP[]; 

public:
    ICMPResponder()
        : Responder(RESPONSE_TYPE_ICMP)
    {}
    ~ICMPResponder(){}

};

const char ICMPResponder::RESPONSE_TYPE_ICMP[] = "icmp";



