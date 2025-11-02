#pragma once

#include "veins/veins.h"
#include "veins/modules/application/ieee80211p/DemoBaseApplLayer.h"

using namespace omnetpp;

namespace veins {

class VEINS_API MyVeinsApp : public DemoBaseApplLayer {
public:
    void initialize(int stage) override;
    void finish() override;

protected:
    void onWSM(BaseFrame1609_4* wsm) override;
    void onWSA(DemoServiceAdvertisment* wsa) override;
    void handleSelfMsg(cMessage* msg) override;
    void handlePositionUpdate(cObject* obj) override;

private:
    // Attack parameters
    bool malicious = false;
    std::string attackType;
    int attackCounter = 0;

    // Timers
    cMessage* attackTimer = nullptr;

    // Statistics
    int normalPacketsSent = 0;
    int attackPacketsSent = 0;
    int packetsReceived = 0;
    void detectMaliciousBehavior(DemoSafetyMessage* msg);
};

} // namespace veins
