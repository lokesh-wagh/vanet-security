#pragma once
#include "veins/modules/application/ieee80211p/DemoBaseApplLayer.h"
#include "veins/base/utils/SimpleAddress.h"
#include <map>

namespace veins {
class MyVeinsApp : public DemoBaseApplLayer {
public:
    void initialize(int stage) override;
    void finish() override;
protected:
    void onWSM(BaseFrame1609_4* wsm) override;
    void handleSelfMsg(cMessage* msg) override;
    void handlePositionUpdate(cObject* obj) override;
private:
    // Attack parameters
    bool malicious = false;
    std::string attackType;
    int attackCounter = 0;

    // Evasive action
    bool underAttack = false;
    simtime_t attackDetectedAt;

    // Timers
    cMessage* attackTimer = nullptr;
    cMessage* evasiveTimer = nullptr;

    // Statistics
    int normalPacketsSent = 0;
    int attackPacketsSent = 0;
    int packetsReceived = 0;
    int attacksDetected = 0;

    // Flood detection
    std::map<LAddress::L2Type, int> messageCounts;
    simtime_t lastReset = 0;

    void detectMaliciousBehavior(DemoSafetyMessage* msg);
    void takeEvasiveAction();
    void endEvasiveAction();
    void changeNodeColor(const char* color);
};
}
