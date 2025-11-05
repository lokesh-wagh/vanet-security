#pragma once
#include "veins/modules/application/ieee80211p/DemoBaseApplLayer.h"
#include "veins/base/utils/SimpleAddress.h"
#include "veins/modules/messages/MyMsg_m.h"
#include <map>
#include <set>

namespace veins {

struct DeliveryInfo {
    int srcId;
    simtime_t sendTime;
    std::set<int> receivers;
    bool delivered = false;
};

// Forward declare MyVeinsApp to use in MessageCounter if needed
class MyVeinsApp;

struct MessageCounter {
    int count = 0;
    simtime_t startTime;
    bool isBlacklisted = false;
};

class MyVeinsApp : public DemoBaseApplLayer {
public:
    void initialize(int stage) override;
    void finish() override;

protected:
    void onWSM(BaseFrame1609_4* wsm) override;
    void handleSelfMsg(cMessage* msg) override;
    void handlePositionUpdate(cObject* obj) override;
    void handleLowerMsg(cMessage* msg) override;

private:
    bool detectionEnabled = true;
    // Attack parameters
    bool malicious = false;
    std::string attackType;
    int attackCounter = 0;
    int totalAttackers = 14;
    int totalDefenders = 15;
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

    // Network performance metrics
    simtime_t totalEndToEndDelay;
    simtime_t totalJitterTime;
    int jitterCount;
    long totalBytesReceived;
    int packetsSent;
    simtime_t lastArrivalTime;
    simtime_t lastInterArrivalTime;
    simtime_t lastThroughputTime;

    // Flood detection and prevention
    std::map<int, MessageCounter> messageCounters; // srcId -> counter
    double detectionWindow = 2.0;
    double floodThreshold = 3.0;
    simtime_t lastWindowStart;
    int packetsInWindow = 0;

    // Statistics vectors
    cOutVector packetsSentVector;
    cOutVector packetsReceivedVector;
    cOutVector endToEndDelayVector;
    cOutVector jitterVector;
    cOutVector throughputVector;

    // Message tracking
    std::map<int, int> receivedMessages;

    // Global packet delivery tracking (static = shared across all instances)
    static std::map<long, DeliveryInfo> globalPacketMap;
    static long nextPacketId;

    bool detectMaliciousBehavior(MyMsg* msg);
    void takeEvasiveAction();
    void endEvasiveAction();
    void changeNodeColor(const char* color);
    void populateMyMsg(MyMsg* msg , bool attackPacket);
    bool isFloodAttacker(int senderId);
    void updateMessageCounter(int senderId);
};

}
