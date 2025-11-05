#ifndef MYVEINSAPP_H
#define MYVEINSAPP_H

#include <map>
#include <set>
#include <deque>
#include <string>
#include <omnetpp.h>
#include "veins/modules/application/ieee80211p/DemoBaseApplLayer.h"

using namespace omnetpp;

namespace veins {

// Forward declaration
class MyMsg;

// Enhanced message counter with sliding window support
struct MessageCounter {
    int count = 0;                          // Current message count in window
    simtime_t startTime = -1;               // Start time of current window
    simtime_t suspicionStartTime = -1;      // When suspicion started
    simtime_t blacklistTime = -1;           // When blacklisted
    bool isBlacklisted = false;             // Blacklist status
    int suspicionLevel = 0;                 // Suspicion level (0-10)
    std::deque<simtime_t> messageTimestamps; // Sliding window of timestamps

    MessageCounter() = default;
};

// Delivery information for global tracking
struct DeliveryInfo {
    int srcId = -1;                         // Source node ID
    simtime_t sendTime = -1;                // Original send time
    std::set<int> receivers;                // Nodes that received this packet

    DeliveryInfo() = default;
};

// Detection statistics
struct DetectionStatistics {
    int totalDetections = 0;                // Total malicious behavior detections
    int highRateDetections = 0;             // High rate flood detections
    int packetsBlocked = 0;                 // Total packets blocked
    int falsePositives = 0;                 // False positive detections

    void reset() {
        totalDetections = highRateDetections = packetsBlocked = falsePositives = 0;
    }
};

class MyVeinsApp : public DemoBaseApplLayer {
private:
    // ==================== CORE DETECTION PARAMETERS ====================
    bool malicious = false;                         // Whether this node is malicious
    bool detectionEnabled = true;                  // Master detection switch
    bool underAttack = false;                       // Whether node is under attack
    bool entropyBasedDetectionEnabled = true;      // Entropy-based detection
    bool messageValidationEnabled = true;          // Message content validation

    // ==================== DETECTION THRESHOLDS ====================
    double floodThreshold = 50.0;                  // Basic flood detection threshold
    double severeFloodThreshold = 100.0;           // Severe flood threshold
    double burstThreshold = 200.0;                 // Burst attack threshold
    double anomalyThreshold = 2.0;                 // Anomaly detection threshold

    // ==================== TIMING PARAMETERS ====================
    simtime_t detectionWindow = 3.0;               // Primary detection window (3 seconds)
    simtime_t blacklistTimeout = 30.0;             // Blacklist duration (30 seconds)
    simtime_t persistentFloodDuration = 6.0;       // Persistent flood duration (6 seconds)
    simtime_t maxBurstDuration = 1.0;              // Maximum burst duration (1 second)
    simtime_t maxMessageAge = 5.0;                 // Maximum acceptable message age (5 seconds)

    // ==================== BEHAVIORAL PARAMETERS ====================
    int minBurstSize = 50;                         // Minimum messages for burst
    int maxSuspicionLevel = 3;                     // Maximum suspicion level
    double maxReasonableSpeed = 50.0;              // Maximum believable speed (50 m/s = 180 km/h)

    // ==================== ATTACK COUNTERS ====================
    int attackCounter = 0;                         // Attack attempts counter
    int normalPacketsSent = 0;                     // Normal packets sent
    int attackPacketsSent = 0;                     // Attack packets sent
    int packetsReceived = 0;                       // Total packets received
    int attacksDetected = 0;                       // Successful detections

    // ==================== NETWORK METRICS ====================
    simtime_t totalEndToEndDelay = 0.0;            // Cumulative delay
    simtime_t totalJitterTime = 0.0;               // Cumulative jitter
    int jitterCount = 0;                           // Jitter samples count
    double totalBytesReceived = 0.0;               // Total bytes received
    int packetsSent = 0;                           // Total packets sent
    simtime_t lastArrivalTime = -1.0;              // Last packet arrival time
    simtime_t lastInterArrivalTime = -1.0;         // Last inter-arrival time
    simtime_t lastThroughputTime = 0.0;            // Last throughput calculation

    // ==================== DETECTION COMPONENTS ====================
    std::map<int, MessageCounter> messageCounters; // Per-sender counters
    DetectionStatistics detectionStats;            // Detection statistics

    // ==================== MESSAGE TRACKING ====================
    std::map<int, int> receivedMessages;           // Messages received per sender
    int packetsInWindow = 0;                       // Packets in current window
    simtime_t lastWindowStart = 0.0;               // Last window start time
    simtime_t attackDetectedAt = -1.0;             // When attack was detected

    // ==================== TIMERS ====================
    cMessage* attackTimer = nullptr;               // Attack scheduling timer
    cMessage* evasiveTimer = nullptr;              // Evasive action timer

    // ==================== STATISTICS ====================
    cOutVector packetsSentVector;                  // Packets sent over time
    cOutVector packetsReceivedVector;              // Packets received over time
    cOutVector endToEndDelayVector;                // End-to-end delay
    cOutVector jitterVector;                       // Jitter measurements
    cOutVector throughputVector;                   // Throughput over time
    cOutVector detectionRateVector;                // Detection rate over time
    cOutVector falsePositiveVector;                // False positives over time

    // Static members for global tracking
    static std::map<long, DeliveryInfo> globalPacketMap;    // Global packet delivery info
    static long nextPacketId;                               // Next packet ID

protected:
    // ==================== CORE APPLICATION METHODS ====================
    virtual void initialize(int stage) override;
    virtual void finish() override;
    virtual void handleSelfMsg(cMessage* msg) override;
    virtual void handleLowerMsg(cMessage* msg) override;
    virtual void onWSM(BaseFrame1609_4* wsm) override;
    virtual void handlePositionUpdate(cObject* obj) override;

    // ==================== MESSAGE MANAGEMENT ====================
    void populateMyMsg(MyMsg* msg, bool attackPacket = false);
    void changeNodeColor(const char* color);

    // ==================== ENHANCED DETECTION METHODS ====================

    // Primary detection methods
    bool isFloodAttacker(int senderId);
    void updateMessageCounter(int senderId);
    bool detectMaliciousBehavior(MyMsg* msg);

    // Advanced detection algorithms
    bool detectBurstAttack(const MessageCounter& counter);
    bool detectAnomalousTraffic(int senderId, double currentRate);
    bool validateMessageContent(MyMsg* msg);

    // Attack response methods
    void takeEvasiveAction();
    void endEvasiveAction();

public:
    // Constructor/Destructor
    MyVeinsApp();
    virtual ~MyVeinsApp();

    // Simulation parameters (to be set from NED file)
    int totalDefenders = 16;                     // Total non-attacking nodes
    int totalAttackers = 8;                      // Total attacking nodes

    // Attack type
    std::string attackType = "none";             // Type of attack for malicious nodes
};

} // namespace veins

#endif // MYVEINSAPP_H
