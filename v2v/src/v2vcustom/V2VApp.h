#ifndef __V2V_V2VAPP_H__
#define __V2V_V2VAPP_H__

#include <random>
#include <vector>
#include <string>
#include "inet/common/INETDefs.h"
#include "inet/applications/base/ApplicationBase.h"
#include "inet/transportlayer/contract/udp/UdpSocket.h"
#include "inet/mobility/contract/IMobility.h"

using namespace inet;

class V2VApp : public ApplicationBase
{
  private:
    // UDP socket
    UdpSocket socket;
    int localPort = -1;
    int destPort = -1;
    L3Address destAddr;

    // Timers
    cMessage* sendTimer = nullptr;
    cMessage* evasiveTimer = nullptr;

    // Parameters
    simtime_t sendInterval;
    bool malicious = false;
    std::string attackType;
    std::string spoofedSourceId;
    double dataManipulationProbability = 0.0;
    bool enableEvasiveAction = true;
    double evasiveActionDuration = 5.0;

    // Counters and metrics
    int attackCounter = 0;
    long packetsSent = 0;
    long packetsReceived = 0;
    long packetsDropped = 0;
    long packetsManipulated = 0;
    long packetsReplayed = 0;
    long helloFloodPackets = 0;
    long sybilIdentitiesUsed = 0;
    long burstPacketsSent = 0;
    long evasiveActionsTaken = 0;

    // Random generator for attacks
    std::mt19937 randomGenerator;

    // Mobility and state
    Coord originalSpeed;
    bool isEmergencyMessageDetected = false;

    // Signals for statistics
    simsignal_t packetsSentSignal;
    simsignal_t packetsReceivedSignal;
    simsignal_t packetsDroppedSignal;
    simsignal_t packetsManipulatedSignal;
    simsignal_t packetsReplayedSignal;
    simsignal_t helloFloodPacketsSignal;
    simsignal_t sybilIdentitiesSignal;
    simsignal_t burstPacketsSignal;
    simsignal_t attackEffectivenessSignal;
    simsignal_t evasiveActionsSignal;

  protected:
    virtual void initialize(int stage) override;
    virtual void handleMessageWhenUp(cMessage* msg) override;
    virtual void handleStartOperation(LifecycleOperation* operation) override;
    virtual void handleStopOperation(LifecycleOperation* operation) override;
    virtual void handleCrashOperation(LifecycleOperation* operation) override;
    virtual void finish() override;

  private:
    void sendPacket();
    void receivePacket(Packet* pk);
    void processPacketForEvasiveAction(Packet* pk);
    bool isMaliciousPattern(const std::vector<uint8_t>& data);
    bool isEmergencyMessage(const std::vector<uint8_t>& data);
    bool isCollisionWarning(const std::vector<uint8_t>& data);
    void takeEvasiveAction();
    void endEvasiveAction();

  public:
    virtual ~V2VApp();
};

#endif
