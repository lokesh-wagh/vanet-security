#ifndef V2VAPP_H
#define V2VAPP_H

#include <omnetpp.h>
#include "veins/base/utils/Coord.h"
#include "veins/modules/messages/BaseFrame1609_4_m.h"
#include "veins/modules/messages/DemoSafetyMessage_m.h"
#include <random>
#include <vector>
#include <string>

using namespace omnetpp;

class V2VApp : public cSimpleModule
{
public:
    virtual void initialize() override;
    virtual void handleMessage(cMessage* msg) override;
    virtual void finish() override;

protected:
    // Timers
    cMessage* sendTimer = nullptr;
    cMessage* evasiveTimer = nullptr;

    // Attack parameters
    bool malicious = false;
    std::string attackType;
    int attackCounter = 0;

    // Additional attack parameters
    std::string spoofedSourceId;
    double dataManipulationProbability = 0.0;

    // Evasive action parameters
    bool enableEvasiveAction = false;
    double evasiveActionDuration = 0.0;

    // Metrics and statistics
    int packetsSent = 0;
    int packetsReceived = 0;
    int packetsDropped = 0;
    int packetsManipulated = 0;
    int packetsReplayed = 0;
    int helloFloodPackets = 0;
    int sybilIdentitiesUsed = 0;
    int burstPacketsSent = 0;
    int evasiveActionsTaken = 0;

    // Random generator
    std::default_random_engine randomGenerator;

    // Current position and speed
    veins::Coord curPosition;
    veins::Coord curSpeed;

private:
    void sendPacket();
    void receivePacket(cMessage* msg);
    void processPacketForEvasiveAction(veins::BaseFrame1609_4* frame);
    bool isImpossiblePosition(const veins::Coord& pos);
    bool isImpossibleSpeed(const veins::Coord& speed);
    bool isSuddenPositionChange(const veins::Coord& pos, const veins::Coord& speed);
    void takeEvasiveAction();
    void endEvasiveAction();

    // Statistics
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
};

#endif
