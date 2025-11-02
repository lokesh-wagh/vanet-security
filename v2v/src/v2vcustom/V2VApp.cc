#include "v2vcustom/V2VApp.h"
#include <random>
#include <fstream>

using namespace veins;

Define_Module(V2VApp);

void V2VApp::initialize() {
    EV << "✅ Custom V2VApp initialized on node: " << getParentModule()->getFullName() << endl;
    bubble("Custom V2VApp running!");

    // Initialize timers
    sendTimer = new cMessage("sendTimer");
    evasiveTimer = new cMessage("evasiveTimer");

    // Read parameters
    malicious = par("malicious").boolValue();
    attackType = par("attackType").stdstringValue();
    attackCounter = 0;

    spoofedSourceId = par("spoofedSourceId").stdstringValue();
    dataManipulationProbability = par("dataManipulationProbability").doubleValue();
    enableEvasiveAction = par("enableEvasiveAction").boolValue();
    evasiveActionDuration = par("evasiveActionDuration").doubleValue();

    // Initialize metrics
    packetsSent = 0;
    packetsReceived = 0;
    packetsDropped = 0;
    packetsManipulated = 0;
    packetsReplayed = 0;
    helloFloodPackets = 0;
    sybilIdentitiesUsed = 0;
    burstPacketsSent = 0;
    evasiveActionsTaken = 0;

    // Initialize random generator
    randomGenerator.seed(std::random_device{}());

    // Initialize statistics
    packetsSentSignal = registerSignal("packetsSent");
    packetsReceivedSignal = registerSignal("packetsReceived");
    packetsDroppedSignal = registerSignal("packetsDropped");
    packetsManipulatedSignal = registerSignal("packetsManipulated");
    packetsReplayedSignal = registerSignal("packetsReplayed");
    helloFloodPacketsSignal = registerSignal("helloFloodPackets");
    sybilIdentitiesSignal = registerSignal("sybilIdentities");
    burstPacketsSignal = registerSignal("burstPackets");
    attackEffectivenessSignal = registerSignal("attackEffectiveness");
    evasiveActionsSignal = registerSignal("evasiveActions");

    if (malicious) {
        EV_WARN << "**** Node " << getParentModule()->getFullName()
                << " configured as MALICIOUS (type=" << attackType << ") ****\n";
        bubble("MALICIOUS");
    } else {
        EV_INFO << "Node " << getParentModule()->getFullName() << " is normal\n";
    }

    // Schedule first message
    simtime_t sendInterval = par("sendInterval");
    scheduleAt(simTime() + sendInterval, sendTimer);
}

void V2VApp::handleMessage(cMessage* msg) {
    if (msg == sendTimer) {
        sendPacket();
        simtime_t sendInterval = par("sendInterval");
        scheduleAt(simTime() + sendInterval, sendTimer);
    }
    else if (msg == evasiveTimer) {
        endEvasiveAction();
    }
    else {
        receivePacket(msg);
    }
}

void V2VApp::receivePacket(cMessage* msg) {
    EV_INFO << "Received packet at " << getFullPath()
            << " (time=" << simTime() << ")\n";
    packetsReceived++;
    emit(packetsReceivedSignal, packetsReceived);

    // Check if we need to take evasive action based on packet content
    if (enableEvasiveAction && !malicious) {
        if (auto frame = dynamic_cast<BaseFrame1609_4*>(msg)) {
            processPacketForEvasiveAction(frame);
        }
    }

    delete msg;
}

void V2VApp::processPacketForEvasiveAction(BaseFrame1609_4* frame) {
    if (auto safetyMsg = dynamic_cast<DemoSafetyMessage*>(frame)) {
        veins::Coord senderPos = safetyMsg->getSenderPos();
        veins::Coord senderSpeed = safetyMsg->getSenderSpeed();

        // Check for impossible positions or speeds (potential spoofing)
        if (isImpossiblePosition(senderPos) || isImpossibleSpeed(senderSpeed)) {
            EV_WARN << "[" << getParentModule()->getFullName()
                    << "] Detected impossible position/speed! Taking evasive action.\n";
            takeEvasiveAction();
        }
    }
}

bool V2VApp::isImpossiblePosition(const veins::Coord& pos) {
    return (pos.x < -10000 || pos.x > 10000 || pos.y < -10000 || pos.y > 10000);
}

bool V2VApp::isImpossibleSpeed(const veins::Coord& speed) {
    return (speed.length() > 200);
}

bool V2VApp::isSuddenPositionChange(const veins::Coord& pos, const veins::Coord& speed) {
    return false; // Placeholder
}

void V2VApp::takeEvasiveAction() {
    EV_WARN << "[" << getParentModule()->getFullName()
            << "] Taking evasive action!\n";
    bubble("Evasive Action!");

    if (evasiveTimer && !evasiveTimer->isScheduled()) {
        scheduleAt(simTime() + evasiveActionDuration, evasiveTimer);
    }

    evasiveActionsTaken++;
    emit(evasiveActionsSignal, evasiveActionsTaken);
}

void V2VApp::endEvasiveAction() {
    EV_INFO << "[" << getParentModule()->getFullName()
            << "] Resuming normal operation.\n";
    bubble("Resuming normal");
}

void V2VApp::sendPacket() {
    if (!malicious) {
        // Normal behavior - send safety message
        DemoSafetyMessage* safetyMsg = new DemoSafetyMessage("V2V_Normal");
        safetyMsg->setSenderPos(curPosition);
        safetyMsg->setSenderSpeed(curSpeed);

        EV_INFO << "[" << getParentModule()->getFullName() << "] sending normal message\n";
        send(safetyMsg, "lowerLayerOut");
        packetsSent++;
        emit(packetsSentSignal, packetsSent);
        return;
    }

    // MALICIOUS BEHAVIOR
    attackCounter++;

    if (attackType == "flood") {
        // Flood attack: send multiple messages quickly
        for (int i = 0; i < 3; i++) {
            DemoSafetyMessage* floodMsg = new DemoSafetyMessage("V2V_Flood");
            floodMsg->setSenderPos(veins::Coord(9999 + i, 9999 + i));
            floodMsg->setSenderSpeed(veins::Coord(300, 0));

            send(floodMsg, "lowerLayerOut");
            packetsSent++;
        }
        EV_WARN << "[" << getParentModule()->getFullName() << "] FLOOD pkt #" << attackCounter << "\n";
        emit(packetsSentSignal, packetsSent);
    }
    else if (attackType == "spoof") {
        // Spoof attack
        DemoSafetyMessage* spoofMsg = new DemoSafetyMessage("V2V_Spoof");
        spoofMsg->setSenderPos(veins::Coord(8888, 8888));
        spoofMsg->setSenderSpeed(veins::Coord(250, 0));

        EV_WARN << "[" << getParentModule()->getFullPath() << "] sending SPOOF message\n";
        send(spoofMsg, "lowerLayerOut");
        packetsSent++;
        emit(packetsSentSignal, packetsSent);
    }
}

void V2VApp::finish() {
    if (malicious) {
        double attackEffectiveness = packetsSent;
        emit(attackEffectivenessSignal, attackEffectiveness);
        EV_WARN << "[" << getParentModule()->getFullName() << "] Malicious node final statistics:\n"
                << "  Attack Type: " << attackType << "\n"
                << "  Total Attack Cycles: " << attackCounter << "\n"
                << "  Total Packets Sent: " << packetsSent << "\n";
    } else {
        EV_INFO << "[" << getParentModule()->getFullName() << "] Normal node statistics:\n"
                << "  Packets Sent: " << packetsSent << "\n"
                << "  Packets Received: " << packetsReceived << "\n"
                << "  Evasive Actions Taken: " << evasiveActionsTaken << "\n";
    }

    cancelEvent(sendTimer);
    if (evasiveTimer) cancelEvent(evasiveTimer);
}
