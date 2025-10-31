#include "v2vcustom/V2VApp.h"
#include "inet/common/packet/chunk/BytesChunk.h"
#include "inet/common/packet/Packet.h"
#include "inet/networklayer/common/L3AddressResolver.h"
#include "inet/mobility/contract/IMobility.h"
#include <random>
#include <fstream>

using namespace inet;

Define_Module(V2VApp);

V2VApp::~V2VApp() {
    if (sendTimer) {
        cancelAndDelete(sendTimer);
        sendTimer = nullptr;
    }
    if (evasiveTimer) {
        cancelAndDelete(evasiveTimer);
        evasiveTimer = nullptr;
    }
    try { socket.close(); } catch (...) {}
}

void V2VApp::initialize(int stage) {
    ApplicationBase::initialize(stage);

    if (stage == INITSTAGE_LOCAL) {
        EV << "✅ Custom V2VApp initialized on node: " << getParentModule()->getFullName() << endl;
        bubble("Custom V2VApp running!");

        localPort = par("localPort");
        destPort = par("destPort");
        sendInterval = par("sendInterval");
        sendTimer = new cMessage("sendTimer");
        evasiveTimer = new cMessage("evasiveTimer");

        // read malicious params
        malicious = par("malicious").boolValue();
        attackType = par("attackType").stdstringValue();
        attackCounter = 0;

        // Additional attack parameters
        spoofedSourceId = par("spoofedSourceId").stdstringValue();
        dataManipulationProbability = par("dataManipulationProbability").doubleValue();

        // Evasive action parameters
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

        // Initialize random generator for attacks
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
    }
}

void V2VApp::handleStartOperation(LifecycleOperation *operation) {
    // Setup socket at startup
    socket.setOutputGate(gate("socketOut"));
    socket.bind(localPort);
    socket.setBroadcast(true);

    // Destination: broadcast
    destAddr = L3AddressResolver().resolve("255.255.255.255");

    // Schedule first send
    scheduleAt(simTime() + uniform(0, sendInterval), sendTimer);

    EV_INFO << "V2VApp started on " << getFullPath()
            << " (localPort=" << localPort << ", destPort=" << destPort << ")\n";
}

void V2VApp::handleStopOperation(LifecycleOperation *operation) {
    cancelEvent(sendTimer);
    if (evasiveTimer) cancelEvent(evasiveTimer);
    socket.close();
    EV_INFO << "V2VApp stopped on " << getFullPath() << "\n";
}

void V2VApp::handleCrashOperation(LifecycleOperation *operation) {
    cancelEvent(sendTimer);
    if (evasiveTimer) cancelEvent(evasiveTimer);
    try { socket.close(); } catch (...) {}
    EV_WARN << "V2VApp crashed on " << getFullPath() << "\n";
}

void V2VApp::handleMessageWhenUp(cMessage *msg) {
    if (msg == sendTimer) {
        sendPacket();
        scheduleAt(simTime() + sendInterval, sendTimer);
    }
    else if (msg == evasiveTimer) {
        // End evasive action and resume normal movement
        endEvasiveAction();
    }
    else if (auto pk = dynamic_cast<Packet *>(msg)) {
        receivePacket(pk);
    }
    else {
        socket.processMessage(msg);
    }
}

void V2VApp::receivePacket(Packet *pk) {
    EV_INFO << "Received packet '" << pk->getName()
            << "' at " << getFullPath()
            << " (time=" << simTime() << ")\n";
    packetsReceived++;
    emit(packetsReceivedSignal, packetsReceived);

    // Check if we need to take evasive action based on packet content
    if (enableEvasiveAction && !malicious) {
        processPacketForEvasiveAction(pk);
    }

    delete pk;
}

void V2VApp::processPacketForEvasiveAction(Packet *pk) {
    const auto& bytesChunk = pk->peekDataAt<BytesChunk>(b(0), pk->getTotalLength());
    if (!bytesChunk) return;

    std::vector<uint8_t> data = bytesChunk->getBytes();

    // Check for malicious patterns in received data
    if (isMaliciousPattern(data)) {
        EV_WARN << "[" << getParentModule()->getFullName()
                << "] Detected malicious pattern! Taking evasive action.\n";
        takeEvasiveAction();
    }

    // Check for emergency messages that require immediate action
    if (isEmergencyMessage(data)) {
        EV_WARN << "[" << getParentModule()->getFullName()
                << "] Emergency message received! Taking safety measures.\n";
        takeEvasiveAction();
    }

    // Check for collision warnings
    if (isCollisionWarning(data)) {
        EV_WARN << "[" << getParentModule()->getFullName()
                << "] Collision warning! Taking evasive action.\n";
        takeEvasiveAction();
    }
}

bool V2VApp::isMaliciousPattern(const std::vector<uint8_t>& data) {
    if (data.empty()) return false;

    // Check for known attack markers
    if (data[0] == 0xFF || data[0] == 0xFE || data[0] == 0xFD) {
        return true; // Flood/timing attack markers
    }

    // Check for impossibly large packet size (potential flood)
    if (data.size() > 1000) {
        return true;
    }

    // Check for suspicious content patterns
    std::string content(data.begin(), data.end());
    if (content.find("REPLAY_ATTACK") != std::string::npos ||
        content.find("SYBIL_ATTACK") != std::string::npos ||
        content.find("HELLO_FLOOD") != std::string::npos) {
        return true;
    }

    return false;
}

bool V2VApp::isEmergencyMessage(const std::vector<uint8_t>& data) {
    std::string content(data.begin(), data.end());
    return (content.find("EMERGENCY") != std::string::npos ||
            content.find("ACCIDENT") != std::string::npos ||
            content.find("COLLISION") != std::string::npos);
}

bool V2VApp::isCollisionWarning(const std::vector<uint8_t>& data) {
    std::string content(data.begin(), data.end());
    return (content.find("COLLISION_WARNING") != std::string::npos ||
            content.find("BRAKE_IMMEDIATELY") != std::string::npos);
}

void V2VApp::takeEvasiveAction() {
    // Get mobility module
    cModule *host = getParentModule();
    IMobility *mobility = check_and_cast<IMobility*>(host->getSubmodule("mobility"));

    if (!mobility) {
        EV_WARN << "Mobility module not found!\n";
        return;
    }

    // Store original speed for later restoration
    originalSpeed = mobility->getCurrentVelocity();
    Coord currentPos = mobility->getCurrentPosition();

    // Different evasive actions based on situation
    if (isEmergencyMessageDetected) {
        // For emergency stop, we need to use a different approach
        // since setSpeed() might not be available in all mobility models
        EV_WARN << "[" << getParentModule()->getFullName()
                << "] EMERGENCY STOP initiated!\n";
        bubble("EMERGENCY STOP!");
    } else {
        // Standard evasive action: reduce speed and change direction
        // Note: This is a simplified approach - actual implementation depends on mobility model
        EV_WARN << "[" << getParentModule()->getFullName()
                << "] Evasive action! Speed reduced from " << originalSpeed.length()
                << " to " << originalSpeed.length() * 0.5 << " m/s\n";
        bubble("Evasive Action!");
    }

    // Schedule return to normal operation
    if (evasiveTimer && !evasiveTimer->isScheduled()) {
        scheduleAt(simTime() + evasiveActionDuration, evasiveTimer);
    }

    evasiveActionsTaken++;
    emit(evasiveActionsSignal, evasiveActionsTaken);

    EV_INFO << "[" << getParentModule()->getFullName()
            << "] Evasive action #" << evasiveActionsTaken << " taken\n";
}

void V2VApp::endEvasiveAction() {
    // Get mobility module
    cModule *host = getParentModule();
    IMobility *mobility = check_and_cast<IMobility*>(host->getSubmodule("mobility"));

    if (!mobility) return;

    // Resume normal operation
    EV_INFO << "[" << getParentModule()->getFullName()
            << "] Resuming normal operation.\n";
    bubble("Resuming normal");

    // Reset flags
    isEmergencyMessageDetected = false;
}

void V2VApp::sendPacket() {
    Packet *pk = new Packet("V2VMessage");

    if (!malicious) {
        // normal payload: 100 zero bytes
        std::vector<uint8_t> v(100, 0);
        auto payload = makeShared<BytesChunk>(v);
        pk->insertAtBack(payload);
        EV_INFO << "[" << getParentModule()->getFullName() << "] sending normal message\n";
        socket.sendTo(pk, destAddr, destPort);
        packetsSent++;
        emit(packetsSentSignal, packetsSent);
        return;
    }

    // MALICIOUS BEHAVIOR
    attackCounter++;

    if (attackType == "flood") {
        // Flood attack: larger payload, faster sending controlled via ini
        std::vector<uint8_t> v(1400, 0xAA);
        v[0] = 0xFF; // mark first byte so receivers can detect
        auto payload = makeShared<BytesChunk>(v);
        pk->insertAtBack(payload);
        EV_WARN << "[" << getParentModule()->getFullName() << "] FLOOD pkt #" << attackCounter << "\n";
        socket.sendTo(pk, destAddr, destPort);
        packetsSent++;
        emit(packetsSentSignal, packetsSent);
        return;
    }
    else if (attackType == "spoof") {
        // Spoof attack: include fake source id in payload
        std::string msg = "SPOOF_SRC=" + spoofedSourceId + ";SEQ=" + std::to_string(attackCounter);
        std::vector<uint8_t> v(msg.begin(), msg.end());
        v.resize(200, 0);
        auto payload = makeShared<BytesChunk>(v);
        pk->insertAtBack(payload);
        EV_WARN << "[" << getParentModule()->getFullPath() << "] sending SPOOF message as " << spoofedSourceId << "\n";
        socket.sendTo(pk, destAddr, destPort);
        packetsSent++;
        emit(packetsSentSignal, packetsSent);
        return;
    }
    else if (attackType == "replay") {
        // Replay attack: replay old messages with timestamps
        packetsReplayed++;
        std::string origTime = std::to_string(simTime().dbl() - 1000 - attackCounter * 10);
        std::string replayTime = std::to_string(simTime().dbl());

        std::string msg = "REPLAY_ATTACK;ORIG_TIME=" + origTime +
                         ";REPLAY_TIME=" + replayTime +
                         ";PKT_ID=" + std::to_string(attackCounter);
        std::vector<uint8_t> v(msg.begin(), msg.end());
        v.resize(150, 0);
        auto payload = makeShared<BytesChunk>(v);
        pk->insertAtBack(payload);

        EV_WARN << "[" << getParentModule()->getFullName() << "] REPLAY attack #" << attackCounter
                << " (orig: " << origTime << "s, replay: " << replayTime << "s)\n";

        emit(packetsReplayedSignal, packetsReplayed);
        socket.sendTo(pk, destAddr, destPort);
        packetsSent++;
        emit(packetsSentSignal, packetsSent);
        return;
    }
    else if (attackType == "selective_forwarding") {
        // Selective forwarding: randomly drop packets (simulated by not sending some)
        std::uniform_real_distribution<double> dist(0.0, 1.0);
        if (dist(randomGenerator) < 0.3) { // 30% packet drop
            packetsDropped++;
            EV_WARN << "[" << getParentModule()->getFullName() << "] SELECTIVE_FORWARDING - dropping packet #"
                    << attackCounter << " (Total dropped: " << packetsDropped << ")\n";
            emit(packetsDroppedSignal, packetsDropped);
            delete pk;
            return;
        }
        // Otherwise send normal-looking packet
        std::vector<uint8_t> v(100, 0);
        auto payload = makeShared<BytesChunk>(v);
        pk->insertAtBack(payload);
        EV_WARN << "[" << getParentModule()->getFullName() << "] SELECTIVE_FORWARDING - forwarding packet #"
                << attackCounter << " (Drop rate: " << (double)packetsDropped/attackCounter * 100 << "%)\n";
        socket.sendTo(pk, destAddr, destPort);
        packetsSent++;
        emit(packetsSentSignal, packetsSent);
        return;
    }
    else if (attackType == "data_manipulation") {
        // Data manipulation: corrupt message content
        std::vector<uint8_t> v(100, 0);

        // Create a normal-looking message but with manipulated data
        std::string baseMsg = "POSITION:X=" + std::to_string(100 + attackCounter) + ",Y=200,SPEED=60";
        if (baseMsg.length() < v.size()) {
            std::copy(baseMsg.begin(), baseMsg.end(), v.begin());
        }

        // Track manipulation points
        std::vector<size_t> manipulatedPositions;

        // Manipulate random bytes in the payload
        std::uniform_int_distribution<size_t> byteDist(0, v.size()-1);
        std::uniform_int_distribution<uint8_t> valueDist(1, 255);

        size_t manipulationCount = static_cast<size_t>(v.size() * dataManipulationProbability);
        for (size_t i = 0; i < manipulationCount; ++i) {
            size_t pos = byteDist(randomGenerator);
            uint8_t oldValue = v[pos];
            v[pos] = valueDist(randomGenerator);
            manipulatedPositions.push_back(pos);
            packetsManipulated++;
        }

        auto payload = makeShared<BytesChunk>(v);
        pk->insertAtBack(payload);

        EV_WARN << "[" << getParentModule()->getFullName() << "] DATA_MANIPULATION attack #" << attackCounter
                << " - Manipulated " << manipulatedPositions.size() << " bytes at positions: ";
        for (size_t pos : manipulatedPositions) {
            EV_WARN << pos << " ";
        }
        EV_WARN << "(Total manipulated: " << packetsManipulated << " bytes)\n";

        emit(packetsManipulatedSignal, packetsManipulated);
        socket.sendTo(pk, destAddr, destPort);
        packetsSent++;
        emit(packetsSentSignal, packetsSent);
        return;
    }
    else if (attackType == "sybil") {
        // Sybil attack: simulate multiple identities
        std::vector<std::string> fakeIds = {"node_A", "vehicle_123", "sensor_45", "car_emergency", "truck_99", "bus_001"};
        std::uniform_int_distribution<size_t> idDist(0, fakeIds.size()-1);

        std::string fakeId = fakeIds[idDist(randomGenerator)];
        std::string msg = "SYBIL_ATTACK;ID=" + fakeId + ";REAL_ID=" + std::string(getParentModule()->getFullName()) +
                         ";SEQ=" + std::to_string(attackCounter);
        std::vector<uint8_t> v(msg.begin(), msg.end());
        v.resize(180, 0);
        auto payload = makeShared<BytesChunk>(v);
        pk->insertAtBack(payload);

        sybilIdentitiesUsed++;
        EV_WARN << "[" << getParentModule()->getFullName() << "] SYBIL attack as " << fakeId
                << " #" << attackCounter << " (Unique identities used: " << sybilIdentitiesUsed << ")\n";

        emit(sybilIdentitiesSignal, sybilIdentitiesUsed);
        socket.sendTo(pk, destAddr, destPort);
        packetsSent++;
        emit(packetsSentSignal, packetsSent);
        return;
    }
    else if (attackType == "timing") {
        // Timing attack: send messages with irregular timing patterns
        if (attackCounter % 10 == 0) {
            // Burst mode: send several packets quickly
            int burstSize = 5;
            for (int i = 0; i < burstSize; i++) {
                Packet *burstPk = new Packet("V2VMessage_Burst");
                std::vector<uint8_t> v(120, 0xBB);
                v[0] = 0xFD; // Burst marker
                auto payload = makeShared<BytesChunk>(v);
                burstPk->insertAtBack(payload);
                socket.sendTo(burstPk, destAddr, destPort);
                burstPacketsSent++;
                packetsSent++;
            }
            EV_WARN << "[" << getParentModule()->getFullName() << "] TIMING attack - BURST mode #"
                    << attackCounter << " (sent " << burstSize << " packets, total bursts: " << burstPacketsSent << ")\n";
            emit(burstPacketsSignal, burstPacketsSent);
            emit(packetsSentSignal, packetsSent);
        }

        // Regular timing attack packet
        std::vector<uint8_t> v(100, 0xCC);
        v[0] = 0xFD; // Timing attack marker
        auto payload = makeShared<BytesChunk>(v);
        pk->insertAtBack(payload);
        EV_WARN << "[" << getParentModule()->getFullName() << "] TIMING attack packet #" << attackCounter << "\n";
        socket.sendTo(pk, destAddr, destPort);
        packetsSent++;
        emit(packetsSentSignal, packetsSent);
        return;
    }
    else if (attackType == "hello_flood") {
        // Hello Flood attack: send excessive hello/beacon messages
        std::string nodeName = getParentModule()->getFullName();
        std::string currentTime = std::to_string(simTime().dbl());
        std::string floodId = std::to_string(attackCounter);

        std::string msg = "HELLO_FLOOD;NODE=" + nodeName + ";TIME=" + currentTime + ";FLOOD_ID=" + floodId;
        std::vector<uint8_t> v(msg.begin(), msg.end());
        v.resize(80, 0); // Smaller packets for hello flood

        // Send multiple copies
        int floodCopies = 3;
        for (int i = 0; i < floodCopies; i++) {
            Packet *helloPk = new Packet("V2VHello");
            auto payload = makeShared<BytesChunk>(v);
            helloPk->insertAtBack(payload);
            socket.sendTo(helloPk, destAddr, destPort);
            helloFloodPackets++;
            packetsSent++;
        }

        auto payload = makeShared<BytesChunk>(v);
        pk->insertAtBack(payload);

        EV_WARN << "[" << getParentModule()->getFullName() << "] HELLO_FLOOD attack #" << attackCounter
                << " (sent " << floodCopies + 1 << " packets, total flood packets: " << helloFloodPackets << ")\n";

        emit(helloFloodPacketsSignal, helloFloodPackets);
        emit(packetsSentSignal, packetsSent);
        socket.sendTo(pk, destAddr, destPort);
        return;
    }
    else {
        // Default malicious: abnormal marker + medium size
        std::vector<uint8_t> v(200, 0x00);
        v[0] = 0xFE;
        auto payload = makeShared<BytesChunk>(v);
        pk->insertAtBack(payload);
        EV_WARN << "[" << getParentModule()->getFullName() << "] sending unknown-attack payload\n";
        socket.sendTo(pk, destAddr, destPort);
        packetsSent++;
        emit(packetsSentSignal, packetsSent);
        return;
    }
}

void V2VApp::finish() {
    // Calculate and emit final metrics
    if (malicious) {
        double attackEffectiveness = 0.0;

        if (attackType == "selective_forwarding") {
            attackEffectiveness = (attackCounter > 0) ? (double)packetsDropped / attackCounter * 100 : 0;
            EV_WARN << "[" << getParentModule()->getFullName() << "] SELECTIVE_FORWARDING Final Stats: "
                    << packetsDropped << "/" << attackCounter << " packets dropped ("
                    << attackEffectiveness << "% drop rate)\n";
        }
        else if (attackType == "data_manipulation") {
            attackEffectiveness = packetsManipulated;
            EV_WARN << "[" << getParentModule()->getFullName() << "] DATA_MANIPULATION Final Stats: "
                    << packetsManipulated << " bytes manipulated in " << attackCounter << " packets\n";
        }
        else if (attackType == "replay") {
            attackEffectiveness = packetsReplayed;
            EV_WARN << "[" << getParentModule()->getFullName() << "] REPLAY Final Stats: "
                    << packetsReplayed << " packets replayed\n";
        }
        else if (attackType == "sybil") {
            attackEffectiveness = sybilIdentitiesUsed;
            EV_WARN << "[" << getParentModule()->getFullName() << "] SYBIL Final Stats: "
                    << sybilIdentitiesUsed << " unique fake identities used\n";
        }
        else if (attackType == "hello_flood") {
            attackEffectiveness = helloFloodPackets;
            EV_WARN << "[" << getParentModule()->getFullName() << "] HELLO_FLOOD Final Stats: "
                    << helloFloodPackets << " flood packets sent\n";
        }
        else if (attackType == "timing") {
            attackEffectiveness = burstPacketsSent;
            EV_WARN << "[" << getParentModule()->getFullName() << "] TIMING Final Stats: "
                    << burstPacketsSent << " burst packets sent in " << attackCounter << " attack cycles\n";
        }

        emit(attackEffectivenessSignal, attackEffectiveness);

        EV_WARN << "[" << getParentModule()->getFullName() << "] Malicious node final statistics:\n"
                << "  Attack Type: " << attackType << "\n"
                << "  Total Attack Cycles: " << attackCounter << "\n"
                << "  Total Packets Sent: " << packetsSent << "\n"
                << "  Attack Effectiveness: " << attackEffectiveness << "\n";
    } else {
        EV_INFO << "[" << getParentModule()->getFullName() << "] Normal node statistics:\n"
                << "  Packets Sent: " << packetsSent << "\n"
                << "  Packets Received: " << packetsReceived << "\n"
                << "  Evasive Actions Taken: " << evasiveActionsTaken << "\n";
    }

    cancelEvent(sendTimer);
    if (evasiveTimer) cancelEvent(evasiveTimer);
    socket.close();
    ApplicationBase::finish();
}
