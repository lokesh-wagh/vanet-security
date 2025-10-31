#include "v2vcustom/V2VApp.h"
#include "inet/common/packet/chunk/BytesChunk.h"
#include "inet/common/packet/Packet.h"
#include "inet/networklayer/common/L3AddressResolver.h"

Define_Module(V2VApp);

V2VApp::~V2VApp() {
    if (sendTimer) {
        cancelAndDelete(sendTimer);
        sendTimer = nullptr;
    }
    try { socket.close(); } catch (...) {}
}

void V2VApp::initialize(int stage) {
    ApplicationBase::initialize(stage);

    if (stage == INITSTAGE_LOCAL) {
            EV << "✅ Custom V2VApp initialized on node: " << getParentModule()->getFullName() << endl;
            bubble("Custom V2VApp running!");
        }
    if (stage == INITSTAGE_LOCAL) {
        localPort = par("localPort");
        destPort = par("destPort");
        sendInterval = par("sendInterval");
        sendTimer = new cMessage("sendTimer");

        // read malicious params
        malicious = par("malicious").boolValue();
        attackType = par("attackType").stdstringValue();
        attackCounter = 0;

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
    socket.bind(localPort);              // open() no longer needed in INET 4.5
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
    socket.close();
    EV_INFO << "V2VApp stopped on " << getFullPath() << "\n";
}

void V2VApp::handleCrashOperation(LifecycleOperation *operation) {
    cancelEvent(sendTimer);
    try { socket.close(); } catch (...) {}
    EV_WARN << "V2VApp crashed on " << getFullPath() << "\n";
}

void V2VApp::handleMessageWhenUp(cMessage *msg) {
    if (msg == sendTimer) {
        sendPacket();
        scheduleAt(simTime() + sendInterval, sendTimer);
    }
    else if (auto pk = dynamic_cast<Packet *>(msg)) {
        receivePacket(pk);
    }
    else {
        socket.processMessage(msg);
    }
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
        return;
    }

    // MALICIOUS BEHAVIOR
    attackCounter++;

    if (attackType == "flood") {
        // larger payload, faster sending controlled via ini
        std::vector<uint8_t> v(1400, 0xAA);
        // mark first byte so receivers can detect (optional)
        v[0] = 0xFF;
        auto payload = makeShared<BytesChunk>(v);
        pk->insertAtBack(payload);
        EV_WARN << "[" << getParentModule()->getFullName() << "] FLOOD pkt #" << attackCounter << "\n";
        socket.sendTo(pk, destAddr, destPort);
        return;
    }
    else if (attackType == "spoof") {
        // spoof: include fake source id in payload (application-level spoof)
        std::string msg = "SPOOF_SRC=node_fake_123;";
        std::vector<uint8_t> v(msg.begin(), msg.end());
        // rest zeros
        v.resize(200, 0);
        auto payload = makeShared<BytesChunk>(v);
        pk->insertAtBack(payload);
        EV_WARN << "[" << getParentModule()->getFullPath() << "] sending SPOOF message\n";
        socket.sendTo(pk, destAddr, destPort);
        return;
    }
    else {
        // default malicious: abnormal marker + medium size
        std::vector<uint8_t> v(200, 0x00);
        v[0] = 0xFE;
        auto payload = makeShared<BytesChunk>(v);
        pk->insertAtBack(payload);
        EV_WARN << "[" << getParentModule()->getFullName() << "] sending unknown-attack payload\n";
        socket.sendTo(pk, destAddr, destPort);
        return;
    }
}


void V2VApp::receivePacket(Packet *pk) {
    EV_INFO << "Received packet '" << pk->getName()
            << "' at " << getFullPath()
            << " (time=" << simTime() << ")\n";
    delete pk;
}

void V2VApp::finish() {
    cancelEvent(sendTimer);
    socket.close();
    ApplicationBase::finish();
}
