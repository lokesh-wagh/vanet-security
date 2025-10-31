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
        localPort = par("localPort");
        destPort = par("destPort");
        sendInterval = par("sendInterval");
        sendTimer = new cMessage("sendTimer");
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
    auto pk = new Packet("V2VMessage");
    auto payload = makeShared<BytesChunk>(std::vector<uint8_t>(100, 0));
    pk->insertAtBack(payload);

    EV_INFO << "Sending broadcast message from " << getFullPath()
            << " at " << simTime() << "\n";

    socket.sendTo(pk, destAddr, destPort);
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
