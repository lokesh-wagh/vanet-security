#include "veins/modules/application/traci/MyVeinsApp.h"
#include <random>

using namespace veins;

Define_Module(veins::MyVeinsApp);

void MyVeinsApp::initialize(int stage) {
    DemoBaseApplLayer::initialize(stage);
    if (stage == 0) {
        malicious = par("malicious");
        attackType = par("attackType").stdstringValue();

        attackCounter = 0;
        normalPacketsSent = 0;
        attackPacketsSent = 0;
        packetsReceived = 0;
        attacksDetected = 0;
        underAttack = false;

        if (malicious) {
            attackTimer = new cMessage("attackTimer");
            scheduleAt(simTime() + par("attackInterval").doubleValue(), attackTimer);
            EV_INFO << "MALICIOUS: " << getParentModule()->getFullName() << " | Type: " << attackType << endl;
            changeNodeColor("red");
            bubble("ATTACKER");
        } else {
            EV_INFO << "NORMAL: " << getParentModule()->getFullName() << endl;
            changeNodeColor("green");
        }
    }
}

void MyVeinsApp::changeNodeColor(const char* color) {
    cDisplayString& dispStr = getParentModule()->getDisplayString();
    dispStr.setTagArg("i", 1, color);
}

void MyVeinsApp::detectMaliciousBehavior(DemoSafetyMessage* msg) {
    bool detected = false;

    // FLOOD DETECTION: Check for impossible speeds (simplified approach)
    Coord senderSpeed = msg->getSenderSpeed();
    if (senderSpeed.length() > 100) {  // 100 m/s = 360 km/h (impossible for cars)
        EV_INFO << "FLOOD DETECTED: " << getParentModule()->getFullName()
                << " | Impossible speed: " << senderSpeed.length() << " m/s" << endl;
        detected = true;
    }

    // SPOOF DETECTION: Impossible positions
    Coord senderPos = msg->getSenderPos();
    if (senderPos.x > 5000 || senderPos.y > 5000 || senderPos.x < 0 || senderPos.y < 0) {
        EV_INFO << "SPOOF DETECTED: " << getParentModule()->getFullName()
                << " | Impossible position: (" << senderPos.x << ", " << senderPos.y << ")" << endl;
        detected = true;
    }

    // REPLAY DETECTION: Inconsistent speed data
    if (curSpeed.length() < 1 && senderSpeed.length() > 50) {
        EV_INFO << "REPLAY DETECTED: " << getParentModule()->getFullName()
                << " | Inconsistent speed data" << endl;
        detected = true;
    }

    if (detected) {
        attacksDetected++;
        takeEvasiveAction();
    }
}

void MyVeinsApp::takeEvasiveAction() {
    if (!underAttack) {
        underAttack = true;
        attackDetectedAt = simTime();
        changeNodeColor("yellow");
        bubble("UNDER ATTACK!");
        EV_INFO << "EVASIVE ACTION: " << getParentModule()->getFullName() << " taking defensive measures" << endl;

        evasiveTimer = new cMessage("evasiveTimer");
        scheduleAt(simTime() + 5, evasiveTimer);
    }
}

void MyVeinsApp::endEvasiveAction() {
    underAttack = false;
    changeNodeColor("green");
    bubble("SAFE");
    EV_INFO << "RECOVERED: " << getParentModule()->getFullName() << " back to normal" << endl;
}

void MyVeinsApp::onWSM(BaseFrame1609_4* wsm) {
    packetsReceived++;
    if (auto safetyMsg = dynamic_cast<DemoSafetyMessage*>(wsm)) {
        if (!malicious && !underAttack) {
            detectMaliciousBehavior(safetyMsg);
        }
    }
}

void MyVeinsApp::handleSelfMsg(cMessage* msg) {
    if (msg == attackTimer && malicious) {
        attackCounter++;

        if (attackType == "flood") {
            // FLOOD: Send messages with impossible speeds
            for (int i = 0; i < 20; i++) {
                DemoSafetyMessage* floodMsg = new DemoSafetyMessage();
                populateWSM(floodMsg);
                floodMsg->setSenderPos(curPosition);
                floodMsg->setSenderSpeed(Coord(150 + i, 0));  // High speeds for flood detection
                sendDown(floodMsg);
                attackPacketsSent++;
            }
            EV_INFO << "FLOOD #" << attackCounter << " from " << getParentModule()->getFullName()
                    << " | Sent 20 high-speed packets" << endl;

        } else if (attackType == "spoof") {
            // SPOOF: Send fake identity
            DemoSafetyMessage* spoofMsg = new DemoSafetyMessage();
            populateWSM(spoofMsg);
            spoofMsg->setSenderPos(Coord(7000, 7000));
            spoofMsg->setSenderSpeed(Coord(0, 0));
            sendDown(spoofMsg);
            attackPacketsSent++;
            EV_INFO << "SPOOF #" << attackCounter << " from " << getParentModule()->getFullName()
                    << " | Fake identity with impossible position" << endl;

        } else if (attackType == "replay") {
            // REPLAY: Send old position data
            DemoSafetyMessage* replayMsg = new DemoSafetyMessage();
            populateWSM(replayMsg);
            replayMsg->setSenderPos(curPosition - Coord(500, 500));
            replayMsg->setSenderSpeed(Coord(100, 0));
            sendDown(replayMsg);
            attackPacketsSent++;
            EV_INFO << "REPLAY #" << attackCounter << " from " << getParentModule()->getFullName()
                    << " | Old position data" << endl;
        }

        bubble("ATTACKING");
        scheduleAt(simTime() + par("attackInterval").doubleValue(), attackTimer);

    } else if (msg == evasiveTimer) {
        endEvasiveAction();

    } else {
        // Normal beacon
        DemoSafetyMessage* normalMsg = new DemoSafetyMessage();
        populateWSM(normalMsg);
        normalMsg->setSenderPos(curPosition);
        normalMsg->setSenderSpeed(curSpeed);
        sendDown(normalMsg);
        normalPacketsSent++;
        DemoBaseApplLayer::handleSelfMsg(msg);
    }
}

void MyVeinsApp::handlePositionUpdate(cObject* obj) {
    DemoBaseApplLayer::handlePositionUpdate(obj);

    // Slow down if under attack
    if (underAttack && mobility->getSpeed() > 5) {
        traciVehicle->setSpeed(5);
    }
}

void MyVeinsApp::finish() {
    if (malicious) {
        EV_INFO << "ATTACKER SUMMARY - " << getParentModule()->getFullName()
                << " | Attacks: " << attackCounter << " | Attack Packets: " << attackPacketsSent
                << " | Normal Packets: " << normalPacketsSent << endl;
    } else {
        EV_INFO << "DEFENDER SUMMARY - " << getParentModule()->getFullName()
                << " | Detections: " << attacksDetected << " | Packets Sent: " << normalPacketsSent
                << " | Packets Received: " << packetsReceived << endl;
    }

    if (attackTimer) cancelAndDelete(attackTimer);
    if (evasiveTimer) cancelAndDelete(evasiveTimer);
    DemoBaseApplLayer::finish();
}
