#include "veins/modules/application/traci/MyVeinsApp.h"

using namespace veins;

Define_Module(veins::MyVeinsApp);

void MyVeinsApp::initialize(int stage)
{
    DemoBaseApplLayer::initialize(stage);
    if (stage == 0) {
        malicious = par("malicious");  // FIXED: Remove .boolValue()
        attackType = par("attackType").stdstringValue();

        // Initialize counters
        attackCounter = 0;
        normalPacketsSent = 0;
        attackPacketsSent = 0;
        packetsReceived = 0;

        // Create attack timer for malicious nodes
        if (malicious) {
            attackTimer = new cMessage("attackTimer");
            double attackInterval = par("attackInterval").doubleValue();
            scheduleAt(simTime() + attackInterval, attackTimer);

            EV_WARN << "MALICIOUS NODE ACTIVATED: " << getParentModule()->getFullName()
                    << " | Attack Type: " << attackType
                    << " | Interval: " << attackInterval << "s" << endl;
            bubble("MALICIOUS NODE!");
        } else {
            EV_INFO << "NORMAL NODE: " << getParentModule()->getFullName() << endl;
            bubble("Normal Vehicle");
        }
    }
}

void MyVeinsApp::finish()
{
    // Print final statistics
    if (malicious) {
        EV_WARN << "MALICIOUS NODE SUMMARY - " << getParentModule()->getFullName()
                << " | Total Attacks: " << attackCounter
                << " | Attack Packets: " << attackPacketsSent
                << " | Normal Packets: " << normalPacketsSent << endl;
    } else {
        EV_INFO << "NORMAL NODE SUMMARY - " << getParentModule()->getFullName()
                << " | Packets Sent: " << normalPacketsSent
                << " | Packets Received: " << packetsReceived << endl;
    }

    if (attackTimer) {
        cancelAndDelete(attackTimer);
    }
    DemoBaseApplLayer::finish();
}

void MyVeinsApp::onWSM(BaseFrame1609_4* wsm)
{
    packetsReceived++;

    if (auto safetyMsg = dynamic_cast<DemoSafetyMessage*>(wsm)) {
        EV_INFO << getParentModule()->getFullName()
                << " received safety message | Position: ("
                << safetyMsg->getSenderPos().x << ", " << safetyMsg->getSenderPos().y
                << ") | Speed: " << safetyMsg->getSenderSpeed().length() << " m/s" << endl;

        // Detect malicious patterns in received messages
        if (!malicious) {
            detectMaliciousBehavior(safetyMsg);
        }
    }
}

void MyVeinsApp::detectMaliciousBehavior(DemoSafetyMessage* msg)
{
    Coord senderPos = msg->getSenderPos();
    Coord senderSpeed = msg->getSenderSpeed();

    // Check for impossible positions (spoofing detection)
    if (senderPos.x > 10000 || senderPos.y > 10000 || senderPos.x < -10000 || senderPos.y < -10000) {
        EV_WARN << "DETECTED POSSIBLE SPOOFING: " << getParentModule()->getFullName()
                << " received impossible position (" << senderPos.x << ", " << senderPos.y << ")" << endl;
        bubble("SPOOF DETECTED!");
    }

    // Check for impossible speeds (flooding detection)
    if (senderSpeed.length() > 200) { // 200 m/s = 720 km/h
        EV_WARN << "DETECTED POSSIBLE FLOODING: " << getParentModule()->getFullName()
                << " received impossible speed " << senderSpeed.length() << " m/s" << endl;
        bubble("FLOOD DETECTED!");
    }
}

void MyVeinsApp::onWSA(DemoServiceAdvertisment* wsa)
{
    EV_INFO << getParentModule()->getFullName() << " received service advertisement" << endl;
}

void MyVeinsApp::handleSelfMsg(cMessage* msg)
{
    if (msg == attackTimer && malicious) {
        attackCounter++;

        if (attackType == "flood") {
            // Flood attack: send multiple messages quickly
            for (int i = 0; i < 5; i++) {
                DemoSafetyMessage* floodMsg = new DemoSafetyMessage();
                populateWSM(floodMsg);
                // Set impossible values to mark as attack
                floodMsg->setSenderPos(Coord(9999 + i, 9999 + i)); // Impossible position
                floodMsg->setSenderSpeed(Coord(300, 0));           // Impossible speed (300 m/s)

                sendDown(floodMsg);
                attackPacketsSent++;
            }
            EV_WARN << "FLOOD ATTACK #" << attackCounter << " from " << getParentModule()->getFullName()
                    << " | Sent 5 flood packets | Total: " << attackPacketsSent << endl;
            bubble("FLOOD ATTACK!");

        } else if (attackType == "spoof") {
            // Spoof attack: send fake emergency vehicle information
            DemoSafetyMessage* spoofMsg = new DemoSafetyMessage();
            populateWSM(spoofMsg);
            spoofMsg->setSenderPos(Coord(8888, 8888)); // Fake position far away
            spoofMsg->setSenderSpeed(Coord(0, 0));     // Fake stopped vehicle

            sendDown(spoofMsg);
            attackPacketsSent++;

            EV_WARN << "SPOOF ATTACK #" << attackCounter << " from " << getParentModule()->getFullName()
                    << " | Fake emergency vehicle | Total: " << attackPacketsSent << endl;
            bubble("SPOOF ATTACK!");

        } else if (attackType == "replay") {
            // Replay attack: send old position data
            DemoSafetyMessage* replayMsg = new DemoSafetyMessage();
            populateWSM(replayMsg);
            // Simulate replay by sending position far behind current position
            Coord replayPos = curPosition - Coord(1000, 1000); // 1km behind
            replayMsg->setSenderPos(replayPos);
            replayMsg->setSenderSpeed(curSpeed);

            sendDown(replayMsg);
            attackPacketsSent++;

            EV_WARN << "REPLAY ATTACK #" << attackCounter << " from " << getParentModule()->getFullName()
                    << " | Old position data | Total: " << attackPacketsSent << endl;
            bubble("REPLAY ATTACK!");
        }

        // Schedule next attack
        double attackInterval = par("attackInterval").doubleValue();
        scheduleAt(simTime() + attackInterval, attackTimer);
    }
    else {
        // Handle normal self messages (beacons)
        DemoSafetyMessage* normalMsg = new DemoSafetyMessage();
        populateWSM(normalMsg);
        // Set real position and speed for normal behavior
        normalMsg->setSenderPos(curPosition);
        normalMsg->setSenderSpeed(curSpeed);

        sendDown(normalMsg);
        normalPacketsSent++;

        if (!malicious) {
            EV_INFO << getParentModule()->getFullName()
                    << " sent normal beacon | Position: (" << curPosition.x << ", " << curPosition.y
                    << ") | Total: " << normalPacketsSent << endl;
        }

        DemoBaseApplLayer::handleSelfMsg(msg);
    }
}

void MyVeinsApp::handlePositionUpdate(cObject* obj)
{
    DemoBaseApplLayer::handlePositionUpdate(obj);

    // Print position updates occasionally (every ~10 seconds)
    static simtime_t lastPrint = 0;
    if (simTime() - lastPrint >= 10) {
        EV_INFO << getParentModule()->getFullName()
                << " | Road: " << mobility->getRoadId()
                << " | Position: (" << curPosition.x << ", " << curPosition.y
                << ") | Speed: " << curSpeed.length() << " m/s" << endl;
        lastPrint = simTime();
    }
}
