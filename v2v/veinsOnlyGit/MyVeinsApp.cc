#include "veins/modules/application/traci/MyVeinsApp.h"
#include "veins/modules/messages/MyMsg_m.h"
#include <random>
#include <cmath>

using namespace veins;

// Static member initialization
std::map<long, DeliveryInfo> MyVeinsApp::globalPacketMap;
long MyVeinsApp::nextPacketId = 1;

Define_Module(veins::MyVeinsApp);

// ==================== FLOOD ATTACK PREVENTION ====================

bool MyVeinsApp::isFloodAttacker(int senderId) {
    auto it = messageCounters.find(senderId);
    if (it == messageCounters.end()) {
        return false;
    }

    MessageCounter& counter = it->second;

    // Reset counter if window expired
    if (simTime() - counter.startTime > detectionWindow) {
        counter.count = 0;
        counter.startTime = simTime();
        counter.isBlacklisted = false; // Give another chance
        return false;
    }

    // Check if exceeds threshold
    if (counter.count > floodThreshold) {
        counter.isBlacklisted = true;
        EV_INFO << "BLACKLISTED FLOOD ATTACKER: " << senderId
                << " | Rate: " << counter.count << " msgs/sec" << endl;
        return true;
    }

    return counter.isBlacklisted;
}

void MyVeinsApp::updateMessageCounter(int senderId) {
    auto it = messageCounters.find(senderId);
    if (it == messageCounters.end()) {
        // First message from this sender
        MessageCounter counter;
        counter.count = 1;
        counter.startTime = simTime();
        counter.isBlacklisted = false;
        messageCounters[senderId] = counter;
    } else {
        MessageCounter& counter = it->second;

        // Reset if window expired
        if (simTime() - counter.startTime > detectionWindow) {
            counter.count = 1;
            counter.startTime = simTime();
            counter.isBlacklisted = false;
        } else {
            counter.count++;
        }
    }
}

// ==================== UPDATED handleLowerMsg ====================

void MyVeinsApp::handleLowerMsg(cMessage* msg) {
    if (auto myMsg = dynamic_cast<veins::MyMsg*>(msg)) {
        int receiverId = getParentModule()->getId();
        long packetId = myMsg->getPacketId();
        int senderId = myMsg->getSrcId();
        if (!malicious && detectionEnabled) {
             if(detectMaliciousBehavior(myMsg)){
                 delete msg;
                 return;
             }
         }
        // FLOOD PREVENTION: Check if sender is blacklisted
        if (isFloodAttacker(senderId)) {
            EV_INFO << "DROPPED PACKET from blacklisted flood attacker: " << senderId << endl;
            delete msg;
            return; // REFUSE to accept packet
        }

        // Update message counter for flood detection
        updateMessageCounter(senderId);

        // ========== UPDATE GLOBAL DELIVERY INFO ==========
        auto it = globalPacketMap.find(packetId);
        if (it != globalPacketMap.end()) {
            // Packet exists in global map - add this receiver
            it->second.receivers.insert(receiverId);
            EV_DEBUG << "Updated delivery info for packet " << packetId
                     << " | Receiver: " << receiverId
                     << " | Total receivers: " << it->second.receivers.size() << endl;
        } else {
            // This shouldn't happen normally, but handle gracefully
            EV_INFO << "Received packet " << packetId << " not found in global delivery map" << endl;
            // Optionally create a new entry if packet wasn't tracked
            DeliveryInfo info;
            info.srcId = senderId;
            info.sendTime = myMsg->getTimestamp();
            info.receivers.insert(receiverId);
            globalPacketMap[packetId] = info;
        }
        // ========== END GLOBAL DELIVERY UPDATE ==========

        // Count all packets received
        packetsReceived++;
        packetsInWindow++;

        // Calculate End-to-End Delay
        simtime_t endToEndDelay = simTime() - myMsg->getTimestamp();
        totalEndToEndDelay += endToEndDelay;
        endToEndDelayVector.record(endToEndDelay);

        // Calculate Jitter
        simtime_t currentArrivalTime = simTime();
        if (lastArrivalTime != -1) {
            simtime_t interArrivalTime = currentArrivalTime - lastArrivalTime;
            if (lastInterArrivalTime != -1) {
                simtime_t jitterDiff = interArrivalTime - lastInterArrivalTime;
                totalJitterTime += (jitterDiff > 0 ? jitterDiff : -jitterDiff);
                jitterCount++;
                jitterVector.record(jitterDiff);
            }
            lastInterArrivalTime = interArrivalTime;
        }
        lastArrivalTime = currentArrivalTime;

        // Log reception details (optional - can be verbose)
        if (packetsReceived % 20 == 0) { // Log every 20th packet to reduce spam
            EV_INFO << "Received MyMsg #" << packetsReceived
                    << " from " << senderId
                    << " | Delay: " << endToEndDelay * 1000 << "ms"
                    << " | Packet ID: " << packetId << endl;
        }

        // Update throughput calculation
        totalBytesReceived += myMsg->getByteLength();

        // Store message info for statistics
        receivedMessages[myMsg->getSrcId()]++;




    } else {
        EV_INFO << "Received non-MyMsg packet: " << msg->getClassName() << endl;
    }

    delete msg;
}

// ==================== UPDATED populateMyMsg ====================

void MyVeinsApp::populateMyMsg(MyMsg* msg , bool attackPacket) {
    msg->setSrcId(getParentModule()->getId());
    msg->setDestId(-1);
    msg->setTimestamp(simTime());

    // Set unique packet ID
    long packetId = nextPacketId++;
    msg->setPacketId(packetId);

    // Track this packet in global map
    if(!attackPacket){
        DeliveryInfo info;
       info.srcId = getParentModule()->getId();
       info.sendTime = simTime();
       globalPacketMap[packetId] = info;
    }



    // Set position and speed
    msg->setSenderPosX(curPosition.x);
    msg->setSenderPosY(curPosition.y);
    msg->setSenderSpeedX(curSpeed.x);
    msg->setSenderSpeedY(curSpeed.y);

    msg->setRecipientAddress(-1);
    msg->setBitLength(1000);
    msg->setUserPriority(7);
    msg->setPsid(0);
}

// ==================== UPDATED detectMaliciousBehavior ====================

bool MyVeinsApp::detectMaliciousBehavior(MyMsg* msg) {
    bool detected = false;
    int senderId = msg->getSrcId();

    // Read position and speed from custom fields
    double senderPosX = msg->getSenderPosX();
    double senderPosY = msg->getSenderPosY();
    double senderSpeedX = msg->getSenderSpeedX();
    double senderSpeedY = msg->getSenderSpeedY();

    // Calculate speed magnitude
    double speed = sqrt(senderSpeedX * senderSpeedX + senderSpeedY * senderSpeedY);

    // ========== FLOOD/DOS DETECTION USING MESSAGE COUNTERS ==========
    auto it = messageCounters.find(senderId);
    if (it != messageCounters.end()) {
        MessageCounter& counter = it->second;

        // Check if this sender is flooding based on message rate
        EV_INFO << counter.count << " is detected rate from " << senderId << " and threshold is " << floodThreshold << endl;
        if (counter.count > floodThreshold) {
            EV_INFO << "DOS/FLOOD ATTACK DETECTED from " << senderId
                    << " | Rate: " << counter.count << " msgs/sec" << endl;
            detected = true;

            // Auto-blacklist the flood attacker
            counter.isBlacklisted = true;
            EV_INFO << "AUTO-BLACKLISTED: " << senderId << " for DOS attack" << endl;
        }
    }



    if (detected) {
        attacksDetected++;
        takeEvasiveAction();

        // Log the attacker details
        EV_INFO << "MALICIOUS NODE IDENTIFIED: " << senderId
                << " | Total attacks detected: " << attacksDetected << endl;
        return true;
    }
    else{
        return false;
    }
}

// ==================== ESSENTIAL FUNCTIONS ====================

void MyVeinsApp::initialize(int stage) {
    DemoBaseApplLayer::initialize(stage);
    if (stage == 0) {
        malicious = par("malicious");
        attackType = par("attackType").stdstringValue();
        floodThreshold = par("floodThreshold");
        detectionEnabled = par("detectionEnabled");
        EV_INFO << "Attack detection: " << (detectionEnabled ? "ENABLED" : "DISABLED") << endl;
        // Attack and defense counters
        attackCounter = 0;
        normalPacketsSent = 0;
        attackPacketsSent = 0;
        packetsReceived = 0;
        attacksDetected = 0;
        underAttack = false;

        // Network performance metrics
        totalEndToEndDelay = 0;
        totalJitterTime = 0;
        jitterCount = 0;
        totalBytesReceived = 0;
        packetsSent = 0;
        lastArrivalTime = -1;
        lastInterArrivalTime = -1;
        lastThroughputTime = simTime();

        // Initialize rate-based detection window
        detectionWindow = 1.0;     // 1 second window

        lastWindowStart = simTime();
        packetsInWindow = 0;

        // Statistics recording
        packetsSentVector.setName("Packets Sent");
        packetsReceivedVector.setName("Packets Received");
        endToEndDelayVector.setName("End-to-End Delay");
        jitterVector.setName("Jitter");
        throughputVector.setName("Throughput");

        if (malicious) {
            attackTimer = new cMessage("attackTimer");
            scheduleAt(simTime() + par("attackInterval").doubleValue(), attackTimer);
            EV_INFO << "MALICIOUS NODE: " << getParentModule()->getFullName()
                    << " | Attack type: " << attackType << endl;
            changeNodeColor("red");

            bubble("ATTACKER");
        } else {

            EV_INFO << "NORMAL NODE: " << getParentModule()->getFullName() << endl;
            changeNodeColor("green");
        }
    }
}

void MyVeinsApp::changeNodeColor(const char* color) {
    cDisplayString& dispStr = getParentModule()->getDisplayString();
    dispStr.setTagArg("i", 1, color);
}

void MyVeinsApp::takeEvasiveAction() {
    if (!underAttack) {
        underAttack = true;
        attackDetectedAt = simTime();
        changeNodeColor("yellow");
        bubble("UNDER ATTACK");
        EV_INFO << "EVASIVE ACTION: " << getParentModule()->getFullName()
                << " taking defensive measures" << endl;
//
        evasiveTimer = new cMessage("evasiveTimer");
        scheduleAt(simTime() + 5, evasiveTimer);
    }
}

void MyVeinsApp::endEvasiveAction() {
    underAttack = false;
    changeNodeColor("green");
    bubble("SAFE");
    EV_INFO << "RECOVERED: " << getParentModule()->getFullName()
            << " back to normal state" << endl;
}

void MyVeinsApp::onWSM(BaseFrame1609_4* wsm) {
    // function is bypassed by handleLower
}

void MyVeinsApp::handleSelfMsg(cMessage* msg) {
    if (msg == attackTimer && malicious) {
        attackCounter++;

        if (attackType == "flood") {
            for (int i = 0; i < 200; i++) {
                // Use MyMsg instead of DemoSafetyMessage for attacks
                MyMsg* floodMsg = new MyMsg();
                populateMyMsg(floodMsg , true);
                // Set unrealistic speed using custom fields
                floodMsg->setSenderSpeedX(150 + i);
                floodMsg->setSenderSpeedY(0);
                sendDown(floodMsg);
                attackPacketsSent++;
                packetsSent++;
                packetsSentVector.record(packetsSent);
            }
            EV_INFO << "FLOOD ATTACK #" << attackCounter << " sent by "
                    << getParentModule()->getFullName() << endl;

        } else if (attackType == "spoof") {
            MyMsg* spoofMsg = new MyMsg();
            populateMyMsg(spoofMsg , true);
            // Set impossible location using custom fields
            spoofMsg->setSenderPosX(7000);
            spoofMsg->setSenderPosY(7000);
            spoofMsg->setSenderSpeedX(0);
            spoofMsg->setSenderSpeedY(0);
            sendDown(spoofMsg);
            attackPacketsSent++;
            packetsSent++;
            packetsSentVector.record(packetsSent);
            EV_INFO << "SPOOF ATTACK #" << attackCounter << " sent by "
                    << getParentModule()->getFullName() << endl;

        } else if (attackType == "replay") {
            MyMsg* replayMsg = new MyMsg();
            populateMyMsg(replayMsg , true);
            // Set old position using custom fields
            replayMsg->setSenderPosX(curPosition.x - 500);
            replayMsg->setSenderPosY(curPosition.y - 500);
            replayMsg->setSenderSpeedX(100);
            replayMsg->setSenderSpeedY(0);
            sendDown(replayMsg);
            attackPacketsSent++;
            packetsSent++;
            packetsSentVector.record(packetsSent);
            EV_INFO << "REPLAY ATTACK #" << attackCounter << " sent by "
                    << getParentModule()->getFullName() << endl;
        }

        bubble("ATTACKING");
        scheduleAt(simTime() + par("attackInterval").doubleValue(), attackTimer);

    } else if (msg == evasiveTimer) {
        endEvasiveAction();

    } else {
        MyMsg* normalMsg = new MyMsg();
       populateMyMsg(normalMsg , false);
       sendDown(normalMsg);
       normalPacketsSent++;
       packetsSent++;
       packetsSentVector.record(packetsSent);

       // Reschedule the beacon timer (what parent would do)
       scheduleAt(simTime() + 1.0, msg); // Reschedule for 1 second later
    }
}

void MyVeinsApp::handlePositionUpdate(cObject* obj) {
    DemoBaseApplLayer::handlePositionUpdate(obj);

    // Record throughput periodically
    if (simTime() - lastThroughputTime >= 1.0) {
        double throughput = (totalBytesReceived * 8) / (simTime() - lastThroughputTime).dbl(); // bits per second
        throughputVector.record(throughput);
        lastThroughputTime = simTime();
        totalBytesReceived = 0;
    }

    if (underAttack && mobility->getSpeed() > 5) {
        traciVehicle->setSpeed(5);
    }
}

void MyVeinsApp::finish() {
    // ========== PERSONAL PDR CALCULATION ==========
    int myPacketsSent = 0;
    int myPacketsDelivered = 0;
    int myId = getParentModule()->getId();

    // Scan global packet map to find packets I sent
    for (const auto& entry : globalPacketMap) {
        const DeliveryInfo& info = entry.second;
        if (info.srcId == myId) {
            myPacketsSent++;

            // Read from ini file to get total non-attacking nodes
            int totalNodes = 9;
             int attackingNodes = 3;

            int totalNonAttackers = totalDefenders;


            // Packet delivered if all non-attacking nodes received it (excluding myself)
            int expectedReceivers = totalNonAttackers - 1;
            if (info.receivers.size() >= expectedReceivers / 2) {
                myPacketsDelivered++;
            }
        }
    }

    double myPersonalPDR = (myPacketsSent > 0) ?
        (double)myPacketsDelivered / myPacketsSent * 100 : 0;

    // ========== EXISTING PER-NODE STATISTICS ==========
//    double oldPDR = (packetsSent > 0) ? (double)packetsReceived / packetsSent * 100 : 0;
    double packetLossRatio = (myPacketsSent > 0) ? (double)( myPacketsSent - myPacketsDelivered ) / packetsSent * 100 : 0;
    double avgEndToEndDelay = (myPacketsDelivered > 0) ? totalEndToEndDelay.dbl() / packetsReceived : 0;
    double avgJitter = (jitterCount > 0) ? totalJitterTime.dbl() / jitterCount : 0;

    // ========== LOG EVERYTHING INSTEAD OF recordScalar ==========
    EV_INFO << "=== NODE STATISTICS: " << getParentModule()->getFullName() << " ===" << endl;
    EV_INFO << "Personal PDR: " << myPersonalPDR << "%" << endl;
    EV_INFO << "My Packets Sent: " << myPacketsSent << endl;
    EV_INFO << "My Packets Delivered: " << myPacketsDelivered << endl;
    EV_INFO << "Packet Loss Ratio: " << packetLossRatio << "%" << endl;
    EV_INFO << "Average End-to-End Delay: " << avgEndToEndDelay * 1000 << "ms" << endl;
    EV_INFO << "Average Jitter: " << avgJitter * 1000 << "ms" << endl;
    EV_INFO << "Attacks Detected: " << attacksDetected << endl;
    EV_INFO << "Throughput (last second): " << (totalBytesReceived * 8) << " bits/sec" << endl;

    // ========== GLOBAL STATISTICS (only node[0]) ==========
    if (getParentModule()->getIndex() == 0) {
        // Calculate global PDR
        int totalPacketsSent = 0;
        int totalPacketsDelivered = 0;


        int totalNodes = totalDefenders + totalAttackers;
        int totalNonAttackers = totalDefenders;

        for (const auto& entry : globalPacketMap) {
            const DeliveryInfo& info = entry.second;
            totalPacketsSent++;

            int expectedReceivers = totalNonAttackers - 1;
            if (info.receivers.size() >= expectedReceivers / 2) {
                totalPacketsDelivered++;
            }
        }

        double truePDR = (totalPacketsSent > 0) ?
            (double)totalPacketsDelivered / totalPacketsSent * 100 : 0;

        // Log global statistics
        EV_INFO << "=== GLOBAL NETWORK STATISTICS ===" << endl;
        EV_INFO << "True Packet Delivery Ratio: " << truePDR << "%" << endl;
        EV_INFO << "Total Packets Sent in Network: " << totalPacketsSent << endl;
        EV_INFO << "Total Packets Delivered " << totalPacketsDelivered << endl;
        EV_INFO << "Total Nodes: " << totalNodes << endl;
        EV_INFO << "Non-Attacking Nodes: " << totalNonAttackers << endl;
        EV_INFO << "Attacking Nodes: " << totalAttackers << endl;

        EV_INFO << "Total Unique Senders: " << messageCounters.size() << endl;
    }

    // Node-specific summary
    if (malicious) {
        EV_INFO << "=== ATTACKER SUMMARY ===" << endl;
        EV_INFO << "Attack Type: " << attackType << endl;
        EV_INFO << "Total Attacks Executed: " << attackCounter << endl;
        EV_INFO << "Attack Packets Sent: " << attackPacketsSent << endl;
        EV_INFO << "Normal Packets Sent: " << normalPacketsSent << endl;
    } else {
        int blacklistedAttackers = 0;
        for (const auto& counter : messageCounters) {
            if (counter.second.isBlacklisted) {
                blacklistedAttackers++;
            }
        }

        EV_INFO << "=== DEFENDER SUMMARY ===" << endl;
        EV_INFO << "Successful Attack Detections: " << attacksDetected << endl;
        EV_INFO << "Blacklisted Flood Attackers: " << blacklistedAttackers << endl;
    }

    EV_INFO << "=== END OF STATISTICS ===" << endl << endl;

    if (attackTimer) cancelAndDelete(attackTimer);
    if (evasiveTimer) cancelAndDelete(evasiveTimer);
    DemoBaseApplLayer::finish();
}
