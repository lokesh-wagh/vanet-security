#include "veins/modules/application/traci/MyVeinsApp.h"
#include "veins/modules/messages/MyMsg_m.h"
#include <random>
#include <cmath>
#include <algorithm>
#include <sstream>

using namespace veins;

// Static member initialization
std::map<long, DeliveryInfo> MyVeinsApp::globalPacketMap;
long MyVeinsApp::nextPacketId = 1;

Define_Module(veins::MyVeinsApp);

// ==================== ENHANCED FLOOD ATTACK PREVENTION ====================

bool MyVeinsApp::isFloodAttacker(int senderId) {
    auto it = messageCounters.find(senderId);
    if (it == messageCounters.end()) {
        return false;
    }

    MessageCounter& counter = it->second;
    simtime_t currentTime = simTime();

    // Enhanced window management with sliding window
    if (currentTime - counter.startTime > detectionWindow) {
        // Slide the window - keep recent data for better detection
        if (counter.messageTimestamps.size() > 0) {
            // Remove old timestamps outside current window
            auto oldThreshold = currentTime - detectionWindow;
            while (!counter.messageTimestamps.empty() &&
                   counter.messageTimestamps.front() < oldThreshold) {
                counter.messageTimestamps.pop_front();
                counter.count = counter.messageTimestamps.size();
            }
            counter.startTime = counter.messageTimestamps.empty() ?
                               currentTime : counter.messageTimestamps.front();
        } else {
            counter.count = 0;
            counter.startTime = currentTime;
        }
        counter.isBlacklisted = false; // Give another chance after cleanup
    }

    // Multi-level threshold detection
    if (counter.count > severeFloodThreshold) {
        // Severe flooding - immediate blacklist
        counter.isBlacklisted = true;
        counter.blacklistTime = currentTime;
        EV_WARN << "SEVERE FLOOD ATTACK DETECTED: " << senderId
                << " | Rate: " << counter.count << " msgs/sec"
                << " | Threshold: " << severeFloodThreshold << endl;
        return true;
    }
    else if (counter.count > floodThreshold) {
        // Moderate flooding - check persistence
        if (counter.suspicionStartTime == -1) {
            counter.suspicionStartTime = currentTime;
        }

        simtime_t suspicionDuration = currentTime - counter.suspicionStartTime;
        if (suspicionDuration > persistentFloodDuration) {
            counter.isBlacklisted = true;
            counter.blacklistTime = currentTime;
            EV_WARN << "PERSISTENT FLOOD ATTACK DETECTED: " << senderId
                    << " | Rate: " << counter.count << " msgs/sec"
                    << " | Duration: " << suspicionDuration << "s" << endl;
            return true;
        }
        return false; // Not blacklisted yet, but suspicious
    }
    else {
        // Normal rate - reset suspicion
        counter.suspicionStartTime = -1;
        return counter.isBlacklisted; // Return current blacklist status
    }
}

void MyVeinsApp::updateMessageCounter(int senderId) {
    auto it = messageCounters.find(senderId);
    simtime_t currentTime = simTime();

    if (it == messageCounters.end()) {
        // First message from this sender
        MessageCounter counter;
        counter.count = 1;
        counter.startTime = currentTime;
        counter.suspicionStartTime = -1;
        counter.isBlacklisted = false;
        counter.blacklistTime = -1;
        counter.messageTimestamps.push_back(currentTime);
        messageCounters[senderId] = counter;

        EV_DEBUG << "New sender registered: " << senderId << endl;
    } else {
        MessageCounter& counter = it->second;

        // Check if blacklist period has expired
        if (counter.isBlacklisted && (currentTime - counter.blacklistTime > blacklistTimeout)) {
            EV_INFO << "Blacklist expired for sender: " << senderId << endl;
            counter.isBlacklisted = false;
            counter.count = 0;
            counter.startTime = currentTime;
            counter.suspicionStartTime = -1;
            counter.messageTimestamps.clear();
        }

        if (!counter.isBlacklisted) {
            // Add current timestamp and maintain sliding window
            counter.messageTimestamps.push_back(currentTime);
            counter.count = counter.messageTimestamps.size();

            // Remove timestamps outside the detection window
            auto oldThreshold = currentTime - detectionWindow;
            while (!counter.messageTimestamps.empty() &&
                   counter.messageTimestamps.front() < oldThreshold) {
                counter.messageTimestamps.pop_front();
                counter.count = counter.messageTimestamps.size();
            }

            // Update start time if window was empty
            if (counter.messageTimestamps.empty()) {
                counter.startTime = currentTime;
            }

            // Calculate current message rate for logging
            double currentRate = counter.count / detectionWindow;
            if (currentRate > floodThreshold * 0.8) { // Log when approaching threshold
                EV_DEBUG << "Sender " << senderId << " rate: " << currentRate
                         << " msgs/sec" << endl;
            }
        }
    }
}

// ==================== ENHANCED DETECTION ALGORITHMS ====================

bool MyVeinsApp::detectMaliciousBehavior(MyMsg* msg) {
    bool detected = false;
    int senderId = msg->getSrcId();
    std::string detectionReason;

    // ========== ENHANCED FLOOD/DOS DETECTION ==========
    auto counterIt = messageCounters.find(senderId);
    if (counterIt != messageCounters.end()) {
        MessageCounter& counter = counterIt->second;
        double currentRate = counter.count / detectionWindow;

        // Multi-level flood detection
        if (currentRate > severeFloodThreshold) {
            detected = true;
            std::ostringstream oss;
            oss << "Severe flooding (" << currentRate << " msgs/sec)";
            detectionReason = oss.str();
            counter.isBlacklisted = true;
            counter.blacklistTime = simTime();
        }
        else if (currentRate > floodThreshold) {
            // Check for burst detection
            if (detectBurstAttack(counter)) {
                detected = true;
                detectionReason = "Burst attack detected";
                counter.isBlacklisted = true;
                counter.blacklistTime = simTime();
            }
            // Check for sustained high rate
            else if (counter.suspicionStartTime != -1) {
                simtime_t suspicionTime = simTime() - counter.suspicionStartTime;
                if (suspicionTime > persistentFloodDuration) {
                    detected = true;
                    std::ostringstream oss;
                    oss << "Sustained high rate for " << suspicionTime << "s";
                    detectionReason = oss.str();
                    counter.isBlacklisted = true;
                    counter.blacklistTime = simTime();
                }
            }
        }

        // Entropy-based anomaly detection
        if (!detected && entropyBasedDetectionEnabled) {
            if (detectAnomalousTraffic(senderId, currentRate)) {
                detected = true;
                detectionReason = "Anomalous traffic pattern";
                counter.suspicionLevel++; // Increase suspicion level
                if (counter.suspicionLevel > maxSuspicionLevel) {
                    counter.isBlacklisted = true;
                    counter.blacklistTime = simTime();
                }
            }
        }
    }

    // ========== MESSAGE CONTENT VALIDATION ==========
    if (!detected && messageValidationEnabled) {
        if (!validateMessageContent(msg)) {
            detected = true;
            detectionReason = "Invalid message content";
            EV_WARN << "Message validation failed for sender: " << senderId << endl;
        }
    }

    if (detected) {
        attacksDetected++;
        takeEvasiveAction();

        // Log detailed detection information
        EV_WARN << "MALICIOUS BEHAVIOR DETECTED: " << senderId
                << " | Reason: " << detectionReason
                << " | Total detections: " << attacksDetected << endl;

        // Update detection statistics
        detectionStats.totalDetections++;
        if (counterIt != messageCounters.end()) {
            detectionStats.highRateDetections++;
        }

        return true;
    }

    return false;
}

bool MyVeinsApp::detectBurstAttack(const MessageCounter& counter) {
    if (counter.messageTimestamps.size() < minBurstSize) {
        return false;
    }

    // Check for rapid succession of messages (burst)
    auto recentStart = counter.messageTimestamps.end() - std::min((size_t)minBurstSize, counter.messageTimestamps.size());
    simtime_t burstDuration = counter.messageTimestamps.back() - *recentStart;

    if (burstDuration < maxBurstDuration) {
        double burstRate = minBurstSize / burstDuration.dbl();
        EV_DEBUG << "Burst detected: rate=" << burstRate << " msgs/sec, duration=" << burstDuration << endl;
        return burstRate > burstThreshold;
    }

    return false;
}

bool MyVeinsApp::detectAnomalousTraffic(int senderId, double currentRate) {
    // Calculate average rate across all senders for comparison
    double totalRate = 0.0;
    int activeSenders = 0;

    for (const auto& entry : messageCounters) {
        if (!entry.second.isBlacklisted) {
            double rate = entry.second.count / detectionWindow;
            totalRate += rate;
            activeSenders++;
        }
    }

    if (activeSenders > 0) {
        double averageRate = totalRate / activeSenders;
        double rateDeviation = std::abs(currentRate - averageRate) / averageRate;

        // If rate is significantly higher than network average
        if (rateDeviation > anomalyThreshold) {
            EV_DEBUG << "Anomalous traffic from " << senderId
                     << ": rate=" << currentRate << ", avg=" << averageRate
                     << ", deviation=" << rateDeviation << endl;
            return true;
        }
    }

    return false;
}

bool MyVeinsApp::validateMessageContent(MyMsg* msg) {
    // Validate position coordinates
    double posX = msg->getSenderPosX();
    double posY = msg->getSenderPosY();

    if (std::isnan(posX) || std::isnan(posY) ||
        std::isinf(posX) || std::isinf(posY)) {
        EV_WARN << "Invalid position coordinates in message from " << msg->getSrcId() << endl;
        return false;
    }

    // Validate speed (reasonable vehicle speeds)
    double speedX = msg->getSenderSpeedX();
    double speedY = msg->getSenderSpeedY();
    double speed = std::sqrt(speedX * speedX + speedY * speedY);

    if (speed > maxReasonableSpeed) {
        EV_WARN << "Unreasonable speed in message from " << msg->getSrcId()
                << ": " << speed << " m/s" << endl;
        return false;
    }

    // Validate timestamp (not from future, not too old)
    simtime_t msgTimestamp = msg->getTimestamp();
    simtime_t currentTime = simTime();

    if (msgTimestamp > currentTime) {
        EV_WARN << "Future timestamp in message from " << msg->getSrcId() << endl;
        return false;
    }

    if (currentTime - msgTimestamp > maxMessageAge) {
        EV_WARN << "Stale message from " << msg->getSrcId()
                << ", age: " << (currentTime - msgTimestamp) << "s" << endl;
        return false;
    }

    return true;
}

// ==================== ENHANCED handleLowerMsg ====================

void MyVeinsApp::handleLowerMsg(cMessage* msg) {
    if (auto myMsg = dynamic_cast<veins::MyMsg*>(msg)) {
        int receiverId = getParentModule()->getId();
        long packetId = myMsg->getPacketId();
        int senderId = myMsg->getSrcId();

        // ENHANCED FLOOD PREVENTION with multiple checks
        if (!malicious && detectionEnabled) {
            // Check blacklist first
            if (isFloodAttacker(senderId)) {
                EV_WARN << "DROPPED PACKET from blacklisted flood attacker: " << senderId << endl;
                detectionStats.packetsBlocked++;
                attacksDetected++;
                takeEvasiveAction();
                delete msg;
                return;
            }

            // Update counter and check for new attacks
            updateMessageCounter(senderId);

            // Comprehensive malicious behavior detection
            if (detectMaliciousBehavior(myMsg)) {
                delete msg;
                return;
            }
        } else {
            // Still update counters even if detection is disabled
            updateMessageCounter(senderId);
        }

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

        for(int i=0;i<1000000000;i++){
                // simulating upper layer calculations that the vehicle needs to make
        }

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

// ==================== ESSENTIAL FUNCTIONS ====================

void MyVeinsApp::initialize(int stage) {
    DemoBaseApplLayer::initialize(stage);
    if (stage == 0) {
        malicious = par("malicious");
        attackType = par("attackType").stdstringValue();

        // Enhanced detection parameters
        floodThreshold = par("floodThreshold");
        severeFloodThreshold = par("severeFloodThreshold");
        burstThreshold = par("burstThreshold");
        anomalyThreshold = par("anomalyThreshold");
        detectionWindow = par("detectionWindow");
        blacklistTimeout = par("blacklistTimeout");
        persistentFloodDuration = par("persistentFloodDuration");
        maxBurstDuration = par("maxBurstDuration");
        minBurstSize = par("minBurstSize");
        maxReasonableSpeed = par("maxReasonableSpeed");
        maxMessageAge = par("maxMessageAge");
        maxSuspicionLevel = par("maxSuspicionLevel");

        // Detection features
        detectionEnabled = par("detectionEnabled");
        entropyBasedDetectionEnabled = par("entropyBasedDetection");
        messageValidationEnabled = par("messageValidation");

        EV_INFO << "Enhanced attack detection: " << (detectionEnabled ? "ENABLED" : "DISABLED") << endl;
        if (detectionEnabled) {
            EV_INFO << "Entropy-based detection: " << (entropyBasedDetectionEnabled ? "ON" : "OFF") << endl;
            EV_INFO << "Message validation: " << (messageValidationEnabled ? "ON" : "OFF") << endl;
        }

        // Initialize detection statistics
        detectionStats.totalDetections = 0;
        detectionStats.highRateDetections = 0;
        detectionStats.packetsBlocked = 0;
        detectionStats.falsePositives = 0;

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

        lastWindowStart = simTime();
        packetsInWindow = 0;

        // Statistics recording
        packetsSentVector.setName("Packets Sent");
        packetsReceivedVector.setName("Packets Received");
        endToEndDelayVector.setName("End-to-End Delay");
        jitterVector.setName("Jitter");
        throughputVector.setName("Throughput");
        detectionRateVector.setName("Detection Rate");
        falsePositiveVector.setName("False Positives");

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
            for (int i = 0; i < 5; i++) {
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
            int totalNodes = totalAttackers + totalDefenders;
             int attackingNodes = totalAttackers;

            // Packet delivered if half non-attacking nodes received it (excluding myself)
            int expectedReceivers = totalDefenders - 1;
            if (info.receivers.size() >= expectedReceivers / 2) {
                myPacketsDelivered++;
            }
        }
    }

    double myPersonalPDR = (myPacketsSent > 0) ?
        (double)myPacketsDelivered / myPacketsSent * 100 : 0;

    // ========== EXISTING PER-NODE STATISTICS ==========
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


    if (!malicious && detectionEnabled) {

        // Calculate detection accuracy if we have ground truth
        if (totalAttackers > 0) {
            double detectionRate = (double)detectionStats.totalDetections / totalAttackers * 100;
            EV_INFO << "Estimated Detection Rate: " << detectionRate << "%" << endl;
        }

        // Log blacklisted nodes
        int blacklistedCount = 0;
        for (const auto& counter : messageCounters) {
            if (counter.second.isBlacklisted) {
                blacklistedCount++;
                EV_DEBUG << "Blacklisted: Node " << counter.first
                         << " (suspicion level: " << counter.second.suspicionLevel << ")" << endl;
            }
        }
        EV_INFO << "Total Blacklisted Nodes: " << blacklistedCount << endl;
    }

    // ========== GLOBAL STATISTICS (only node[0]) ==========
    if (getParentModule()->getIndex() == 0) {
        // Calculate global PDR
        int totalPacketsSent = 0;
        int totalPacketsDelivered = 0;

        int totalNodes = totalDefenders + totalAttackers;

        for (const auto& entry : globalPacketMap) {
            const DeliveryInfo& info = entry.second;
            totalPacketsSent++;

            int expectedReceivers = totalDefenders - 1;
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
        EV_INFO << "Non-Attacking Nodes: " << totalDefenders << endl;
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
        if(detectionEnabled){
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
    }

    EV_INFO << "=== END OF STATISTICS ===" << endl << endl;


    DemoBaseApplLayer::finish();
}

MyVeinsApp::MyVeinsApp() {
    // Constructor
}

MyVeinsApp::~MyVeinsApp() {
    // Destructor
}
