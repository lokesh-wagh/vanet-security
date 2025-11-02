#include "veins/modules/application/traci/RSUApp.h"

using namespace veins;

Define_Module(veins::RSUApp);

void RSUApp::initialize(int stage)
{
    DemoBaseApplLayer::initialize(stage);

    if (stage == 0) {
        internetAddress = par("internetAddress").stdstringValue();
        relayToInternet = par("relayToInternet");
        messagesRelayed = 0;

        EV << "RSU " << myId << " initialized. Internet address: " << internetAddress << endl;
    }
}

void RSUApp::onBSM(DemoSafetyMessage* bsm)
{
    EV << "RSU " << myId << " received BSM from a vehicle" << endl;

    if (relayToInternet) {
        EV << "RSU relaying BSM to internet" << endl;
        relayMessageToInternet();
    }
}

void RSUApp::onWSM(BaseFrame1609_4* wsm)
{
    EV << "RSU " << myId << " received WSM" << endl;

    if (relayToInternet) {
        relayMessageToInternet();
    }
}

void RSUApp::relayMessageToInternet()
{
    EV << "RSU " << myId << " relaying message to internet at: " << internetAddress << endl;
    recordScalar("messagesRelayedToInternet", ++messagesRelayed);
}
