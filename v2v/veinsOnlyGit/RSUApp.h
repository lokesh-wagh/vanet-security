#pragma once

#include "veins/modules/application/ieee80211p/DemoBaseApplLayer.h"

namespace veins {

class RSUApp : public DemoBaseApplLayer {
protected:
    void initialize(int stage) override;
    void onWSM(BaseFrame1609_4* wsm) override;
    void onBSM(DemoSafetyMessage* bsm) override;

private:
    std::string internetAddress;
    bool relayToInternet = false;
    int messagesRelayed = 0;

    void relayMessageToInternet();
};

} // namespace veins
