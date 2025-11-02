package org.car2x.veins.modules.application.traci;

import org.car2x.veins.modules.application.ieee80211p.DemoBaseApplLayer;

simple RSUApp extends DemoBaseApplLayer {
    parameters:
        string internetAddress;
        bool relayToInternet = default(false);
        @class(veins::RSUApp);
}