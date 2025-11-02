package org.car2x.veins.modules.application.traci;
import org.car2x.veins.modules.application.ieee80211p.DemoBaseApplLayer;

simple MyVeinsApp extends DemoBaseApplLayer
{
    parameters:
        @class(veins::MyVeinsApp);
        string appName = default("V2V Security App");

        // Attack parameters
        bool malicious = default(false);
        string attackType = default("none");
        double attackInterval @unit(s) = default(2s);


}