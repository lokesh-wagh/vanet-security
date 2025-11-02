package v2v.v2vcustom;

import org.car2x.veins.base.modules.IBaseApplLayer;

module V2VApp like IBaseApplLayer
{
    parameters:
     	int headerLength = default(0);
        double sendInterval @unit(s) = default(1s);
        bool malicious = default(false);
        string attackType = default("none");
        string spoofedSourceId = default("normal_node");
        double dataManipulationProbability = default(0.1);
        bool enableEvasiveAction = default(false);
        double evasiveActionDuration @unit(s) = default(5s);
        bool debug = default(false);
        @display("i=block/control");

    gates:
        input lowerLayerIn;
        output lowerLayerOut;
        input lowerControlIn;
        output lowerControlOut;
}