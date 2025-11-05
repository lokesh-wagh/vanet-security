package v2v.simulations.v2v;

import org.car2x.veins.nodes.Scenario;
import org.car2x.veins.nodes.Car;
import org.car2x.veins.nodes.RSU;  // Import RSU module

network V2VNetwork extends Scenario
{
    parameters:
        int numVehicles = default(10);
        int numRSUs = default(3);  // Add RSU parameter

    submodules:

        rsu[numRSUs]: RSU {  // Add RSU submodules
            @display("p=300,100;i=block/routing");
        }


}