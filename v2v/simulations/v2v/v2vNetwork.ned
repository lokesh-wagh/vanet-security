//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with this program.  If not, see http://www.gnu.org/licenses/.
//

package v2v.simulations.v2v;


import inet.node.inet.WirelessHost;
import inet.physicallayer.wireless.ieee80211.packetlevel.Ieee80211ScalarRadioMedium;
import inet.visualizer.common.IntegratedVisualizer;

network V2VNetwork
{
    parameters:
        int numVehicles = default(10); // number of vehicles

    submodules:
        radioMedium: Ieee80211ScalarRadioMedium {
            @display("p=100,100");
        }

        node[numVehicles]: WirelessHost {
            @display("i=block/car, p=200+50*i,200");
        }
        visualizer: IntegratedVisualizer {
        	@display("p=100,200");
    	}

    connections allowunconnected:
}
