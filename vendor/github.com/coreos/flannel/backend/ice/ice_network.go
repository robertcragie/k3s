// Copyright 2015 flannel authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
// +build !windows

package ice

import (
	"encoding/json"
	"net"
	"sync"

	"github.com/vishvananda/netlink"
	"golang.org/x/net/context"
	log "k8s.io/klog"

	"syscall"

	"github.com/coreos/flannel/backend"
	"github.com/coreos/flannel/pkg/ip"
	"github.com/coreos/flannel/subnet"
)

type network struct {
	backend.SimpleNetwork
	dev       *iceDevice
	subnetMgr subnet.Manager
}

const (
	encapOverhead = 50
)

func newNetwork(subnetMgr subnet.Manager, extIface *backend.ExternalInterface, dev *iceDevice, _ ip.IP4Net, lease *subnet.Lease) (*network, error) {
	nw := &network{
		SimpleNetwork: backend.SimpleNetwork{
			SubnetLease: lease,
			ExtIface:    extIface,
		},
		subnetMgr: subnetMgr,
		dev:       dev,
	}

	return nw, nil
}

func (nw *network) Run(ctx context.Context) {
	wg := sync.WaitGroup{}

	log.V(0).Info("watching for new subnet leases")
	events := make(chan []subnet.Event)
	wg.Add(1)
	go func() {
		subnet.WatchLeases(ctx, nw.subnetMgr, nw.SubnetLease, events)
		log.V(1).Info("WatchLeases exited")
		wg.Done()
	}()

	defer wg.Wait()

	for {
		select {
		case evtBatch := <-events:
			nw.handleSubnetEvents(evtBatch)

		case <-ctx.Done():
			return
		}
	}
}

func (nw *network) MTU() int {
	return nw.ExtIface.Iface.MTU - encapOverhead
}

type iceLeaseAttrs struct {
	VtepMAC hardwareAddr
}

func (nw *network) handleSubnetEvents(batch []subnet.Event) {
	for _, event := range batch {
		sn := event.Lease.Subnet
		attrs := event.Lease.Attrs
		if attrs.BackendType != "ice" {
			log.Warningf("ignoring non-ice subnet(%s): type=%v", sn, attrs.BackendType)
			continue
		}

		var iceAttrs iceLeaseAttrs
		if err := json.Unmarshal(attrs.BackendData, &iceAttrs); err != nil {
			log.Error("error decoding subnet lease JSON: ", err)
			continue
		}

		// This route is used when traffic should be vxlan encapsulated
		iceRoute := netlink.Route{
			LinkIndex: nw.dev.link.Attrs().Index,
			Scope:     netlink.SCOPE_UNIVERSE,
			Dst:       sn.ToIPNet(),
			Gw:        sn.IP.ToIP(),
		}
		iceRoute.SetFlag(syscall.RTNH_F_ONLINK)

		// directRouting is where the remote host is on the same subnet so vxlan isn't required.
		directRoute := netlink.Route{
			Dst: sn.ToIPNet(),
			Gw:  attrs.PublicIP.ToIP(),
		}
		var directRoutingOK = false
		if nw.dev.directRouting {
			if dr, err := ip.DirectRouting(attrs.PublicIP.ToIP()); err != nil {
				log.Error(err)
			} else {
				directRoutingOK = dr
			}
		}

		switch event.Type {
		case subnet.EventAdded:
			if directRoutingOK {
				log.V(2).Infof("Adding direct route to subnet: %s PublicIP: %s", sn, attrs.PublicIP)

				if err := netlink.RouteReplace(&directRoute); err != nil {
					log.Errorf("Error adding route to %v via %v: %v", sn, attrs.PublicIP, err)
					continue
				}
			} else {
				log.V(2).Infof("adding subnet: %s PublicIP: %s VtepMAC: %s", sn, attrs.PublicIP, net.HardwareAddr(iceAttrs.VtepMAC))
				if err := nw.dev.AddARP(neighbor{IP: sn.IP, MAC: net.HardwareAddr(iceAttrs.VtepMAC)}); err != nil {
					log.Error("AddARP failed: ", err)
					continue
				}

				if err := nw.dev.AddFDB(neighbor{IP: attrs.PublicIP, MAC: net.HardwareAddr(iceAttrs.VtepMAC)}); err != nil {
					log.Error("AddFDB failed: ", err)

					// Try to clean up the ARP entry then continue
					if err := nw.dev.DelARP(neighbor{IP: event.Lease.Subnet.IP, MAC: net.HardwareAddr(iceAttrs.VtepMAC)}); err != nil {
						log.Error("DelARP failed: ", err)
					}

					continue
				}

				// Set the route - the kernel would ARP for the Gw IP address if it hadn't already been set above so make sure
				// this is done last.
				if err := netlink.RouteReplace(&iceRoute); err != nil {
					log.Errorf("failed to add iceRoute (%s -> %s): %v", iceRoute.Dst, iceRoute.Gw, err)

					// Try to clean up both the ARP and FDB entries then continue
					if err := nw.dev.DelARP(neighbor{IP: event.Lease.Subnet.IP, MAC: net.HardwareAddr(iceAttrs.VtepMAC)}); err != nil {
						log.Error("DelARP failed: ", err)
					}

					if err := nw.dev.DelFDB(neighbor{IP: event.Lease.Attrs.PublicIP, MAC: net.HardwareAddr(iceAttrs.VtepMAC)}); err != nil {
						log.Error("DelFDB failed: ", err)
					}

					continue
				}
			}
		case subnet.EventRemoved:
			if directRoutingOK {
				log.V(2).Infof("Removing direct route to subnet: %s PublicIP: %s", sn, attrs.PublicIP)
				if err := netlink.RouteDel(&directRoute); err != nil {
					log.Errorf("Error deleting route to %v via %v: %v", sn, attrs.PublicIP, err)
				}
			} else {
				log.V(2).Infof("removing subnet: %s PublicIP: %s VtepMAC: %s", sn, attrs.PublicIP, net.HardwareAddr(iceAttrs.VtepMAC))

				// Try to remove all entries - don't bail out if one of them fails.
				if err := nw.dev.DelARP(neighbor{IP: sn.IP, MAC: net.HardwareAddr(iceAttrs.VtepMAC)}); err != nil {
					log.Error("DelARP failed: ", err)
				}

				if err := nw.dev.DelFDB(neighbor{IP: attrs.PublicIP, MAC: net.HardwareAddr(iceAttrs.VtepMAC)}); err != nil {
					log.Error("DelFDB failed: ", err)
				}

				if err := netlink.RouteDel(&iceRoute); err != nil {
					log.Errorf("failed to delete iceRoute (%s -> %s): %v", iceRoute.Dst, iceRoute.Gw, err)
				}
			}
		default:
			log.Error("internal error: unknown event type: ", int(event.Type))
		}
	}
}
