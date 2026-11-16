package managedproxy

import (
	"testing"
)

func TestSelectWindowsPhysicalInterfacePrefersBestDefaultRoute(t *testing.T) {
	interfaces := []windowsInterface{
		{index: 1, name: "Loopback Pseudo-Interface 1", physical: true, up: true, usable: true},
		{index: 2, name: "Ethernet", physical: true, up: true, usable: true},
		{index: 3, name: "Wi-Fi", physical: true, up: true, usable: true},
		{index: 4, name: "VPN", physical: false, up: true, usable: true},
		{index: 5, name: "Disconnected", physical: true, up: false, usable: true},
	}
	routes := []windowsRoute{
		{index: 4, metric: 1},
		{index: 3, metric: 25},
		{index: 2, metric: 10},
	}
	selected, err := selectWindowsPhysicalInterface(interfaces, routes)
	if err != nil {
		t.Fatal(err)
	}
	if selected.index != 2 || selected.name != "Ethernet" {
		t.Fatalf("selected %+v; want Ethernet", selected)
	}
}

func TestSelectWindowsPhysicalInterfaceFallsBackToAnyUsableAdapter(t *testing.T) {
	interfaces := []windowsInterface{
		{index: 7, name: "Wi-Fi", physical: true, up: true, usable: true},
		{index: 8, name: "Ethernet", physical: true, up: true, usable: true},
	}
	selected, err := selectWindowsPhysicalInterface(interfaces, nil)
	if err != nil {
		t.Fatal(err)
	}
	if selected.index != 7 || selected.name != "Wi-Fi" {
		t.Fatalf("selected %+v; want first usable adapter", selected)
	}
}

func TestSelectWindowsPhysicalInterfaceRejectsVirtualOnlyNetwork(t *testing.T) {
	interfaces := []windowsInterface{{index: 4, name: "VPN", physical: false, up: true, usable: true}}
	routes := []windowsRoute{{index: 4, metric: 1}}
	if _, err := selectWindowsPhysicalInterface(interfaces, routes); err == nil {
		t.Fatal("accepted a virtual-only adapter")
	}
}

func TestPhysicalAdapterTypeExcludesTunnels(t *testing.T) {
	if !physicalAdapterType(6, 0) || !physicalAdapterType(71, 0) {
		t.Fatal("rejected Ethernet or Wi-Fi")
	}
	if physicalAdapterType(6, 1) || physicalAdapterType(131, 0) {
		t.Fatal("accepted a tunnel adapter")
	}
}
