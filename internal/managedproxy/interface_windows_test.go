package managedproxy

import (
	"testing"
)

func TestSelectWindowsPhysicalInterfacePrefersBestDefaultRoute(t *testing.T) {
	interfaces := []windowsInterface{
		{index: 1, name: "Loopback Pseudo-Interface 1", hardware: false, up: true, usable: true, interfaceType: 6},
		{index: 2, name: "Ethernet", hardware: true, up: true, usable: true, interfaceType: 6, interfaceMetric: 25},
		{index: 3, name: "Wi-Fi", hardware: true, up: true, usable: true, interfaceType: 71, interfaceMetric: 55},
		{index: 4, name: "vEthernet", hardware: false, up: true, usable: true, interfaceType: 6},
		{index: 5, name: "Disconnected", hardware: true, up: false, usable: true, interfaceType: 6},
	}
	routes := []windowsRoute{
		{index: 4, metric: 1},
		{index: 3, metric: 0},
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

func TestSelectWindowsPhysicalInterfaceRejectsRouteNotFound(t *testing.T) {
	interfaces := []windowsInterface{
		{index: 8, name: "Ethernet", hardware: true, up: true, usable: true, interfaceType: 6},
		{index: 7, name: "Wi-Fi", hardware: true, up: true, usable: true, interfaceType: 71},
	}
	if _, err := selectWindowsPhysicalInterface(interfaces, nil); err == nil {
		t.Fatal("selected an adapter without a default route")
	}
}

func TestSelectWindowsPhysicalInterfaceRejectsVirtualOnlyNetwork(t *testing.T) {
	interfaces := []windowsInterface{{index: 4, name: "VPN", hardware: false, up: true, usable: true, interfaceType: 6}}
	routes := []windowsRoute{{index: 4, metric: 1}}
	if _, err := selectWindowsPhysicalInterface(interfaces, routes); err == nil {
		t.Fatal("accepted a virtual-only adapter")
	}
}

func TestSelectWindowsPhysicalInterfaceRequiresDefaultRoute(t *testing.T) {
	interfaces := []windowsInterface{{index: 2, name: "Ethernet", hardware: true, up: true, usable: true, interfaceType: 6}}
	virtualRoutes := []windowsRoute{{index: 9, metric: 1}}
	if _, err := selectWindowsPhysicalInterface(interfaces, virtualRoutes); err == nil {
		t.Fatal("selected an adapter without a default route")
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

func TestMIBIfHardwareInterfaceBit(t *testing.T) {
	if !mibIfHardwareInterface(0x01) || !mibIfHardwareInterface(0x89) {
		t.Fatal("failed to recognize hardware interface flag")
	}
	if mibIfHardwareInterface(0x08) || mibIfHardwareInterface(0x10) {
		t.Fatal("misclassified non-hardware interface flags")
	}
}
