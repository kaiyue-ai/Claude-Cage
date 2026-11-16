package managedproxy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"github.com/sylvinus/agent-vm/internal/diagnostics"
	"github.com/sylvinus/agent-vm/internal/host"
	"golang.org/x/sys/windows"
)

type windowsCoreRecord struct {
	PID        uint32 `json:"pid"`
	Executable string `json:"executable"`
	Created    int64  `json:"created"`
}

func windowsCoreRecordPath(profile string) string {
	return filepath.Join(Dir(profile), "managed-process.json")
}

func coreEnvironment(dir string) []string {
	env := []string{"HOME=" + dir, "USERPROFILE=" + dir}
	for _, key := range []string{"SystemRoot", "WINDIR", "TEMP", "TMP"} {
		if value := os.Getenv(key); value != "" {
			env = append(env, key+"="+value)
		}
	}
	return env
}

func identifyCore(handle windows.Handle) (string, int64, error) {
	name := make([]uint16, 32768)
	size := uint32(len(name))
	if err := windows.QueryFullProcessImageName(handle, 0, &name[0], &size); err != nil {
		return "", 0, err
	}
	var created, exited, kernel, user windows.Filetime
	if err := windows.GetProcessTimes(handle, &created, &exited, &kernel, &user); err != nil {
		return "", 0, err
	}
	return windows.UTF16ToString(name[:size]), created.Nanoseconds(), nil
}

// Stop opens one process handle and validates both its image and creation time
// before termination. A reused PID cannot terminate an unrelated application.
func stopWindowsCore(profile string) error {
	path := windowsCoreRecordPath(profile)
	if _, err := os.Lstat(path); os.IsNotExist(err) {
		return nil
	}
	if err := host.CheckPrivateFile(path); err != nil {
		return err
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var record windowsCoreRecord
	if len(b) > 4096 || json.Unmarshal(b, &record) != nil || record.PID == 0 || record.Created == 0 {
		return errors.New("Cage 代理进程记录无效")
	}
	core, err := CorePath()
	if err != nil {
		return err
	}
	if !strings.EqualFold(filepath.Clean(core), filepath.Clean(record.Executable)) {
		return errors.New("Cage 代理进程不属于当前安装目录")
	}
	handle, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION|windows.PROCESS_TERMINATE|windows.SYNCHRONIZE, false, record.PID)
	if errors.Is(err, windows.ERROR_INVALID_PARAMETER) {
		return removeStaleCore(profile, path)
	}
	if errors.Is(err, windows.ERROR_ACCESS_DENIED) && !recordedCoreRunning(record) {
		// The core runs as the current user, so a PID that cannot be
		// terminated now belongs to another account's process.
		return removeStaleCore(profile, path)
	}
	if err != nil {
		return err
	}
	defer windows.CloseHandle(handle)
	image, created, err := identifyCore(handle)
	if err != nil {
		return err
	}
	if !sameCore(record, image, created) {
		// The recorded core exited and its PID was reused, typically after a
		// reboot. Forget the stale record and leave the other process alone.
		return removeStaleCore(profile, path)
	}
	var code uint32
	if err := windows.GetExitCodeProcess(handle, &code); err != nil {
		return err
	}
	if code == 259 {
		if err := windows.TerminateProcess(handle, 0); err != nil {
			return err
		}
		state, err := windows.WaitForSingleObject(handle, 5000)
		if err != nil {
			return err
		}
		if state != windows.WAIT_OBJECT_0 {
			return errors.New("Cage 代理进程未能及时停止")
		}
	}
	return removeStaleCore(profile, path)
}

func sameCore(record windowsCoreRecord, image string, created int64) bool {
	return strings.EqualFold(filepath.Clean(image), filepath.Clean(record.Executable)) && created == record.Created
}

func recordedCoreRunning(record windowsCoreRecord) bool {
	handle, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, record.PID)
	if err != nil {
		return false
	}
	defer windows.CloseHandle(handle)
	image, created, err := identifyCore(handle)
	return err == nil && sameCore(record, image, created)
}

func removeStaleCore(profile, path string) error {
	if err := removeWindowsCoreSocket(profile); err != nil {
		return err
	}
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return &coreError{stage: "record.remove", err: err}
	}
	return nil
}

func removeWindowsCoreSocket(profile string) error {
	if err := os.Remove(Socket(profile)); err != nil && !os.IsNotExist(err) {
		return &coreError{stage: "socket.remove", err: err}
	}
	return nil
}

func stopWindowsCoreAfterFailure(profile string, cause error) error {
	if err := stopWindowsCore(profile); err != nil {
		return errors.Join(cause, &coreError{stage: "startup.cleanup", err: err})
	}
	return cause
}

func startWindowsCore(ctx context.Context, profile string, s Store) error {
	name, err := PhysicalInterface(ctx)
	if err != nil {
		return err
	}
	path := filepath.Join(Dir(profile), "config.yaml")
	bound, _ := BoundInterface(path)
	if bound == name && Running(ctx, profile, s) {
		return nil
	}
	if err := Validate(ctx, profile, s); err != nil {
		return err
	}
	if err := stopWindowsCore(profile); err != nil {
		return err
	}
	l, err := net.Listen("tcp4", fmt.Sprintf("127.0.0.1:%d", s.Port))
	if err != nil {
		return errors.New("Cage 代理端口已被占用，请更换独立端口")
	}
	l.Close()
	core, err := CorePath()
	if err != nil {
		return err
	}
	if err := host.EnsurePrivateDir(filepath.Dir(Socket(profile))); err != nil {
		return err
	}
	b, err := s.Runtime(profile)
	if err != nil {
		return err
	}
	b, err = BindInterface(b, name)
	if err != nil {
		return err
	}
	if err := Write(path, b); err != nil {
		return err
	}
	if err := removeWindowsCoreSocket(profile); err != nil {
		return err
	}
	log := diagnostics.New(profile).Stream("proxy", "warn")

	cmd := exec.Command(core, "-d", Dir(profile), "-f", path)
	cmd.Env, cmd.Stdout, cmd.Stderr = coreEnvironment(Dir(profile)), log, log
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: windows.CREATE_NEW_PROCESS_GROUP | windows.CREATE_NO_WINDOW}
	if err := cmd.Start(); err != nil {
		_ = log.Close()
		return err
	}
	handle, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(cmd.Process.Pid))
	if err != nil {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		return err
	}
	image, created, err := identifyCore(handle)
	windows.CloseHandle(handle)
	if err != nil {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		return err
	}
	record, _ := json.Marshal(windowsCoreRecord{PID: uint32(cmd.Process.Pid), Executable: image, Created: created})
	if err := Write(windowsCoreRecordPath(profile), record); err != nil {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		return err
	}
	go func() {
		err := cmd.Wait()
		_ = log.Close()
		if err != nil {
			_ = diagnostics.New(profile).Record("error", "proxy", "core exited: "+err.Error())
		}
	}()
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	timeout := time.NewTimer(15 * time.Second)
	defer timeout.Stop()
	var lastReadiness error
	for {
		select {
		case <-ctx.Done():
			return stopWindowsCoreAfterFailure(profile, ctx.Err())
		case <-timeout.C:
			return stopWindowsCoreAfterFailure(profile, errors.Join(errors.New("代理核心启动超时，请查看私有代理日志"), lastReadiness))
		case <-ticker.C:
			lastReadiness = checkRunning(ctx, profile, s)
			if lastReadiness == nil {
				if err := host.ProtectFile(Socket(profile)); err != nil {
					return stopWindowsCoreAfterFailure(profile, &coreError{stage: "socket.protect", err: err})
				}
				return nil
			}
		}
	}
}

func windowsPhysicalInterface(ctx context.Context) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	interfaces, err := windowsNetworkInterfaces()
	if err != nil {
		return "", errors.New("无法读取 Windows 网卡信息，请确认系统网络服务正常后重试；Cage 外网保持关闭")
	}
	routes, err := windowsIPv4DefaultRoutes()
	if err != nil {
		return "", errors.New("无法读取 Windows 路由信息，请确认系统网络服务正常后重试；Cage 外网保持关闭")
	}
	selected, err := selectWindowsPhysicalInterface(interfaces, routes)
	if err != nil {
		return "", err
	}
	iface, err := net.InterfaceByIndex(selected.index)
	if err != nil || iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
		return "", errors.New("物理网卡已断开，请重试")
	}
	if !strings.EqualFold(iface.Name, selected.name) {
		return "", errors.New("物理网卡信息已变化，请重试")
	}
	return iface.Name, nil
}

type windowsInterface struct {
	index           int
	name            string
	hardware        bool
	up              bool
	usable          bool
	luid            uint64
	interfaceType   uint32
	tunnelType      uint32
	interfaceMetric uint32
}

type windowsRoute struct {
	index  int
	metric uint32
}

type windowsSelectedInterface struct {
	index int
	name  string
}

func selectWindowsPhysicalInterface(interfaces []windowsInterface, routes []windowsRoute) (windowsSelectedInterface, error) {
	usable := make(map[int]windowsInterface, len(interfaces))
	for _, candidate := range interfaces {
		if candidate.index > 0 && candidate.hardware && candidate.up && candidate.usable && physicalAdapterType(candidate.interfaceType, candidate.tunnelType) {
			if _, exists := usable[candidate.index]; !exists {
				usable[candidate.index] = candidate
			}
		}
	}
	if len(routes) > 0 {
		type scoredRoute struct {
			windowsInterface
			metric uint32
		}
		scored := make([]scoredRoute, 0, len(routes))
		for _, route := range routes {
			if candidate, ok := usable[route.index]; ok {
				scored = append(scored, scoredRoute{
					windowsInterface: candidate,
					metric:           route.metric + candidate.interfaceMetric,
				})
			}
		}
		if len(scored) == 0 {
			return windowsSelectedInterface{}, errors.New("未找到可用的物理 IPv4 默认路由。请连接以太网或 Wi-Fi；Cage 外网保持关闭")
		}
		sort.Slice(scored, func(i, j int) bool {
			if scored[i].metric != scored[j].metric {
				return scored[i].metric < scored[j].metric
			}
			return scored[i].index < scored[j].index
		})
		return windowsSelectedInterface{index: scored[0].index, name: scored[0].name}, nil
	}
	ordered := make([]windowsInterface, 0, len(usable))
	for _, candidate := range usable {
		ordered = append(ordered, candidate)
	}
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].index < ordered[j].index })
	if len(ordered) > 0 {
		return windowsSelectedInterface{index: ordered[0].index, name: ordered[0].name}, nil
	}
	return windowsSelectedInterface{}, errors.New("未找到可用的物理 IPv4 网卡。请连接以太网或 Wi-Fi；仅有虚拟网卡的 Windows 虚拟机和云主机暂不可用。Cage 外网保持关闭")
}

func windowsNetworkInterfaces() ([]windowsInterface, error) {
	const flags = windows.GAA_FLAG_SKIP_ANYCAST |
		windows.GAA_FLAG_SKIP_MULTICAST |
		windows.GAA_FLAG_SKIP_DNS_SERVER |
		windows.GAA_FLAG_INCLUDE_TUNNEL_BINDINGORDER
	var ifTable *windows.MibIfTable2
	if err := windows.GetIfTable2Ex(windows.MibIfTableNormalWithoutStatistics, &ifTable); err != nil {
		return nil, err
	}
	defer windows.FreeMibTable(unsafe.Pointer(ifTable))
	ifRows := make(map[int]windows.MibIfRow2, ifTable.NumEntries)
	for index := 0; index < int(ifTable.NumEntries); index++ {
		row := *(*windows.MibIfRow2)(unsafe.Pointer(uintptr(unsafe.Pointer(&ifTable.Table)) + uintptr(index)*unsafe.Sizeof(windows.MibIfRow2{})))
		ifRows[int(row.InterfaceIndex)] = row
	}
	var buffer []byte
	var addresses *windows.IpAdapterAddresses
	const maxAttempts = 4
	for attempt := 0; ; attempt++ {
		var needed uint32
		err := windows.GetAdaptersAddresses(windows.AF_UNSPEC, flags, 0, addresses, &needed)
		if err == nil && addresses != nil {
			break
		}
		if err != nil && err != windows.ERROR_BUFFER_OVERFLOW || needed == 0 || attempt+1 >= maxAttempts {
			return nil, err
		}
		buffer = make([]byte, needed)
		addresses = (*windows.IpAdapterAddresses)(unsafe.Pointer(&buffer[0]))
	}
	var result []windowsInterface
	for adapter := addresses; adapter != nil; adapter = adapter.Next {
		if adapter.IfIndex == 0 || adapter.FriendlyName == nil {
			continue
		}
		row, ok := ifRows[int(adapter.IfIndex)]
		if !ok {
			continue
		}
		candidate := windowsInterface{
			index:         int(adapter.IfIndex),
			name:          windows.UTF16PtrToString(adapter.FriendlyName),
			hardware:      row.InterfaceAndOperStatusFlags&0x08 != 0,
			up:            adapter.OperStatus == windows.IfOperStatusUp,
			luid:          row.InterfaceLuid,
			interfaceType: row.Type,
			tunnelType:    row.TunnelType,
		}
		for address := adapter.FirstUnicastAddress; address != nil; address = address.Next {
			ip := address.Address.IP()
			if ip == nil || ip.To4() == nil || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsUnspecified() {
				continue
			}
			if address.DadState == windows.NldsPreferred {
				candidate.usable = true
				break
			}
		}
		if !candidate.hardware || !physicalAdapterType(candidate.interfaceType, candidate.tunnelType) {
			continue
		}
		interfaceRow := windows.MibIpInterfaceRow{Family: windows.AF_INET, InterfaceLuid: candidate.luid}
		if err := windows.GetIpInterfaceEntry(&interfaceRow); err == nil && interfaceRow.Metric != 0 {
			candidate.interfaceMetric = interfaceRow.Metric
		} else {
			candidate.interfaceMetric = 1
		}
		result = append(result, candidate)
	}
	return result, nil
}
func physicalAdapterType(interfaceType, tunnelType uint32) bool {
	switch interfaceType {
	case windows.IF_TYPE_ETHERNET_CSMACD, windows.IF_TYPE_IEEE80211, windows.IF_TYPE_IEEE1394:
		return tunnelType == 0
	default:
		return false
	}
}

func windowsIPv4DefaultRoutes() ([]windowsRoute, error) {
	var table *windows.MibIpForwardTable2
	if err := windows.GetIpForwardTable2(windows.AF_INET, &table); err != nil {
		return nil, err
	}
	if table == nil {
		return nil, windows.ERROR_INTERNAL_ERROR
	}
	defer windows.FreeMibTable(unsafe.Pointer(table))
	var routes []windowsRoute
	for _, row := range table.Rows() {
		if row.DestinationPrefix.PrefixLength != 0 || row.NextHop.Family != windows.AF_INET || row.InterfaceIndex == 0 {
			continue
		}
		nextHop := (*windows.RawSockaddrInet4)(unsafe.Pointer(&row.NextHop)).Addr[:]
		if net.IP(nextHop).Equal(net.IPv4zero) {
			continue
		}
		routes = append(routes, windowsRoute{index: int(row.InterfaceIndex), metric: row.Metric})
	}
	return routes, nil
}
