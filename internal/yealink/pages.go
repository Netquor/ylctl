package yealink

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// ---- status ----

// AccountState is a registration state.
type AccountState struct {
	Code     int    `json:"code"`
	Name     string `json:"state"`
	Observed bool   `json:"observed_live"` // true when seen on a real phone, false when taken from the phone's own JavaScript only
}

// StateFromCode maps the phone's account status code. The mapping is the one
// in the phone's own JavaScript (TransAccountStatus): -1,4,7,8,9,10 count as
// registering, 5 and 11 as registered. Codes 0 and 2 were observed on real phones.
func StateFromCode(code int) AccountState {
	s := AccountState{Code: code}
	switch code {
	case 0:
		s.Name, s.Observed = "disabled", true
	case 1:
		s.Name = "registering"
	case 2:
		s.Name, s.Observed = "registered", true
	case 3:
		s.Name = "failed"
	case 6:
		s.Name = "inexistent"
	case -1, 4, 7, 8, 9, 10:
		s.Name = "registering"
	case 5, 11:
		s.Name = "registered"
	default:
		s.Name = "unknown"
	}
	return s
}

// AccountStatus is one line of the status page's account list.
type AccountStatus struct {
	Index int          `json:"index"`
	Label string       `json:"account"` // user@host as the phone shows it, empty if disabled
	State AccountState `json:"state"`
}

// Info identifies the device.
type Info struct {
	Model         string `json:"model"`
	Firmware      string `json:"firmware"`
	Hardware      string `json:"hardware"`
	MAC           string `json:"mac"`
	IP            string `json:"ip"`
	UptimeSeconds int64  `json:"uptime_seconds"`
	UptimeText    string `json:"uptime"`
}

// Network is the IPv4 setup shown on the status page.
type Network struct {
	WANType    string `json:"wan_type"`
	IP         string `json:"ip"`
	Mask       string `json:"mask"`
	Gateway    string `json:"gateway"`
	DNS1       string `json:"dns1"`
	DNS2       string `json:"dns2"`
	VLANID     string `json:"vlan_id"`
	LinkStatus string `json:"link"`
}

// StatusPage is everything parsed from the status page.
type StatusPage struct {
	Info     Info            `json:"info"`
	Network  Network         `json:"network"`
	Accounts []AccountStatus `json:"accounts"`
}

// ParseStatus parses the status page. It never panics; it returns
// ErrUnexpectedPage when the key labels are missing.
func ParseStatus(page string) (*StatusPage, error) {
	fw, ok := LabelValue(page, "PhoneFirmware")
	if !ok || fw == "" {
		return nil, fmt.Errorf("%w: status page without firmware version", ErrUnexpectedPage)
	}
	lv := func(id string) string { v, _ := LabelValue(page, id); return v }
	vars := JSVars(page)
	sp := &StatusPage{}
	sp.Info = Info{
		Model:    vars["g_phonetype"],
		Firmware: fw,
		Hardware: lv("hardware-version"),
		MAC:      strings.ToUpper(lv("tdMACAddress")),
		IP:       lv("tdWANIP"),
	}
	if secs, err := strconv.ParseInt(lv("tdPowerOnTime"), 10, 64); err == nil && secs >= 0 {
		sp.Info.UptimeSeconds = secs
		sp.Info.UptimeText = FormatUptime(secs)
	}
	wan := map[string]string{"0": "DHCP", "1": "PPPoE", "2": "Static IP"}
	wt := lv("NetworkWanType")
	if n, ok := wan[wt]; ok {
		wt = n
	}
	sp.Network = Network{
		WANType: wt, IP: lv("tdWANIP"), Mask: lv("tdSubnetMask"), Gateway: lv("tdGateway"),
		DNS1: lv("tdPrimaryDNS"), DNS2: lv("tdSecondaryDNS"), VLANID: lv("vlanid"),
		LinkStatus: LinkText(lv("tdWANProtStatus")),
	}
	if obj, ok := ParseJSObject(page, "g_dataAccStatus"); ok {
		keys := make([]string, 0, len(obj))
		for k := range obj {
			keys = append(keys, k)
		}
		sort.Slice(keys, func(i, j int) bool { return accIndex(keys[i]) < accIndex(keys[j]) })
		for _, k := range keys {
			raw, _ := obj[k].(string)
			label, code := splitAccountStatus(raw)
			sp.Accounts = append(sp.Accounts, AccountStatus{Index: accIndex(k), Label: label, State: StateFromCode(code)})
		}
	}
	return sp, nil
}

func accIndex(key string) int {
	n, err := strconv.Atoi(strings.TrimPrefix(key, "Account"))
	if err != nil {
		return 1 << 20
	}
	return n
}

// splitAccountStatus splits "1004@host:2" at the last colon. A bare "0" means disabled.
func splitAccountStatus(s string) (label string, code int) {
	i := strings.LastIndex(s, ":")
	numStr := s
	if i >= 0 {
		label, numStr = s[:i], s[i+1:]
	}
	n, err := strconv.Atoi(strings.TrimSpace(numStr))
	if err != nil {
		return label, 99
	}
	return label, n
}

// FormatUptime renders seconds like the phone's own page: "0 days 01:00".
func FormatUptime(secs int64) string {
	return fmt.Sprintf("%d days %02d:%02d", secs/86400, secs/3600%24, secs/60%60)
}

// LinkText decodes the port status bit mask (see InitPortStatus in the phone's page_status.js).
func LinkText(v string) string {
	t, err := strconv.Atoi(v)
	if err != nil {
		return ""
	}
	switch {
	case t&64 != 0:
		return "1000Mbps Full Duplex"
	case t&32 != 0:
		return "1000Mbps Half Duplex"
	case t&16 != 0:
		return "100Mbps Full Duplex"
	case t&8 != 0:
		return "100Mbps Half Duplex"
	case t&4 != 0:
		return "10Mbps Full Duplex"
	case t&2 != 0:
		return "10Mbps Half Duplex"
	}
	return "Link Down"
}

// ---- settings-autop ----

// Autop holds the Auto Provision fields of the settings-autop page.
type Autop struct {
	Fields []Field
}

// Get returns a field value.
func (a *Autop) Get(name string) (string, bool) {
	for _, f := range a.Fields {
		if f.Name == name {
			return f.Value, true
		}
	}
	return "", false
}

// ServerURL, EnablePNP, EnableDHCP and RepeatMinutes are the fields adopt works with.
const (
	FieldServerURL     = "AutoProvisionServerURL"
	FieldEnablePNP     = "AutoProvisionEnablePNP"
	FieldEnableDHCP    = "AutoProvisionEnableDHCPOption"
	FieldPowerOn       = "AutoProvisionPowerOn"
	FieldRepeatMinutes = "AutoProvisionRepeatMinutes"
)

// ParseAutop collects every AutoProvision* field (the *_hour/_min helper
// inputs of the time pickers are skipped).
func ParseAutop(page string) (*Autop, error) {
	a := &Autop{}
	for _, f := range ParseFields(page) {
		if !strings.HasPrefix(f.Name, "AutoProvision") || strings.HasSuffix(f.Name, "_hour") || strings.HasSuffix(f.Name, "_min") {
			continue
		}
		a.Fields = append(a.Fields, f)
	}
	if _, ok := a.Get(FieldServerURL); !ok {
		return nil, fmt.Errorf("%w: settings-autop page without %s", ErrUnexpectedPage, FieldServerURL)
	}
	return a, nil
}

// Display returns the value as it may be printed: secrets masked, the
// provisioning URL shortened unless reveal is set.
func Display(name, value string, reveal bool) string {
	if name == FieldServerURL {
		if reveal {
			return value
		}
		return MaskURL(value)
	}
	return MaskValue(name, value)
}

// ---- account-register ----

// Account is the Register page of one account.
type Account struct {
	Number       int           `json:"account"`
	Enabled      bool          `json:"enabled"`
	Label        string        `json:"label"`
	DisplayName  string        `json:"display_name"`
	RegisterName string        `json:"register_name"`
	UserName     string        `json:"user_name"`
	Password     string        `json:"password"`
	Servers      []SIPServer   `json:"servers"`
	Outbound     OutboundProxy `json:"outbound_proxy"`
}

// SIPServer is one SIP server entry.
type SIPServer struct {
	Host      string `json:"host"`
	Port      string `json:"port"`
	Transport string `json:"transport"`
}

// OutboundProxy is the outbound proxy block.
type OutboundProxy struct {
	Enabled bool   `json:"enabled"`
	Host    string `json:"host"`
	Port    string `json:"port"`
}

var transportNames = map[string]string{"0": "UDP", "1": "TCP", "2": "TLS", "3": "DNS-NAPTR"}

// ParseAccount parses the account-register page for account number n (1-based).
func ParseAccount(page string, n int) (*Account, error) {
	fm := FieldMap(ParseFields(page))
	if _, ok := fm["AccountLabel"]; !ok {
		return nil, fmt.Errorf("%w: account page without AccountLabel", ErrUnexpectedPage)
	}
	v := func(name string) string { return fm[name].Value }
	acc := &Account{
		Number: n, Enabled: v("AccountEnable") == "1", Label: v("AccountLabel"), DisplayName: v("AccountDisplayName"),
		RegisterName: v("AccountRegisterName"), UserName: v("AccountUserName"),
		Password: MaskValue("AccountPassword", v("AccountPassword")),
	}
	for i := 1; i <= 2; i++ {
		host, ok := fm["server"+strconv.Itoa(i)]
		if !ok {
			continue
		}
		t := v("Transport" + strconv.Itoa(i))
		if name, ok := transportNames[t]; ok {
			t = name
		}
		acc.Servers = append(acc.Servers, SIPServer{Host: host.Value, Port: v("port" + strconv.Itoa(i)), Transport: t})
	}
	acc.Outbound = OutboundProxy{Enabled: v("AccountOutboundSwitch") == "1", Host: v("AccountOutboundProxy"), Port: v("AccountOutboundPort")}
	return acc, nil
}
