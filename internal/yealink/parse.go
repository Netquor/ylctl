package yealink

import (
	"encoding/json"
	"html"
	"regexp"
	"strconv"
	"strings"
)

var (
	reTag      = regexp.MustCompile(`(?is)<(input|select|textarea)\b((?:[^>"']|"[^"]*"|'[^']*')*)>`)
	reAttr     = regexp.MustCompile(`([A-Za-z_:][-A-Za-z0-9_:.]*)\s*=\s*(?:"([^"]*)"|'([^']*)')`)
	reToken    = regexp.MustCompile(`g_strToken\s*=\s*"([^"]*)"`)
	reJSVar    = regexp.MustCompile(`var\s+(g_[A-Za-z_]+)\s*=\s*"([^"]*)"\s*;`)
	reResInfo  = regexp.MustCompile(`(?is)<div[^>]*id="_RES_INFO_"[^>]*>(.*?)</div>`)
	reTitle    = regexp.MustCompile(`(?is)<title>(.*?)</title>`)
	reAssetVer = regexp.MustCompile(`\?(\d+\.\d+\.\d+\.\d+)`)
)

// Field is one named form control as found on a phone settings page.
type Field struct {
	Name  string
	Value string // the current value (the page's dvalue, falling back to value)
	Tag   string // input, select or textarea
	Type  string // input type, if any
}

func attrs(s string) map[string]string {
	m := map[string]string{}
	for _, a := range reAttr.FindAllStringSubmatch(s, -1) {
		v := a[2]
		if v == "" {
			v = a[3]
		}
		k := strings.ToLower(a[1])
		if _, seen := m[k]; !seen {
			m[k] = html.UnescapeString(v)
		}
	}
	return m
}

// ParseFields returns the named controls in page order. The first control of a
// name wins (radio groups repeat the name). Controls without a name are skipped.
func ParseFields(page string) []Field {
	var out []Field
	seen := map[string]bool{}
	for _, m := range reTag.FindAllStringSubmatch(page, -1) {
		a := attrs(m[2])
		name := a["name"]
		if name == "" || seen[name] {
			continue
		}
		seen[name] = true
		v, ok := a["dvalue"]
		if !ok {
			v = a["value"]
		}
		out = append(out, Field{Name: name, Value: v, Tag: strings.ToLower(m[1]), Type: strings.ToLower(a["type"])})
	}
	return out
}

// FieldMap indexes ParseFields by name.
func FieldMap(fs []Field) map[string]Field {
	m := make(map[string]Field, len(fs))
	for _, f := range fs {
		m[f.Name] = f
	}
	return m
}

// ParseToken extracts the CSRF token (g_strToken) of a page.
func ParseToken(page string) (string, bool) {
	m := reToken.FindStringSubmatch(page)
	if m == nil || m[1] == "" {
		return "", false
	}
	return m[1], true
}

// JSVars returns the simple string variables the phone defines (g_phonetype, g_strFirmware, ...).
func JSVars(page string) map[string]string {
	m := map[string]string{}
	for _, v := range reJSVar.FindAllStringSubmatch(page, -1) {
		if _, ok := m[v[1]]; !ok {
			m[v[1]] = v[2]
		}
	}
	return m
}

// LabelValue returns the dvalue (or inner text) of <label id="id">.
func LabelValue(page, id string) (string, bool) {
	re := regexp.MustCompile(`(?is)<label\b([^>]*\bid="` + regexp.QuoteMeta(id) + `"[^>]*)>(.*?)</label>`)
	m := re.FindStringSubmatch(page)
	if m == nil {
		return "", false
	}
	a := attrs(m[1])
	if v, ok := a["dvalue"]; ok {
		return strings.TrimSpace(v), true
	}
	return strings.TrimSpace(html.UnescapeString(m[2])), true
}

// ParseResInfo returns the content of <div id="_RES_INFO_"> if present.
func ParseResInfo(page string) (string, bool) {
	m := reResInfo.FindStringSubmatch(page)
	if m == nil {
		return "", false
	}
	return strings.TrimSpace(html.UnescapeString(m[1])), true
}

// ParseJSObject decodes g_json.ParseJSON("{...}") assigned to varName.
func ParseJSObject(page, varName string) (map[string]any, bool) {
	re := regexp.MustCompile(`\b` + regexp.QuoteMeta(varName) + `\s*=\s*g_json\.ParseJSON\(("(?:\\.|[^"\\])*")\)`)
	m := re.FindStringSubmatch(page)
	if m == nil {
		return nil, false
	}
	s, err := strconv.Unquote(m[1])
	if err != nil {
		// JavaScript escapes that Go does not know: fall back to the common case.
		s = strings.ReplaceAll(m[1][1:len(m[1])-1], `\"`, `"`)
		s = strings.ReplaceAll(s, `\\`, `\`)
	}
	var obj map[string]any
	if err := json.Unmarshal([]byte(s), &obj); err != nil {
		return nil, false
	}
	return obj, true
}

// IsLoginPage reports whether a body is the phone's login page (session lost).
func IsLoginPage(body string) bool {
	if strings.Contains(body, "page_login.js") || strings.Contains(body, `id="idUsername"`) {
		return true
	}
	if v, ok := ParseResInfo(body); ok {
		var o map[string]any
		if json.Unmarshal([]byte(v), &o) == nil {
			if s, _ := o["authstatus"].(string); s != "" && s != "done" {
				return true
			}
		}
	}
	return false
}

// PageIdentity is what a login page reveals without logging in.
type PageIdentity struct {
	Model    string
	Firmware string
}

// IdentifyLoginPage recognises a Yealink login form and reads model and firmware from it.
func IdentifyLoginPage(body string) (PageIdentity, bool) {
	if !strings.Contains(body, "page_login.js") && !strings.Contains(body, "Yealink") {
		return PageIdentity{}, false
	}
	v := JSVars(body)
	id := PageIdentity{Model: v["g_phonetype"], Firmware: v["g_strFirmware"]}
	if id.Firmware == "" {
		if m := reAssetVer.FindStringSubmatch(body); m != nil {
			id.Firmware = m[1]
		}
	}
	if id.Model == "" {
		if m := reTitle.FindStringSubmatch(body); m != nil {
			t := strings.Fields(html.UnescapeString(m[1]))
			if len(t) >= 2 && strings.EqualFold(t[0], "Yealink") {
				id.Model = t[1]
			}
		}
	}
	if !strings.Contains(body, "page_login.js") && id.Model == "" {
		return PageIdentity{}, false
	}
	return id, true
}
