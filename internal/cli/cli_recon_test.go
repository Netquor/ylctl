package cli

import "testing"

func TestIPLessAndStateColors(t *testing.T) {
	if !ipLess("10.0.0.9", "10.0.0.10") || ipLess("10.0.0.10", "10.0.0.9") {
		t.Error("addresses must sort numerically, not as text")
	}
	a := &app{}
	for _, s := range []string{stManaged, stRegistered, stUnregistered, stNoAuth, stLocked, stError} {
		if a.stateColor(&reconPhone{State: s}) == "" || a.stateText(&reconPhone{State: s}) == "" {
			t.Errorf("state %s has no color or text", s)
		}
	}
	p := &reconPhone{State: stRegistered, RegHere: true, Registered: []string{"1002@pbx"}}
	if a.stateText(p) == a.stateText(&reconPhone{State: stRegistered, Registered: []string{"1002@pbx"}}) {
		t.Error("registered-to-your-PBX must read differently from registered-elsewhere")
	}
}
