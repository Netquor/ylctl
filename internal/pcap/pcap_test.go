package pcap

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"
	"time"
)

func sample(t *testing.T, n int) []byte {
	t.Helper()
	var b bytes.Buffer
	w := NewWriter(&b, LinkEthernet, 65535)
	for i := 0; i < n; i++ {
		data := bytes.Repeat([]byte{byte(i + 1)}, 20+i)
		if err := w.WritePacket(Packet{Time: time.Unix(1700000000+int64(i), 123000), Data: data, OrigLen: uint32(len(data))}); err != nil {
			t.Fatal(err)
		}
	}
	return b.Bytes()
}

func TestSplitEverywhere(t *testing.T) {
	raw := sample(t, 4)
	for step := 1; step <= 40; step++ {
		var p Parser
		var got []Packet
		for i := 0; i < len(raw); i += step {
			end := min(i+step, len(raw))
			pk, err := p.Feed(raw[i:end])
			if err != nil {
				t.Fatalf("step %d: %v", step, err)
			}
			got = append(got, pk...)
		}
		if len(got) != 4 {
			t.Fatalf("step %d: got %d packets", step, len(got))
		}
		if got[2].Time.Unix() != 1700000002 || got[2].Time.Nanosecond() != 123000 || len(got[2].Data) != 22 {
			t.Fatalf("step %d: bad packet %+v", step, got[2])
		}
		if err := p.Finish(); err != nil {
			t.Fatal(err)
		}
	}
}

func TestTruncatedTail(t *testing.T) {
	raw := sample(t, 3)
	var p Parser
	pk, err := p.Feed(raw[:len(raw)-5])
	if err != nil || len(pk) != 2 {
		t.Fatalf("pk=%d err=%v", len(pk), err)
	}
	if err := p.Finish(); !errors.Is(err, ErrTruncated) {
		t.Fatalf("want ErrTruncated, got %v", err)
	}
	if p.Buffered() == 0 {
		t.Fatal("tail should stay buffered")
	}
}

func TestBadMagicEarly(t *testing.T) {
	var p Parser
	if _, err := p.Feed([]byte("GET ")); !errors.Is(err, ErrBadMagic) {
		t.Fatalf("got %v", err)
	}
	if _, err := p.Feed([]byte{1}); !errors.Is(err, ErrBadMagic) {
		t.Fatal("parser must stay failed")
	}
}

func TestHugeLengthNotAllocated(t *testing.T) {
	raw := sample(t, 1)[:24]
	rec := make([]byte, 16)
	binary.LittleEndian.PutUint32(rec[8:], 0xffffffff)
	binary.LittleEndian.PutUint32(rec[12:], 0xffffffff)
	var p Parser
	_, err := p.Feed(append(raw, rec...))
	if !errors.Is(err, ErrBadRecord) {
		t.Fatalf("got %v", err)
	}
	if p.Buffered() > 64 {
		t.Fatalf("buffered %d", p.Buffered())
	}
}

func TestBigEndianAndNano(t *testing.T) {
	h := make([]byte, 24)
	binary.BigEndian.PutUint32(h[0:], 0xa1b23c4d)
	binary.BigEndian.PutUint16(h[4:], 2)
	binary.BigEndian.PutUint16(h[6:], 4)
	binary.BigEndian.PutUint32(h[16:], 65535)
	binary.BigEndian.PutUint32(h[20:], 1)
	rec := make([]byte, 16+3)
	binary.BigEndian.PutUint32(rec[0:], 10)
	binary.BigEndian.PutUint32(rec[4:], 999)
	binary.BigEndian.PutUint32(rec[8:], 3)
	binary.BigEndian.PutUint32(rec[12:], 3)
	var p Parser
	pk, err := p.Feed(append(h, rec...))
	if err != nil || len(pk) != 1 || pk[0].Time.Nanosecond() != 999 {
		t.Fatalf("pk=%v err=%v", pk, err)
	}
}

func TestEmptyFinish(t *testing.T) {
	var p Parser
	if p.Finish() == nil {
		t.Fatal("empty stream must not be a clean finish")
	}
}

func FuzzParser(f *testing.F) {
	f.Add(sample(&testing.T{}, 2), 7)
	f.Add([]byte{0xd4, 0xc3, 0xb2, 0xa1}, 1)
	f.Fuzz(func(t *testing.T, data []byte, step int) {
		if step < 1 {
			step = 1
		}
		var p Parser
		for i := 0; i < len(data); i += step {
			end := min(i+step, len(data))
			if _, err := p.Feed(data[i:end]); err != nil {
				break
			}
			if p.Buffered() > DefaultMaxPacket+16+24 {
				t.Fatalf("buffer grew to %d", p.Buffered())
			}
		}
		_ = p.Finish()
	})
}
