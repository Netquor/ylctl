// Package pcap reads and writes the classic pcap capture format incrementally.
//
// The phone streams a pcap file while it is still being written, so the parser
// takes whatever bytes have arrived (a record may be split anywhere), returns
// the packets that are complete and keeps the rest for the next call.
// It never allocates from a length field it has not validated.
package pcap

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"time"
)

// Link types this package knows by name (others are passed through as numbers).
const (
	LinkNull     = 0
	LinkEthernet = 1
	LinkRaw      = 101
	LinkLinuxSLL = 113
)

// DefaultMaxPacket bounds one record. The phone's snaplen is 65535; anything
// larger than this is treated as a corrupt stream, not as a reason to wait.
const DefaultMaxPacket = 262144

var (
	// ErrBadMagic means the first four bytes are not a pcap magic number.
	ErrBadMagic = errors.New("pcap: not a pcap stream (bad magic number)")
	// ErrBadRecord means a record header carries an impossible length.
	ErrBadRecord = errors.New("pcap: corrupt record header")
	// ErrTruncated is reported by Finish when the stream ends inside a header or record.
	ErrTruncated = errors.New("pcap: stream ends inside a record")
)

// Header is the global pcap header.
type Header struct {
	Major, Minor uint16
	SnapLen      uint32
	LinkType     uint32
	Nano         bool // timestamps carry nanoseconds, not microseconds
	BigEndian    bool
}

// Packet is one captured frame. Data is owned by the caller.
type Packet struct {
	Time    time.Time
	CapLen  uint32
	OrigLen uint32
	Data    []byte
}

// Parser is an incremental pcap parser. The zero value is ready to use.
type Parser struct {
	MaxPacket uint32 // 0 means DefaultMaxPacket

	buf     []byte
	hdr     Header
	haveHdr bool
	failed  error
	bytesIn int64
}

// Header returns the global header once enough bytes have arrived.
func (p *Parser) Header() (Header, bool) { return p.hdr, p.haveHdr }

// Buffered returns how many bytes are held back waiting for the rest of a record.
func (p *Parser) Buffered() int { return len(p.buf) }

// BytesIn returns the total bytes fed so far.
func (p *Parser) BytesIn() int64 { return p.bytesIn }

func (p *Parser) max() uint32 {
	if p.MaxPacket == 0 {
		return DefaultMaxPacket
	}
	return p.MaxPacket
}

// Feed adds bytes and returns every packet that is now complete. After an
// error the parser stays failed and returns the same error.
func (p *Parser) Feed(b []byte) ([]Packet, error) {
	if p.failed != nil {
		return nil, p.failed
	}
	p.bytesIn += int64(len(b))
	p.buf = append(p.buf, b...)
	if !p.haveHdr {
		if len(p.buf) < 24 {
			// Reject early when the bytes seen so far cannot be a magic number.
			if len(p.buf) >= 4 {
				if _, _, _, ok := magic(p.buf); !ok {
					p.failed = ErrBadMagic
					return nil, p.failed
				}
			}
			return nil, nil
		}
		bo, nano, big, ok := magic(p.buf)
		if !ok {
			p.failed = ErrBadMagic
			return nil, p.failed
		}
		p.hdr = Header{
			Major: bo.Uint16(p.buf[4:]), Minor: bo.Uint16(p.buf[6:]),
			SnapLen: bo.Uint32(p.buf[16:]), LinkType: bo.Uint32(p.buf[20:]),
			Nano: nano, BigEndian: big,
		}
		p.haveHdr = true
		p.buf = p.buf[24:]
	}
	var out []Packet
	bo := p.order()
	for {
		if len(p.buf) < 16 {
			break
		}
		sec := bo.Uint32(p.buf[0:])
		frac := bo.Uint32(p.buf[4:])
		capLen := bo.Uint32(p.buf[8:])
		origLen := bo.Uint32(p.buf[12:])
		if capLen > p.max() || (p.hdr.SnapLen != 0 && capLen > p.hdr.SnapLen && capLen > 65535) {
			p.failed = fmt.Errorf("%w: captured length %d is larger than the limit %d", ErrBadRecord, capLen, p.max())
			return out, p.failed
		}
		if origLen < capLen {
			origLen = capLen // some writers leave it zero; never report less than we hold
		}
		if uint32(len(p.buf)-16) < capLen {
			break // the rest of this record has not arrived yet
		}
		data := make([]byte, capLen)
		copy(data, p.buf[16:16+capLen])
		var t time.Time
		if p.hdr.Nano {
			t = time.Unix(int64(sec), int64(frac))
		} else {
			t = time.Unix(int64(sec), int64(frac)*1000)
		}
		out = append(out, Packet{Time: t, CapLen: capLen, OrigLen: origLen, Data: data})
		p.buf = p.buf[16+capLen:]
	}
	// Do not let the backing array grow without bound.
	if len(p.buf) == 0 {
		p.buf = nil
	}
	return out, nil
}

// Finish reports whether the stream ended cleanly. A partial record at the end
// is returned as ErrTruncated (the packets before it were already delivered).
func (p *Parser) Finish() error {
	if p.failed != nil {
		return p.failed
	}
	if !p.haveHdr {
		if len(p.buf) == 0 {
			return io.ErrUnexpectedEOF
		}
		return fmt.Errorf("%w: only %d header bytes", ErrTruncated, len(p.buf))
	}
	if len(p.buf) > 0 {
		return fmt.Errorf("%w: %d trailing bytes", ErrTruncated, len(p.buf))
	}
	return nil
}

func (p *Parser) order() binary.ByteOrder {
	if p.hdr.BigEndian {
		return binary.BigEndian
	}
	return binary.LittleEndian
}

func magic(b []byte) (bo binary.ByteOrder, nano, big, ok bool) {
	if len(b) < 4 {
		return nil, false, false, false
	}
	switch binary.LittleEndian.Uint32(b) {
	case 0xa1b2c3d4:
		return binary.LittleEndian, false, false, true
	case 0xa1b23c4d:
		return binary.LittleEndian, true, false, true
	case 0xd4c3b2a1:
		return binary.BigEndian, false, true, true
	case 0x4d3cb2a1:
		return binary.BigEndian, true, true, true
	}
	return nil, false, false, false
}

// Writer writes a little-endian, microsecond pcap stream.
type Writer struct {
	w       io.Writer
	started bool
	snap    uint32
	link    uint32
}

// NewWriter prepares a writer; the file header is written with the first packet
// or by WriteHeader.
func NewWriter(w io.Writer, link, snap uint32) *Writer {
	if snap == 0 {
		snap = 65535
	}
	return &Writer{w: w, link: link, snap: snap}
}

// WriteHeader writes the global header once.
func (w *Writer) WriteHeader() error {
	if w.started {
		return nil
	}
	w.started = true
	h := make([]byte, 24)
	binary.LittleEndian.PutUint32(h[0:], 0xa1b2c3d4)
	binary.LittleEndian.PutUint16(h[4:], 2)
	binary.LittleEndian.PutUint16(h[6:], 4)
	binary.LittleEndian.PutUint32(h[16:], w.snap)
	binary.LittleEndian.PutUint32(h[20:], w.link)
	_, err := w.w.Write(h)
	return err
}

// WritePacket writes one record (header and data in a single Write call so a
// live reader never sees half a header from this process).
func (w *Writer) WritePacket(p Packet) error {
	if err := w.WriteHeader(); err != nil {
		return err
	}
	rec := make([]byte, 16+len(p.Data))
	binary.LittleEndian.PutUint32(rec[0:], uint32(p.Time.Unix()))
	binary.LittleEndian.PutUint32(rec[4:], uint32(p.Time.Nanosecond()/1000))
	binary.LittleEndian.PutUint32(rec[8:], uint32(len(p.Data)))
	orig := p.OrigLen
	if orig < uint32(len(p.Data)) {
		orig = uint32(len(p.Data))
	}
	binary.LittleEndian.PutUint32(rec[12:], orig)
	copy(rec[16:], p.Data)
	_, err := w.w.Write(rec)
	return err
}
