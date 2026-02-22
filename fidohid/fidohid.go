// Package fidohid implements the CTAPHID protocol over a virtual HID device
// created via /dev/uhid. This allows a CTAP2 authenticator to appear as a
// hardware security key to browsers without any extension.
package fidohid

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"log"
	"sync"
	"time"

	"github.com/psanford/uhid"
)

// FIDO2 HID report descriptor (usage page 0xF1D0)
var fidoReportDescriptor = []byte{
	0x06, 0xD0, 0xF1, // Usage Page (FIDO Alliance)
	0x09, 0x01, // Usage (CTAPHID)
	0xA1, 0x01, // Collection (Application)
	0x09, 0x20, //   Usage (Data In)
	0x15, 0x00, //   Logical Minimum (0)
	0x26, 0xFF, 0x00, //   Logical Maximum (255)
	0x75, 0x08, //   Report Size (8)
	0x95, 0x40, //   Report Count (64)
	0x81, 0x02, //   Input (Data, Variable, Absolute)
	0x09, 0x21, //   Usage (Data Out)
	0x15, 0x00, //   Logical Minimum (0)
	0x26, 0xFF, 0x00, //   Logical Maximum (255)
	0x75, 0x08, //   Report Size (8)
	0x95, 0x40, //   Report Count (64)
	0x91, 0x02, //   Output (Data, Variable, Absolute)
	0xC0, // End Collection
}

// CTAPHID constants
const (
	reportLen   = 64
	initDataLen = 57 // 64 - 4(CID) - 1(CMD) - 2(BCNT)
	contDataLen = 59 // 64 - 4(CID) - 1(SEQ)

	broadcastCID uint32 = 0xFFFFFFFF
)

// CTAPHID command identifiers
const (
	cmdPing      = 0x01
	cmdMsg       = 0x03
	cmdInit      = 0x06
	cmdCBOR      = 0x10
	cmdCancel    = 0x11
	cmdKeepalive = 0x3B
	cmdError     = 0x3F
)

// CTAPHID error codes
const (
	errInvalidCmd     = 0x01
	errInvalidPar     = 0x02
	errInvalidLen     = 0x03
	errInvalidSeq     = 0x04
	errMsgTimeout     = 0x05
	errChannelBusy    = 0x06
	errLockRequired   = 0x0A
	errInvalidChannel = 0x0B
	errOther          = 0x7F
)

// Keepalive status codes
const (
	keepaliveProcessing = 0x01
	keepaliveUpNeeded   = 0x02
)

// CTAPHID capability flags
const (
	capCBOR = 0x04 // Device supports CTAPHID_CBOR
	capNMSG = 0x08 // Device does NOT support CTAPHID_MSG (no legacy U2F)
)

const (
	channelTimeout    = 30 * time.Second
	keepaliveInterval = 100 * time.Millisecond
)

// CommandHandler processes CTAP2 commands. Implemented by ctap2.Handler.
type CommandHandler interface {
	HandleCommand(ctx context.Context, cmd byte, data []byte) (status byte, response []byte)
}

// channel tracks per-channel CTAPHID transaction state
type channel struct {
	cmd        byte
	totalLen   uint16
	data       []byte
	seqNum     byte
	lastSeen   time.Time
	cancelFunc context.CancelFunc
}

// Device is a virtual FIDO2 HID device backed by /dev/uhid.
type Device struct {
	dev     *uhid.Device
	handler CommandHandler

	mu       sync.Mutex
	channels map[uint32]*channel

	writeMu sync.Mutex // serializes multi-packet HID responses
}

// New creates a new virtual FIDO2 HID device. The name appears in
// /sys/devices/virtual/misc/uhid/ and is matched by udev rules.
// Call Run() to start processing HID events.
func New(name string, handler CommandHandler) (*Device, error) {
	dev, err := uhid.NewDevice(name, fidoReportDescriptor)
	if err != nil {
		return nil, err
	}

	// Appear as a USB FIDO2 device
	dev.Data.Bus = 0x03       // BUS_USB
	dev.Data.VendorID = 0x1209  // pid.codes open-source VID
	dev.Data.ProductID = 0xF1D0 // FIDO-themed PID

	return &Device{
		dev:      dev,
		handler:  handler,
		channels: make(map[uint32]*channel),
	}, nil
}

// Run opens the virtual HID device and processes events until ctx is cancelled.
// It blocks until the context is done or an unrecoverable error occurs.
func (d *Device) Run(ctx context.Context) error {
	events, err := d.dev.Open(ctx)
	if err != nil {
		return err
	}

	// Log the hidraw nodes for debugging
	nodes, err := d.dev.HidrawNodes(ctx)
	if err == nil && len(nodes) > 0 {
		log.Printf("fidohid: virtual FIDO2 device created: %v", nodes)
	}

	go d.cleanupChannels(ctx)

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case ev, ok := <-events:
			if !ok {
				return nil
			}
			if ev.Err != nil {
				log.Printf("fidohid: event error: %v", ev.Err)
				continue
			}
			switch ev.Type {
			case uhid.Output:
				d.handleOutput(ev.Data)
			case uhid.Open:
				log.Printf("fidohid: device opened by host")
			case uhid.Close:
				log.Printf("fidohid: device closed by host")
			}
		}
	}
}

// Close destroys the virtual HID device.
func (d *Device) Close() error {
	// Cancel all in-progress operations
	d.mu.Lock()
	for _, ch := range d.channels {
		if ch.cancelFunc != nil {
			ch.cancelFunc()
		}
	}
	d.channels = make(map[uint32]*channel)
	d.mu.Unlock()

	return d.dev.Close()
}

// handleOutput processes a single HID output report from the host.
func (d *Device) handleOutput(data []byte) {
	// Linux hidraw prepends a report ID byte (0x00 for devices without
	// explicit Report IDs). The uhid Output event includes this prefix,
	// so skip it to get the actual 64-byte CTAPHID packet.
	if len(data) > 0 && data[0] == 0x00 {
		data = data[1:]
	}

	if len(data) < 7 {
		// Too short to be a valid CTAPHID packet
		return
	}

	// Pad short reports to 64 bytes
	if len(data) < reportLen {
		padded := make([]byte, reportLen)
		copy(padded, data)
		data = padded
	}

	cid := binary.BigEndian.Uint32(data[0:4])

	if data[4]&0x80 != 0 {
		// Initialization packet
		cmd := data[4] & 0x7F
		bcnt := binary.BigEndian.Uint16(data[5:7])
		d.handleInitPacket(cid, cmd, bcnt, data[7:])
	} else {
		// Continuation packet
		seq := data[4]
		d.handleContPacket(cid, seq, data[5:])
	}
}

// handleInitPacket processes a CTAPHID initialization packet.
func (d *Device) handleInitPacket(cid uint32, cmd byte, bcnt uint16, payload []byte) {
	log.Printf("fidohid: init CID=%08x CMD=0x%02x BCNT=%d", cid, cmd, bcnt)

	// INIT on broadcast CID is always allowed
	if cmd == cmdInit {
		d.handleInit(cid, payload[:min(int(bcnt), len(payload))])
		return
	}

	// All other commands require a valid (non-broadcast) CID
	if cid == broadcastCID {
		d.sendError(cid, errInvalidChannel)
		return
	}

	// CANCEL: cancel any in-progress operation on this channel
	if cmd == cmdCancel {
		log.Printf("fidohid: CANCEL CID=%08x", cid)
		d.mu.Lock()
		if ch, ok := d.channels[cid]; ok && ch.cancelFunc != nil {
			ch.cancelFunc()
		}
		d.mu.Unlock()
		return
	}

	// Cancel any existing transaction on this channel before starting a new one
	d.mu.Lock()
	if ch, ok := d.channels[cid]; ok && ch.cancelFunc != nil {
		ch.cancelFunc()
	}

	// Begin assembling the new message
	dataLen := min(int(bcnt), initDataLen, len(payload))
	msgData := make([]byte, 0, bcnt)
	msgData = append(msgData, payload[:dataLen]...)

	d.channels[cid] = &channel{
		cmd:      cmd,
		totalLen: bcnt,
		data:     msgData,
		seqNum:   0,
		lastSeen: time.Now(),
	}
	d.mu.Unlock()

	// If the full message fits in one packet, dispatch immediately
	if uint16(len(msgData)) >= bcnt {
		d.dispatchCommand(cid, cmd, msgData[:bcnt])
	}
}

// handleContPacket processes a CTAPHID continuation packet.
func (d *Device) handleContPacket(cid uint32, seq byte, payload []byte) {
	d.mu.Lock()
	ch, exists := d.channels[cid]
	if !exists || ch.totalLen == 0 {
		d.mu.Unlock()
		d.sendError(cid, errInvalidChannel)
		return
	}

	if seq != ch.seqNum {
		d.mu.Unlock()
		log.Printf("fidohid: bad seq CID=%08x expected=%d got=%d", cid, ch.seqNum, seq)
		d.sendError(cid, errInvalidSeq)
		return
	}

	remaining := int(ch.totalLen) - len(ch.data)
	dataLen := min(remaining, contDataLen, len(payload))
	ch.data = append(ch.data, payload[:dataLen]...)
	ch.seqNum++
	ch.lastSeen = time.Now()

	complete := uint16(len(ch.data)) >= ch.totalLen
	cmd := ch.cmd
	var data []byte
	if complete {
		data = make([]byte, ch.totalLen)
		copy(data, ch.data[:ch.totalLen])
		// Reset channel state but keep it alive
		ch.totalLen = 0
		ch.data = nil
	}
	d.mu.Unlock()

	if complete {
		d.dispatchCommand(cid, cmd, data)
	}
}

// handleInit processes a CTAPHID_INIT command.
func (d *Device) handleInit(cid uint32, nonce []byte) {
	log.Printf("fidohid: INIT from CID=%08x", cid)

	var newCID uint32

	if cid == broadcastCID {
		// Allocate a new random channel ID
		newCID = d.allocateCID()
	} else {
		// Re-sync: cancel existing transaction, reuse CID
		d.mu.Lock()
		if ch, ok := d.channels[cid]; ok && ch.cancelFunc != nil {
			ch.cancelFunc()
		}
		d.mu.Unlock()
		newCID = cid
	}

	d.mu.Lock()
	d.channels[newCID] = &channel{lastSeen: time.Now()}
	d.mu.Unlock()

	// INIT response: nonce(8) + CID(4) + version(1) + major(1) + minor(1) + build(1) + caps(1)
	resp := make([]byte, 17)
	copy(resp[0:8], nonce)
	binary.BigEndian.PutUint32(resp[8:12], newCID)
	resp[12] = 2                 // CTAPHID protocol version
	resp[13] = 1                 // Major version
	resp[14] = 0                 // Minor version
	resp[15] = 0                 // Build version
	resp[16] = capCBOR | capNMSG // Supports CTAP2/CBOR, no legacy U2F

	// Response goes on the CID the request arrived on
	d.sendResponse(cid, cmdInit, resp)
}

// dispatchCommand routes a fully-assembled CTAPHID message.
func (d *Device) dispatchCommand(cid uint32, cmd byte, data []byte) {
	switch cmd {
	case cmdCBOR:
		// CBOR commands may block (fingerprint), run in goroutine
		go d.handleCBOR(cid, data)
	case cmdPing:
		d.sendResponse(cid, cmdPing, data)
	case cmdMsg:
		// Legacy U2F not supported
		d.sendError(cid, errInvalidCmd)
	default:
		log.Printf("fidohid: unknown cmd 0x%02x", cmd)
		d.sendError(cid, errInvalidCmd)
	}
}

// handleCBOR dispatches a CTAP2 CBOR command and sends keepalives while waiting.
func (d *Device) handleCBOR(cid uint32, data []byte) {
	if len(data) < 1 {
		d.sendError(cid, errInvalidLen)
		return
	}

	ctapCmd := data[0]
	ctapData := data[1:]

	log.Printf("fidohid: CBOR cmd=0x%02x datalen=%d", ctapCmd, len(ctapData))

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Store cancel so CTAPHID_CANCEL can abort the operation
	d.mu.Lock()
	if ch, ok := d.channels[cid]; ok {
		ch.cancelFunc = cancel
	} else {
		d.channels[cid] = &channel{cancelFunc: cancel, lastSeen: time.Now()}
	}
	d.mu.Unlock()

	// Run HandleCommand in a goroutine; send keepalives while it blocks
	type result struct {
		status byte
		resp   []byte
	}
	resultCh := make(chan result, 1)

	go func() {
		status, resp := d.handler.HandleCommand(ctx, ctapCmd, ctapData)
		resultCh <- result{status, resp}
	}()

	ticker := time.NewTicker(keepaliveInterval)
	defer ticker.Stop()

	for {
		select {
		case r := <-resultCh:
			// CTAPHID_CBOR response: [status_byte][cbor_data...]
			resp := make([]byte, 1+len(r.resp))
			resp[0] = r.status
			copy(resp[1:], r.resp)
			d.sendResponse(cid, cmdCBOR, resp)

			d.mu.Lock()
			if ch, ok := d.channels[cid]; ok {
				ch.cancelFunc = nil
			}
			d.mu.Unlock()
			return

		case <-ticker.C:
			d.sendKeepalive(cid, keepaliveProcessing)

		case <-ctx.Done():
			d.mu.Lock()
			if ch, ok := d.channels[cid]; ok {
				ch.cancelFunc = nil
			}
			d.mu.Unlock()
			return
		}
	}
}

// sendResponse sends a CTAPHID response, fragmenting into 64-byte HID reports.
func (d *Device) sendResponse(cid uint32, cmd byte, data []byte) {
	d.writeMu.Lock()
	defer d.writeMu.Unlock()

	// Initialization packet
	pkt := make([]byte, reportLen)
	binary.BigEndian.PutUint32(pkt[0:4], cid)
	pkt[4] = cmd | 0x80
	binary.BigEndian.PutUint16(pkt[5:7], uint16(len(data)))

	n := copy(pkt[7:], data)
	if err := d.dev.InjectEvent(pkt); err != nil {
		log.Printf("fidohid: inject error: %v", err)
		return
	}

	data = data[n:]
	seq := byte(0)

	// Continuation packets
	for len(data) > 0 {
		pkt = make([]byte, reportLen)
		binary.BigEndian.PutUint32(pkt[0:4], cid)
		pkt[4] = seq
		n = copy(pkt[5:], data)
		if err := d.dev.InjectEvent(pkt); err != nil {
			log.Printf("fidohid: inject error: %v", err)
			return
		}
		data = data[n:]
		seq++
	}
}

// sendError sends a CTAPHID_ERROR response.
func (d *Device) sendError(cid uint32, code byte) {
	d.sendResponse(cid, cmdError, []byte{code})
}

// sendKeepalive sends a CTAPHID_KEEPALIVE message.
func (d *Device) sendKeepalive(cid uint32, status byte) {
	d.sendResponse(cid, cmdKeepalive, []byte{status})
}

// allocateCID generates a random unique channel ID.
func (d *Device) allocateCID() uint32 {
	d.mu.Lock()
	defer d.mu.Unlock()

	for {
		var buf [4]byte
		if _, err := rand.Read(buf[:]); err != nil {
			// Fallback to sequential
			cid := uint32(time.Now().UnixNano() & 0x7FFFFFFF)
			if cid != 0 && cid != broadcastCID {
				return cid
			}
			continue
		}
		cid := binary.BigEndian.Uint32(buf[:])
		if cid != 0 && cid != broadcastCID {
			if _, exists := d.channels[cid]; !exists {
				return cid
			}
		}
	}
}

// cleanupChannels removes idle channels that have exceeded the timeout.
func (d *Device) cleanupChannels(ctx context.Context) {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			d.mu.Lock()
			now := time.Now()
			for cid, ch := range d.channels {
				if now.Sub(ch.lastSeen) > channelTimeout {
					if ch.cancelFunc != nil {
						ch.cancelFunc()
					}
					delete(d.channels, cid)
				}
			}
			d.mu.Unlock()
		}
	}
}
