package discordgo

/*
#cgo pkg-config: dave
#include <dave/dave.h>
#include <stdlib.h>

static void recordDAVEFailure(const char* source, const char* reason, void* data) {
    *(bool*)data = true;
}
// Native diagnostic messages include complete handshake payloads. Report
// failures through the voice logger without recording cryptographic material.
static void quietDAVELog(DAVELoggingSeverity severity, const char* file, int line, const char* message) {}
static void initDAVELogging(void) { daveSetLogSinkCallback(quietDAVELog); }
static DAVESessionHandle newDAVENativeSession(bool* failed) {
    return daveSessionCreate(NULL, NULL, recordDAVEFailure, failed);
}
*/
import "C"

import (
	"bytes"
	"errors"
	"fmt"
	"runtime"
	"strconv"
	"sync"
	"unsafe"
)

var (
	opusSilencePacket    = [3]byte{0xF8, 0xFF, 0xFE}
	errDAVECommitIgnored = errors.New("MLS commit is not applicable to this group")
	daveLoggingOnce      sync.Once
)

const maxDAVEMessageSize = 1 << 20

type daveTransition struct {
	version int
	epoch   string
	serial  uint64
	ratchet C.DAVEKeyRatchetHandle
}

type daveNative struct {
	session    C.DAVESessionHandle
	failed     *C.bool
	encryptor  C.DAVEEncryptorHandle
	decryptors map[string]C.DAVEDecryptorHandle
	pending    map[uint16]daveTransition
}

func (n *daveNative) clearMedia() {
	for _, transition := range n.pending {
		C.daveKeyRatchetDestroy(transition.ratchet)
	}
	n.pending = make(map[uint16]daveTransition)
	for _, decryptor := range n.decryptors {
		C.daveDecryptorDestroy(decryptor)
	}
	n.decryptors = make(map[string]C.DAVEDecryptorHandle)
	if n.encryptor != nil {
		C.daveEncryptorDestroy(n.encryptor)
	}
	n.encryptor = nil
}

func (n *daveNative) close() {
	n.clearMedia()
	if n.session != nil {
		C.daveSessionDestroy(n.session)
		n.session = nil
	}
	C.free(unsafe.Pointer(n.failed))
	n.failed = nil
}

// DAVESession owns the MLS group and Opus cryptors. All native state, including
// teardown, is serialized so the voice sender and receiver can use it together.
// SetChannelID must be called before generating the first key package.
// Close releases native resources; Reset keeps the session reusable.
// Applications normally use the session owned by VoiceConnection.
type DAVESession struct {
	mu                  sync.Mutex
	native              *daveNative
	cleanup             runtime.Cleanup
	userID              string
	channelID           uint64
	initialized         bool
	closed              bool
	protocolVersion     int
	activeEpoch         string
	receiveEpoch        string
	pendingTransitionID uint16
	transitionSerial    uint64
	receivePassthrough  bool
	externalSender      []byte
	ssrcToUserID        map[uint32]string
	users               map[string]bool
	roster              map[string]bool
}

func NewDAVESession(userID string) *DAVESession {
	daveLoggingOnce.Do(func() { C.initDAVELogging() })
	n := &daveNative{failed: (*C.bool)(C.calloc(1, C.size_t(unsafe.Sizeof(C.bool(false)))))}
	n.session = C.newDAVENativeSession(n.failed)
	n.clearMedia()
	d := &DAVESession{native: n, userID: userID, users: map[string]bool{userID: true}, ssrcToUserID: make(map[uint32]string), roster: make(map[string]bool)}
	d.cleanup = runtime.AddCleanup(d, (*daveNative).close, n)
	return d
}

func (d *DAVESession) SetChannelID(channelID string) error {
	id, err := strconv.ParseUint(channelID, 10, 64)
	if err != nil || id == 0 {
		return errors.New("invalid DAVE channel ID")
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed || d.initialized {
		return errors.New("DAVE channel cannot change after initialization")
	}
	d.channelID = id
	return nil
}

func (d *DAVESession) initLocked(version int) error {
	_, err := strconv.ParseUint(d.userID, 10, 64)
	if d.closed || d.channelID == 0 || err != nil || version != 1 {
		return errors.New("DAVE initialization requires a valid channel, user and supported version")
	}
	if !bool(C.daveHasWelcomeChannelBinding()) {
		return errors.New("libdave lacks required Welcome channel validation")
	}
	n := d.native
	n.clearMedia()
	// Native Reset preserves its roster and returns only subsequent changes.
	// A fresh session makes a re-Welcome's roster complete for the new epoch.
	C.daveSessionDestroy(n.session)
	n.session = C.newDAVENativeSession(n.failed)
	if len(d.externalSender) != 0 {
		C.daveSessionSetExternalSender(n.session, daveBytes(d.externalSender), C.size_t(len(d.externalSender)))
	}
	n.encryptor = C.daveEncryptorCreate()
	C.daveEncryptorAssignSsrcToCodec(n.encryptor, 0, C.DAVE_CODEC_OPUS)
	C.daveEncryptorSetPassthroughMode(n.encryptor, false)
	userID := C.CString(d.userID)
	defer C.free(unsafe.Pointer(userID))
	*n.failed = false
	C.daveSessionInit(n.session, C.uint16_t(version), C.uint64_t(d.channelID), userID)
	d.activeEpoch, d.receiveEpoch = "", ""
	d.receivePassthrough = false
	d.roster = make(map[string]bool)
	d.initialized = !bool(*n.failed)
	d.protocolVersion = version
	if !d.initialized {
		return errors.New("MLS initialization failed")
	}
	return nil
}

func (d *DAVESession) GenerateKeyPackage() ([]byte, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if !d.initialized {
		err := d.initLocked(1)
		if err != nil {
			return nil, err
		}
	}
	return d.keyPackageLocked()
}

func (d *DAVESession) keyPackageLocked() ([]byte, error) {
	if d.closed {
		return nil, errors.New("DAVE session is closed")
	}
	var data *C.uint8_t
	var size C.size_t
	C.daveSessionGetMarshalledKeyPackage(d.native.session, &data, &size)
	result := copyDAVEBytes(data, size)
	if len(result) == 0 {
		return nil, errors.New("MLS key package generation failed")
	}
	return result, nil
}

func (d *DAVESession) ResetForReWelcome() ([]byte, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	err := d.initLocked(1)
	if err != nil {
		return nil, err
	}
	return d.keyPackageLocked()
}

func (d *DAVESession) HandlePrepareEpoch(epoch uint64, version int) ([]byte, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if epoch != 1 {
		return nil, nil
	}
	passthrough := d.protocolVersion == 0 && d.native.encryptor != nil && bool(C.daveEncryptorIsPassthroughMode(d.native.encryptor))
	err := d.initLocked(version)
	if err != nil {
		return nil, err
	}
	// A version-zero connection keeps sending plaintext until the gateway
	// executes its upgrade. A re-Welcome uses ResetForReWelcome and fails closed.
	if passthrough {
		err = d.prepareLocked(0, 0, true)
		if err != nil {
			return nil, err
		}
	}
	return d.keyPackageLocked()
}

func validDAVEMessage(data []byte) bool { return len(data) > 0 && len(data) <= maxDAVEMessageSize }
func daveBytes(data []byte) *C.uint8_t  { return (*C.uint8_t)(unsafe.Pointer(unsafe.SliceData(data))) }
func copyDAVEBytes(data *C.uint8_t, size C.size_t) []byte {
	defer C.daveFree(unsafe.Pointer(data))
	return bytes.Clone(unsafe.Slice((*byte)(unsafe.Pointer(data)), int(size)))
}

func (d *DAVESession) HandleExternalSenderPackage(data []byte) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed || !validDAVEMessage(data) {
		return errors.New("invalid MLS external sender")
	}
	if len(d.externalSender) != 0 {
		if bytes.Equal(d.externalSender, data) {
			return nil
		}
		return errors.New("MLS external sender changed within a voice session")
	}
	*d.native.failed = false
	C.daveSessionSetExternalSender(d.native.session, daveBytes(data), C.size_t(len(data)))
	if bool(*d.native.failed) {
		return errors.New("MLS external sender validation failed")
	}
	d.externalSender = bytes.Clone(data)
	return nil
}

// recognizedUsers allocates only C-owned pointers; native code never retains a
// pointer into Go memory. The caller holds mu for the whole native operation.
func (d *DAVESession) recognizedUsers() (**C.char, C.size_t, func()) {
	count := len(d.users)
	array := C.malloc(C.size_t(count) * C.size_t(unsafe.Sizeof(uintptr(0))))
	values := unsafe.Slice((**C.char)(array), count)
	index := 0
	for id := range d.users {
		values[index] = C.CString(id)
		index++
	}
	return (**C.char)(array), C.size_t(count), func() {
		for _, value := range values {
			C.free(unsafe.Pointer(value))
		}
		C.free(array)
	}
}

func (d *DAVESession) HandleProposals(data []byte) ([]byte, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed || !validDAVEMessage(data) {
		return nil, errors.New("invalid MLS proposals")
	}
	users, count, free := d.recognizedUsers()
	defer free()
	var result *C.uint8_t
	var size C.size_t
	*d.native.failed = false
	C.daveSessionProcessProposals(d.native.session, daveBytes(data), C.size_t(len(data)), users, count, &result, &size)
	out := copyDAVEBytes(result, size)
	if bool(*d.native.failed) {
		return nil, errors.New("MLS proposal validation failed")
	}
	return out, nil
}

func (d *DAVESession) HandleCommit(data []byte) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed || !validDAVEMessage(data) {
		return errors.New("invalid MLS commit")
	}
	result := C.daveSessionProcessCommit(d.native.session, daveBytes(data), C.size_t(len(data)))
	if result == nil {
		return errors.New("MLS commit validation failed")
	}
	defer C.daveCommitResultDestroy(result)
	if bool(C.daveCommitResultIsFailed(result)) {
		return errors.New("MLS commit validation failed")
	}
	if bool(C.daveCommitResultIsIgnored(result)) {
		return errDAVECommitIgnored
	}
	var ids *C.uint64_t
	var count C.size_t
	C.daveCommitResultGetRosterMemberIds(result, &ids, &count)
	defer C.daveFree(unsafe.Pointer(ids))
	for _, id := range unsafe.Slice(ids, int(count)) {
		var signature *C.uint8_t
		var size C.size_t
		C.daveCommitResultGetRosterMemberSignature(result, id, &signature, &size)
		C.daveFree(unsafe.Pointer(signature))
		userID := strconv.FormatUint(uint64(id), 10)
		if size == 0 {
			delete(d.roster, userID)
		} else {
			d.roster[userID] = true
		}
	}
	return nil
}

func (d *DAVESession) HandleWelcome(data []byte) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed || !validDAVEMessage(data) {
		return errors.New("invalid MLS Welcome")
	}
	users, count, free := d.recognizedUsers()
	defer free()
	result := C.daveSessionProcessWelcome(d.native.session, daveBytes(data), C.size_t(len(data)), users, count)
	if result == nil {
		return errors.New("MLS Welcome validation failed")
	}
	defer C.daveWelcomeResultDestroy(result)
	var ids *C.uint64_t
	var size C.size_t
	C.daveWelcomeResultGetRosterMemberIds(result, &ids, &size)
	defer C.daveFree(unsafe.Pointer(ids))
	d.roster = make(map[string]bool)
	for _, id := range unsafe.Slice(ids, int(size)) {
		d.roster[strconv.FormatUint(uint64(id), 10)] = true
	}
	return nil
}

func (d *DAVESession) epochLocked() string {
	var data *C.uint8_t
	var size C.size_t
	C.daveSessionGetLastEpochAuthenticator(d.native.session, &data, &size)
	return string(copyDAVEBytes(data, size))
}

func (d *DAVESession) ratchetLocked(userID string) C.DAVEKeyRatchetHandle {
	if !d.roster[userID] || !d.users[userID] {
		return nil
	}
	user := C.CString(userID)
	defer C.free(unsafe.Pointer(user))
	return C.daveSessionGetKeyRatchet(d.native.session, user)
}

func (d *DAVESession) HandlePrepareTransition(id uint16, version int) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.prepareLocked(id, version, true)
}

func (d *DAVESession) prepareLocked(id uint16, version int, executeInitial bool) error {
	if d.closed || (version != 0 && version != 1) {
		return errors.New("unsupported DAVE transition")
	}
	n := d.native
	epoch := d.epochLocked()
	d.receivePassthrough = version == 0
	if version == 1 && epoch != d.receiveEpoch {
		for userID := range d.roster {
			if userID != d.userID && d.users[userID] && n.decryptors[userID] == nil {
				n.decryptors[userID] = C.daveDecryptorCreate()
			}
		}
		for userID, decryptor := range n.decryptors {
			ratchet := d.ratchetLocked(userID)
			// Passing nil expires the removed member's previous receive key.
			C.daveDecryptorTransitionToKeyRatchet(decryptor, ratchet)
			C.daveKeyRatchetDestroy(ratchet)
		}
		d.receiveEpoch = epoch
	}
	if version == 1 {
		for _, decryptor := range n.decryptors {
			C.daveDecryptorTransitionToPassthroughMode(decryptor, false)
		}
	}
	if version == 0 {
		for userID := range d.users {
			if userID != d.userID && n.decryptors[userID] == nil {
				n.decryptors[userID] = C.daveDecryptorCreate()
			}
		}
		for _, decryptor := range n.decryptors {
			C.daveDecryptorTransitionToKeyRatchet(decryptor, nil)
			C.daveDecryptorTransitionToPassthroughMode(decryptor, true)
		}
	}
	// Only pending transitions may execute. Replayed prepares must not reinstall
	// an unchanged epoch and reset its sender nonce or receiver replay window.
	previous, exists := n.pending[id]
	if exists && previous.version == version && previous.epoch == epoch {
		return nil
	}
	C.daveKeyRatchetDestroy(previous.ratchet)
	var ratchet C.DAVEKeyRatchetHandle
	if version == 1 {
		ratchet = d.ratchetLocked(d.userID)
	}
	d.transitionSerial++
	n.pending[id] = daveTransition{version: version, epoch: epoch, serial: d.transitionSerial, ratchet: ratchet}
	d.pendingTransitionID = id
	if id == 0 && executeInitial {
		return d.executeLocked(id)
	}
	return nil
}

func (d *DAVESession) executeLocked(id uint16) error {
	transition, ok := d.native.pending[id]
	if !ok {
		return nil
	}
	delete(d.native.pending, id)
	defer C.daveKeyRatchetDestroy(transition.ratchet)
	for pendingID, pending := range d.native.pending {
		if pending.serial < transition.serial {
			C.daveKeyRatchetDestroy(pending.ratchet)
			delete(d.native.pending, pendingID)
		}
	}
	if d.native.encryptor == nil {
		d.native.encryptor = C.daveEncryptorCreate()
		C.daveEncryptorAssignSsrcToCodec(d.native.encryptor, 0, C.DAVE_CODEC_OPUS)
	}
	if transition.version == 0 {
		C.daveEncryptorSetPassthroughMode(d.native.encryptor, true)
		d.protocolVersion = 0
		return nil
	}
	C.daveEncryptorSetPassthroughMode(d.native.encryptor, false)
	d.protocolVersion = transition.version
	if transition.epoch != d.activeEpoch {
		C.daveEncryptorSetKeyRatchet(d.native.encryptor, transition.ratchet)
		d.activeEpoch = transition.epoch
	}
	return nil
}

func (d *DAVESession) HandleExecuteTransition(id uint16) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		return errors.New("DAVE session is closed")
	}
	return d.executeLocked(id)
}

func (d *DAVESession) ActivatePreparedTransition(id uint16) error {
	return d.HandleExecuteTransition(id)
}

// DeriveSenderKey prepares the current epoch without enabling transmission.
// Normal voice operation prepares and executes transitions from the gateway.
func (d *DAVESession) DeriveSenderKey() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed || len(d.roster) == 0 {
		return errors.New("no authenticated MLS epoch")
	}
	return d.prepareLocked(d.pendingTransitionID, 1, false)
}

func (d *DAVESession) Activate() {
	d.mu.Lock()
	defer d.mu.Unlock()
	if !d.closed {
		_ = d.executeLocked(d.pendingTransitionID)
	}
}

func (d *DAVESession) CanEncrypt() bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return !d.closed && d.protocolVersion == 1 && d.native.encryptor != nil && bool(C.daveEncryptorHasKeyRatchet(d.native.encryptor))
}

func (d *DAVESession) canSendPassthrough() bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return !d.closed && d.protocolVersion == 0 && d.native.encryptor != nil && bool(C.daveEncryptorIsPassthroughMode(d.native.encryptor))
}

func (d *DAVESession) EncryptFrame(data []byte) ([]byte, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.encryptLocked(data)
}

// sendFrame selects the negotiated mode under the same lock as execution of a
// transition, so an upgrade cannot race a previously observed plaintext mode.
func (d *DAVESession) sendFrame(data []byte) ([]byte, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if !d.closed && d.protocolVersion == 0 && d.native.encryptor != nil && bool(C.daveEncryptorIsPassthroughMode(d.native.encryptor)) {
		return bytes.Clone(data), nil
	}
	return d.encryptLocked(data)
}

func (d *DAVESession) encryptLocked(data []byte) ([]byte, error) {
	if d.closed || d.protocolVersion != 1 || d.native.encryptor == nil || !bool(C.daveEncryptorHasKeyRatchet(d.native.encryptor)) || !validDAVEMessage(data) {
		return nil, errors.New("DAVE encryption is unavailable")
	}
	size := C.daveEncryptorGetMaxCiphertextByteSize(d.native.encryptor, C.DAVE_MEDIA_TYPE_AUDIO, C.size_t(len(data)))
	out := make([]byte, int(size))
	var written C.size_t
	result := C.daveEncryptorEncrypt(d.native.encryptor, C.DAVE_MEDIA_TYPE_AUDIO, 0, daveBytes(data), C.size_t(len(data)), daveBytes(out), size, &written)
	if result != C.DAVE_ENCRYPTOR_RESULT_CODE_SUCCESS {
		return nil, fmt.Errorf("DAVE encryption failed (%d)", int(result))
	}
	return out[:int(written)], nil
}

func (d *DAVESession) DecryptFrame(ssrc uint32, data []byte) ([]byte, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed || !validDAVEMessage(data) {
		return nil, errors.New("DAVE decryption is unavailable")
	}
	if bytes.Equal(data, opusSilencePacket[:]) {
		return bytes.Clone(data), nil
	}
	userID := d.ssrcToUserID[ssrc]
	decryptor := d.native.decryptors[userID]
	if !d.users[userID] || decryptor == nil {
		return nil, errors.New("unknown DAVE sender")
	}
	out := make([]byte, len(data))
	var written C.size_t
	result := C.daveDecryptorDecrypt(decryptor, C.DAVE_MEDIA_TYPE_AUDIO, daveBytes(data), C.size_t(len(data)), daveBytes(out), C.size_t(len(out)), &written)
	if result != C.DAVE_DECRYPTOR_RESULT_CODE_SUCCESS {
		return nil, fmt.Errorf("DAVE decryption failed (%d)", int(result))
	}
	return out[:int(written)], nil
}

func (d *DAVESession) AddUser(userID string) {
	_, err := strconv.ParseUint(userID, 10, 64)
	if err != nil {
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if !d.closed {
		d.users[userID] = true
		if userID != d.userID && d.receivePassthrough && d.native.decryptors[userID] == nil {
			decryptor := C.daveDecryptorCreate()
			C.daveDecryptorTransitionToPassthroughMode(decryptor, true)
			d.native.decryptors[userID] = decryptor
		}
	}
}

func (d *DAVESession) RemoveUser(userID string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed || userID == d.userID {
		return
	}
	delete(d.users, userID)
	for ssrc, id := range d.ssrcToUserID {
		if id == userID {
			delete(d.ssrcToUserID, ssrc)
		}
	}
	decryptor := d.native.decryptors[userID]
	if decryptor != nil {
		C.daveDecryptorDestroy(decryptor)
		delete(d.native.decryptors, userID)
	}
}

func (d *DAVESession) SetSSRC(ssrc uint32, userID string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if !d.closed {
		d.ssrcToUserID[ssrc] = userID
	}
}

func (d *DAVESession) Reset() {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		return
	}
	d.native.clearMedia()
	C.daveSessionReset(d.native.session)
	d.initialized = false
	d.activeEpoch, d.receiveEpoch = "", ""
	d.protocolVersion = 0
	d.roster = make(map[string]bool)
}

func (d *DAVESession) Close() {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		return
	}
	d.closed = true
	d.cleanup.Stop()
	d.native.close()
}
