package discordgo

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"fmt"
	"slices"
	"strconv"
	"sync"

	"github.com/bwmarrin/discordgo/mls"
)

const maxDAVEMissingNonces = 1000

var opusSilencePacket = [3]byte{0xF8, 0xFF, 0xFE}

type daveReceiver struct {
	userID            string
	baseSecret        []byte
	currentGeneration uint32
	key               []byte
	aesBlock          cipher.Block
	frameCipher       cipher.AEAD
	newestNonce       uint32
	hasNonce          bool
	missingNonces     []uint32
}

type DAVESession struct {
	mu                  sync.Mutex
	protocolVersion     int
	epoch               uint64
	pendingTransitionID uint16
	pendingVersion      int

	exporterSecret    []byte
	senderKey         []byte
	senderNonce       uint32
	frameCipher       cipher.AEAD
	userID            string
	active            bool
	passthrough       bool
	ratchetBaseSecret []byte
	currentGeneration uint32
	hasPendingKey     bool

	ssrcToUserID map[uint32]string
	receivers    map[string]*daveReceiver

	kpBundle *mls.KeyPackageBundle
}

func NewDAVESession(userID string) *DAVESession {
	return &DAVESession{
		userID: userID,
	}
}

func (d *DAVESession) GenerateKeyPackage() ([]byte, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.generateKeyPackageLocked()
}

func (d *DAVESession) ResetForReWelcome() ([]byte, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	d.exporterSecret = nil
	d.hasPendingKey = false

	return d.generateKeyPackageLocked()
}

func (d *DAVESession) generateKeyPackageLocked() ([]byte, error) {
	userIDNum, err := strconv.ParseUint(d.userID, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("parsing user ID for credential: %w", err)
	}
	identity := make([]byte, 8)
	binary.BigEndian.PutUint64(identity, userIDNum)

	bundle, err := mls.GenerateKeyPackage(identity)
	if err != nil {
		return nil, fmt.Errorf("generating key package: %w", err)
	}
	d.kpBundle = bundle
	return bundle.Serialized, nil
}

func (d *DAVESession) HandleExternalSenderPackage(data []byte) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	return nil
}

func (d *DAVESession) HandleWelcome(data []byte) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.kpBundle == nil {
		return fmt.Errorf("no key package generated")
	}

	result, err := mls.ProcessWelcome(data, d.kpBundle)
	if err != nil {
		return fmt.Errorf("processing welcome: %w", err)
	}

	if bytes.Equal(d.exporterSecret, result.ExporterSecret) {
		return nil
	}

	d.exporterSecret = result.ExporterSecret
	d.epoch = result.Epoch
	d.hasPendingKey = true
	d.receivers = nil
	return nil
}

func (d *DAVESession) HandleCommit(data []byte) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	return nil
}

func (d *DAVESession) HandlePrepareTransition(transitionID uint16, protocolVersion int) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.pendingTransitionID = transitionID
	d.pendingVersion = protocolVersion
	if protocolVersion == 0 {
		d.passthrough = true
	}
}

func (d *DAVESession) ActivatePreparedTransition(transitionID uint16) error {
	d.mu.Lock()
	if transitionID != d.pendingTransitionID {
		d.mu.Unlock()
		return nil
	}
	if d.pendingVersion > 0 && d.senderKey != nil && d.frameCipher != nil {
		d.active = true
		d.passthrough = false
		d.protocolVersion = d.pendingVersion
		d.hasPendingKey = false
		d.mu.Unlock()
		return nil
	}
	d.mu.Unlock()
	return d.HandleExecuteTransition(transitionID)
}

func (d *DAVESession) HandleExecuteTransition(transitionID uint16) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if transitionID != d.pendingTransitionID {
		return nil
	}

	if d.pendingVersion > 0 {
		if d.hasPendingKey && d.exporterSecret != nil {
			err := d.deriveSenderKeyLocked()
			if err != nil {
				return err
			}
			d.hasPendingKey = false
		}
		if d.senderKey == nil || d.frameCipher == nil {
			return nil
		}

		d.active = true
		d.passthrough = false
		d.protocolVersion = d.pendingVersion
	} else {
		d.active = false
		d.passthrough = true
		d.protocolVersion = 0
		d.senderKey = nil
		d.frameCipher = nil
		d.hasPendingKey = false
	}
	return nil
}

func (d *DAVESession) HandlePrepareEpoch(epoch uint64, protocolVersion int) ([]byte, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	d.epoch = epoch
	d.active = false
	d.senderKey = nil
	d.frameCipher = nil
	d.exporterSecret = nil
	d.receivers = nil

	return d.generateKeyPackageLocked()
}

func (d *DAVESession) DeriveSenderKey() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.deriveSenderKeyLocked()
}

func (d *DAVESession) deriveSenderKeyLocked() error {
	if d.exporterSecret == nil {
		return fmt.Errorf("no exporter secret")
	}

	userIDNum, err := strconv.ParseUint(d.userID, 10, 64)
	if err != nil {
		return fmt.Errorf("parsing user ID: %w", err)
	}
	context := make([]byte, 8)
	binary.LittleEndian.PutUint64(context, userIDNum)

	baseSecret, err := mls.Export(d.exporterSecret, daveExportLabel, context, daveKeySize)
	if err != nil {
		return fmt.Errorf("exporting base secret: %w", err)
	}

	// Deriving an unchanged key must preserve its nonce and ratchet position.
	generation, senderNonce := uint32(0), uint32(0)
	if bytes.Equal(d.ratchetBaseSecret, baseSecret) {
		if d.frameCipher != nil {
			return nil
		}
		generation, senderNonce = d.currentGeneration, d.senderNonce
	}

	key, err := hashRatchetGetKey(baseSecret, generation)
	if err != nil {
		return fmt.Errorf("deriving ratchet key: %w", err)
	}
	frameCipher, err := newDAVECipher(key)
	if err != nil {
		return fmt.Errorf("creating frame cipher: %w", err)
	}
	d.ratchetBaseSecret = baseSecret
	d.currentGeneration = generation
	d.senderNonce = senderNonce
	d.senderKey = key
	d.frameCipher = frameCipher
	return nil
}

func (d *DAVESession) EncryptFrame(opusData []byte) ([]byte, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	if !d.active || d.frameCipher == nil {
		return nil, fmt.Errorf("DAVE encryption is not active")
	}
	if d.senderNonce == ^uint32(0) {
		return nil, fmt.Errorf("DAVE sender nonce exhausted; a new epoch is required")
	}

	d.senderNonce++

	generation := d.senderNonce >> 24
	if generation != d.currentGeneration {
		key, err := hashRatchetGetKey(d.ratchetBaseSecret, generation)
		if err != nil {
			return nil, fmt.Errorf("ratcheting key for generation %d: %w", generation, err)
		}
		frameCipher, err := newDAVECipher(key)
		if err != nil {
			return nil, fmt.Errorf("creating cipher for generation %d: %w", generation, err)
		}
		d.senderKey = key
		d.frameCipher = frameCipher
		d.currentGeneration = generation
	}

	encrypted := encryptSecureFrame(d.frameCipher, d.senderNonce, opusData)
	return encrypted, nil
}

func (d *DAVESession) SetSSRC(ssrc uint32, userID string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.ssrcToUserID == nil {
		d.ssrcToUserID = make(map[uint32]string)
	}
	d.ssrcToUserID[ssrc] = userID
}

func (d *DAVESession) DecryptFrame(ssrc uint32, data []byte) ([]byte, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	if len(data) == 3 && data[0] == opusSilencePacket[0] && data[1] == opusSilencePacket[1] && data[2] == opusSilencePacket[2] {
		return data, nil
	}

	ciphertext, truncatedTag, nonce, err := parseSecureFrame(data)
	if err != nil {
		if d.passthrough {
			return data, nil
		}
		return nil, err
	}

	userID, ok := d.ssrcToUserID[ssrc]
	if !ok {
		return nil, fmt.Errorf("unknown SSRC %d", ssrc)
	}
	recv := d.receivers[userID]
	if recv == nil {
		recv, err = d.createReceiverLocked(userID)
		if err != nil {
			return nil, err
		}
	}

	missingIndex := -1
	if recv.hasNonce && nonce <= recv.newestNonce {
		missingIndex = slices.Index(recv.missingNonces, nonce)
		if missingIndex < 0 {
			return nil, fmt.Errorf("DAVE frame nonce was replayed or is too old")
		}
	}

	generation := nonce >> 24
	if generation != recv.currentGeneration {
		key, err := hashRatchetGetKey(recv.baseSecret, generation)
		if err != nil {
			return nil, fmt.Errorf("ratcheting receiver key for generation %d: %w", generation, err)
		}
		recv.key = key
		block, err := aes.NewCipher(key)
		if err != nil {
			return nil, err
		}
		recv.aesBlock = block
		fc, err := newDAVECipher(key)
		if err != nil {
			return nil, err
		}
		recv.frameCipher = fc
		recv.currentGeneration = generation
	}

	plaintext, err := decryptSecureFrame(recv.aesBlock, recv.frameCipher, nonce, ciphertext, truncatedTag)
	if err != nil {
		return nil, err
	}

	if !recv.hasNonce {
		recv.hasNonce = true
		recv.newestNonce = nonce
	} else if nonce > recv.newestNonce {
		missing := min(nonce-recv.newestNonce-1, maxDAVEMissingNonces)
		remove := max(0, len(recv.missingNonces)+int(missing)-maxDAVEMissingNonces)
		recv.missingNonces = slices.Delete(recv.missingNonces, 0, remove)
		for n := nonce - missing; n < nonce; n++ {
			recv.missingNonces = append(recv.missingNonces, n)
		}
		recv.newestNonce = nonce
	} else {
		recv.missingNonces = slices.Delete(recv.missingNonces, missingIndex, missingIndex+1)
	}
	return plaintext, nil
}

func (d *DAVESession) createReceiverLocked(userID string) (*daveReceiver, error) {
	if d.exporterSecret == nil {
		return nil, fmt.Errorf("no exporter secret")
	}

	userIDNum, err := strconv.ParseUint(userID, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("parsing user ID: %w", err)
	}
	context := make([]byte, 8)
	binary.LittleEndian.PutUint64(context, userIDNum)

	baseSecret, err := mls.Export(d.exporterSecret, daveExportLabel, context, daveKeySize)
	if err != nil {
		return nil, fmt.Errorf("exporting receiver base secret: %w", err)
	}

	key, err := hashRatchetGetKey(baseSecret, 0)
	if err != nil {
		return nil, fmt.Errorf("deriving receiver ratchet key: %w", err)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	fc, err := newDAVECipher(key)
	if err != nil {
		return nil, err
	}

	recv := &daveReceiver{
		userID:      userID,
		baseSecret:  baseSecret,
		key:         key,
		aesBlock:    block,
		frameCipher: fc,
	}

	if d.receivers == nil {
		d.receivers = make(map[string]*daveReceiver)
	}
	d.receivers[userID] = recv
	return recv, nil
}

func (d *DAVESession) clearReceiversLocked() {
	d.receivers = nil
}

// Activate marks the session as active so that CanEncrypt returns true.
// This is called after the Welcome handler derives the sender key, so
// that audio can be encrypted immediately without waiting for
// execute_transition — which Discord does not always send (e.g., after
// server migration with existing channel members).
func (d *DAVESession) Activate() {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.frameCipher != nil {
		d.active = true
		d.passthrough = false
		d.protocolVersion = 1
		d.hasPendingKey = false
	}
}

func (d *DAVESession) CanEncrypt() bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.active && d.frameCipher != nil && d.senderNonce != ^uint32(0)
}

func (d *DAVESession) canSendPassthrough() bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.passthrough && d.protocolVersion == 0
}

func (d *DAVESession) Reset() {
	d.mu.Lock()
	defer d.mu.Unlock()

	d.exporterSecret = nil
	d.senderKey = nil
	d.senderNonce = 0
	d.frameCipher = nil
	d.active = false
	d.passthrough = false
	d.protocolVersion = 0
	d.kpBundle = nil
	d.pendingTransitionID = 0
	d.pendingVersion = 0
	d.ratchetBaseSecret = nil
	d.currentGeneration = 0
	d.hasPendingKey = false
	d.ssrcToUserID = nil
	d.clearReceiversLocked()
}
