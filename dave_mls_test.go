package discordgo

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"io"
	"testing"
	"time"
)

const testMLSChannel = "1234567890"

var testMLSOpus = []byte{0x0d, 0xc5, 0xae, 0xdd, 0x5b, 0xdc, 0x3f, 0x20, 0xbe, 0x56, 0x97, 0xe5, 0x4d, 0xd1, 0xf4, 0x37}

// This gateway fixture signs RFC 9420 external proposals independently of libdave.
type testMLSExternalSender struct {
	key *ecdsa.PrivateKey
}

func newTestMLSExternalSender(t *testing.T) *testMLSExternalSender {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return &testMLSExternalSender{key: key}
}

func (s *testMLSExternalSender) packageBytes(t *testing.T) []byte {
	t.Helper()
	publicKey, err := s.key.PublicKey.ECDH()
	if err != nil {
		t.Fatal(err)
	}
	out := testMLSVector(publicKey.Bytes())
	out = binary.BigEndian.AppendUint16(out, 1)
	return append(out, testMLSVector([]byte{0, 1, 1, 0})...)
}

func (s *testMLSExternalSender) proposal(t *testing.T, epoch uint64, kind uint16, body []byte) []byte {
	t.Helper()
	content := testMLSVector(binary.BigEndian.AppendUint64(nil, 1234567890))
	content = binary.BigEndian.AppendUint64(content, epoch)
	content = append(content, 2) // External sender.
	content = binary.BigEndian.AppendUint32(content, 0)
	content = append(content, 0, 2) // Empty authenticated data; proposal content.
	content = binary.BigEndian.AppendUint16(content, kind)
	content = append(content, body...)

	message := append([]byte{0, 1, 0, 1}, content...)
	tbs := append(testMLSVector([]byte("MLS 1.0 FramedContentTBS")), testMLSVector(message)...)
	digest := sha256.Sum256(tbs)
	signature, err := ecdsa.SignASN1(rand.Reader, s.key, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	message = append(message, testMLSVector(signature)...)
	return append([]byte{0}, testMLSVector(message)...)
}

func testMLSVector(data []byte) []byte {
	var prefix []byte
	switch {
	case len(data) < 64:
		prefix = []byte{byte(len(data))}
	case len(data) < 16384:
		prefix = binary.BigEndian.AppendUint16(nil, uint16(len(data))|0x4000)
	default:
		prefix = binary.BigEndian.AppendUint32(nil, uint32(len(data))|0x80000000)
	}
	return append(prefix, data...)
}

// Only the public Commit envelope is read; Welcome authentication and decryption
// are performed by each participant's native MLS state.
type testMLSReader struct {
	*bytes.Reader
	t *testing.T
}

func (r testMLSReader) take(n int) []byte {
	r.t.Helper()
	if n < 0 || n > r.Len() {
		r.t.Fatalf("invalid MLS fixture length %d; %d bytes remain", n, r.Len())
	}
	out := make([]byte, n)
	_, err := io.ReadFull(r.Reader, out)
	if err != nil {
		r.t.Fatal(err)
	}
	return out
}

func (r testMLSReader) octet() byte { return r.take(1)[0] }

func (r testMLSReader) vector() []byte {
	r.t.Helper()
	first := r.octet()
	width := 1 << (first >> 6)
	length := uint64(first & 63)
	for range width - 1 {
		length = length<<8 | uint64(r.octet())
	}
	if length > uint64(r.Len()) {
		r.t.Fatalf("invalid MLS fixture vector length %d; %d bytes remain", length, r.Len())
	}
	return r.take(int(length))
}

func splitTestMLSCommit(t *testing.T, data []byte) (commit, welcome []byte) {
	t.Helper()
	r := testMLSReader{Reader: bytes.NewReader(data), t: t}
	if !bytes.Equal(r.take(4), []byte{0, 1, 0, 1}) {
		t.Fatal("expected an MLS 1.0 public message")
	}
	r.vector() // Group ID.
	r.take(8)  // Epoch.
	if r.octet() != 1 {
		t.Fatal("expected a member commit")
	}
	r.take(4)  // Leaf index.
	r.vector() // Authenticated data.
	if r.octet() != 3 {
		t.Fatal("expected commit content")
	}
	r.vector() // Proposal references.
	path := r.octet()
	if path == 1 {
		r.vector() // Leaf encryption key.
		r.vector() // Leaf signature key.
		if !bytes.Equal(r.take(2), []byte{0, 1}) {
			t.Fatal("expected a basic leaf credential")
		}
		r.vector() // Identity.
		for range 5 {
			r.vector() // Capabilities.
		}
		if r.octet() != 3 {
			t.Fatal("expected a commit leaf")
		}
		r.vector() // Parent hash.
		r.vector() // Extensions.
		r.vector() // Leaf signature.
		r.vector() // UpdatePath nodes.
	} else if path != 0 {
		t.Fatal("invalid optional UpdatePath")
	}
	r.vector() // FramedContent signature.
	r.vector() // Confirmation tag.
	r.vector() // Membership tag.
	offset := len(data) - r.Len()
	return data[:offset], data[offset:]
}

type testMLSGroup struct {
	sender   *testMLSExternalSender
	members  []*DAVESession
	packages [][]byte
	epoch    uint64
}

func testMLSParticipants(t *testing.T, ids ...string) *testMLSGroup {
	t.Helper()
	group := &testMLSGroup{sender: newTestMLSExternalSender(t)}
	for _, id := range ids {
		session := NewDAVESession(id)
		t.Cleanup(func() { session.Close() })
		err := session.SetChannelID(testMLSChannel)
		if err != nil {
			t.Fatal(err)
		}
		for index, peerID := range ids {
			session.AddUser(peerID)
			session.SetSSRC(uint32(index+1), peerID)
		}
		err = session.HandleExternalSenderPackage(group.sender.packageBytes(t))
		if err != nil {
			t.Fatal(err)
		}
		keyPackage, err := session.GenerateKeyPackage()
		if err != nil {
			t.Fatal(err)
		}
		group.members = append(group.members, session)
		group.packages = append(group.packages, keyPackage)
	}
	return group
}

func (g *testMLSGroup) propose(t *testing.T, proposal []byte, members ...int) (commit, welcome []byte) {
	t.Helper()
	for index, member := range members {
		output, err := g.members[member].HandleProposals(proposal)
		if err != nil {
			t.Fatalf("member %d processing proposals: %v", member, err)
		}
		if len(output) == 0 {
			t.Fatalf("member %d did not produce a commit", member)
		}
		if index == 0 {
			commit, welcome = splitTestMLSCommit(t, output)
		}
	}
	return commit, welcome
}

func (g *testMLSGroup) processCommit(t *testing.T, commit []byte, members ...int) {
	t.Helper()
	for _, member := range members {
		err := g.members[member].HandleCommit(commit)
		if err != nil {
			t.Fatalf("member %d processing commit: %v", member, err)
		}
	}
	g.epoch++
}

func (g *testMLSGroup) join(t *testing.T, newcomer int, members ...int) {
	t.Helper()
	proposal := g.sender.proposal(t, g.epoch, 1, g.packages[newcomer])
	commit, welcome := g.propose(t, proposal, members...)
	g.processCommit(t, commit, members...)
	err := g.members[newcomer].HandleWelcome(welcome)
	if err != nil {
		t.Fatal(err)
	}
}

func (g *testMLSGroup) transition(t *testing.T, id uint16, members ...int) {
	t.Helper()
	for _, member := range members {
		err := g.members[member].HandlePrepareTransition(id, 1)
		if err != nil {
			t.Fatal(err)
		}
		if id != 0 {
			err = g.members[member].HandleExecuteTransition(id)
			if err != nil {
				t.Fatal(err)
			}
		}
		if !g.members[member].CanEncrypt() {
			t.Fatalf("member %d cannot encrypt after transition", member)
		}
	}
}

func testDAVESession(t *testing.T, userID string) *DAVESession {
	t.Helper()
	peer := "987654321"
	if peer == userID {
		peer = "987654322"
	}
	group := testMLSParticipants(t, userID, peer)
	group.join(t, 1, 0)
	group.transition(t, 0, 0, 1)
	return group.members[0]
}

func testMLSEncrypt(t *testing.T, session *DAVESession) []byte {
	t.Helper()
	packet, err := session.EncryptFrame(testMLSOpus)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(packet, testMLSOpus) {
		t.Fatal("encrypted DAVE media was sent as plaintext")
	}
	return packet
}

func testMLSDecrypt(t *testing.T, session *DAVESession, ssrc uint32, packet []byte) {
	t.Helper()
	plaintext, err := session.DecryptFrame(ssrc, packet)
	if err != nil || !bytes.Equal(plaintext, testMLSOpus) {
		t.Fatalf("DAVE media round trip failed: %x, %v", plaintext, err)
	}
}

func TestDAVEMLSMembershipChanges(t *testing.T) {
	g := testMLSParticipants(t, "101", "202", "303")
	a, b, c := g.members[0], g.members[1], g.members[2]
	g.join(t, 1, 0)
	g.transition(t, 0, 0, 1)
	testMLSDecrypt(t, b, 1, testMLSEncrypt(t, a))
	testMLSDecrypt(t, a, 2, testMLSEncrypt(t, b))
	inFlightBeforeJoin := testMLSEncrypt(t, a)
	prepareErr := a.HandlePrepareTransition(6, 1)
	if prepareErr != nil {
		t.Fatal(prepareErr)
	}

	g.join(t, 2, 0, 1)
	for _, session := range g.members {
		err := session.HandlePrepareTransition(7, 1)
		if err != nil {
			t.Fatal(err)
		}
	}
	if c.CanEncrypt() {
		t.Fatal("new member started sending before execute transition")
	}
	// Existing senders keep the old epoch until execute; prepared receivers accept both.
	testMLSDecrypt(t, b, 1, testMLSEncrypt(t, a))
	err := a.HandleExecuteTransition(7)
	if err != nil {
		t.Fatal(err)
	}
	current := testMLSEncrypt(t, a)
	testMLSDecrypt(t, c, 1, current)
	testMLSDecrypt(t, b, 1, current)
	for _, session := range []*DAVESession{b, c} {
		err = session.HandleExecuteTransition(7)
		if err != nil {
			t.Fatal(err)
		}
	}
	testMLSDecrypt(t, b, 1, inFlightBeforeJoin)
	_, err = c.DecryptFrame(1, inFlightBeforeJoin)
	if err == nil {
		t.Fatal("new member decrypted media from before joining")
	}
	c.SetSSRC(99, "101")
	_, err = c.DecryptFrame(99, current)
	if err == nil {
		t.Fatal("replayed media was accepted after an SSRC change")
	}

	inFlightBeforeRemoval := testMLSEncrypt(t, a)
	remove := g.sender.proposal(t, g.epoch, 3, binary.BigEndian.AppendUint32(nil, 1))
	commit, welcome := g.propose(t, remove, 0, 2)
	if len(welcome) != 0 {
		t.Fatal("remove-only commit unexpectedly included a Welcome")
	}
	g.processCommit(t, commit, 0, 2)
	g.transition(t, 8, 0, 2)
	current = testMLSEncrypt(t, a)
	testMLSDecrypt(t, c, 1, current)
	_, err = b.DecryptFrame(1, current)
	if err == nil {
		t.Fatal("removed member decrypted a new epoch frame")
	}
	testMLSDecrypt(t, c, 1, inFlightBeforeRemoval)
	a.RemoveUser("202")
	_, err = a.DecryptFrame(2, testMLSEncrypt(t, b))
	if err == nil {
		t.Fatal("media from a departed participant remained accepted")
	}

	// Duplicate or stale transition messages must not roll back keys or reset nonces.
	for _, id := range []uint16{8, 7, 6} {
		err = a.HandleExecuteTransition(id)
		if err != nil {
			t.Fatal(err)
		}
		next := testMLSEncrypt(t, a)
		if bytes.Equal(next, current) {
			t.Fatal("transition reused a media key and nonce")
		}
		testMLSDecrypt(t, c, 1, next)
		current = next
	}
	fresh := testMLSEncrypt(t, a)
	tampered := bytes.Clone(fresh)
	tampered[0] ^= 1
	_, err = c.DecryptFrame(1, tampered)
	if err == nil {
		t.Fatal("accepted tampered media")
	}
	testMLSDecrypt(t, c, 1, fresh)
}

func TestDAVEMLSRejectMalformedControl(t *testing.T) {
	for _, control := range []string{"external sender", "proposal", "commit", "welcome"} {
		t.Run(control, func(t *testing.T) {
			g := testMLSParticipants(t, "101", "202")
			d := g.members[0]
			var err error
			switch control {
			case "external sender":
				err = d.HandleExternalSenderPackage([]byte{0xff})
			case "proposal":
				_, err = d.HandleProposals([]byte{0xff})
			case "commit":
				err = d.HandleCommit([]byte{0xff})
			case "welcome":
				err = d.HandleWelcome([]byte{0xff})
			}
			if err == nil {
				t.Fatal("accepted malformed MLS control message")
			}
		})
	}
}

func TestDAVEMLSAuthenticateControl(t *testing.T) {
	for _, attack := range []string{"wrong proposal signer", "unknown proposal participant", "tampered key package", "wrong proposal epoch", "tampered commit", "tampered welcome", "unknown welcome participant", "wrong welcome external sender"} {
		t.Run(attack, func(t *testing.T) {
			g := testMLSParticipants(t, "101", "202")
			a, b := g.members[0], g.members[1]
			proposal := g.sender.proposal(t, 0, 1, g.packages[1])
			var err error
			switch attack {
			case "wrong proposal signer":
				forged := newTestMLSExternalSender(t).proposal(t, 0, 1, g.packages[1])
				_, err = a.HandleProposals(forged)
			case "unknown proposal participant":
				a.RemoveUser("202")
				_, err = a.HandleProposals(proposal)
				a.AddUser("202")
			case "tampered key package":
				keyPackage := bytes.Clone(g.packages[1])
				keyPackage[len(keyPackage)-1] ^= 1
				_, err = a.HandleProposals(g.sender.proposal(t, 0, 1, keyPackage))
			case "wrong proposal epoch":
				_, err = a.HandleProposals(g.sender.proposal(t, 1, 1, g.packages[1]))
			}
			if attack == "wrong proposal signer" || attack == "unknown proposal participant" || attack == "tampered key package" || attack == "wrong proposal epoch" {
				if err == nil {
					t.Fatal("accepted unauthorized MLS proposal")
				}
			}
			commit, welcome := g.propose(t, proposal, 0)
			if attack == "tampered commit" {
				badCommit := bytes.Clone(commit)
				badCommit[len(badCommit)-1] ^= 1
				err = a.HandleCommit(badCommit)
				if err == nil {
					t.Fatal("accepted tampered MLS commit")
				}
			}
			g.processCommit(t, commit, 0)
			switch attack {
			case "tampered welcome":
				badWelcome := bytes.Clone(welcome)
				badWelcome[len(badWelcome)-1] ^= 1
				err = b.HandleWelcome(badWelcome)
			case "unknown welcome participant":
				b.RemoveUser("101")
				err = b.HandleWelcome(welcome)
				b.AddUser("101")
				b.SetSSRC(1, "101")
			case "wrong welcome external sender":
				err = b.HandleExternalSenderPackage(newTestMLSExternalSender(t).packageBytes(t))
				if err == nil {
					t.Fatal("external sender was replaced inside a voice session")
				}
			}
			if attack == "tampered welcome" || attack == "unknown welcome participant" || attack == "wrong welcome external sender" {
				if err == nil {
					t.Fatal("accepted unauthenticated MLS Welcome")
				}
			}
			err = b.HandleWelcome(welcome)
			if err != nil {
				t.Fatalf("valid Welcome failed after rejection: %v", err)
			}
			g.transition(t, 0, 0, 1)
			testMLSDecrypt(t, b, 1, testMLSEncrypt(t, a))
		})
	}
}

func TestDAVEMLSWelcomeChannelBinding(t *testing.T) {
	g := testMLSParticipants(t, "101", "202")
	b := g.members[1]
	b.Reset()
	err := b.SetChannelID("1234567891")
	if err != nil {
		t.Fatal(err)
	}
	keyPackage, err := b.GenerateKeyPackage()
	if err != nil {
		t.Fatal(err)
	}
	proposal := g.sender.proposal(t, 0, 1, keyPackage)
	_, welcome := g.propose(t, proposal, 0)
	err = b.HandleWelcome(welcome)
	if err == nil {
		t.Fatal("accepted a Welcome for a different voice channel")
	}
	if b.CanEncrypt() {
		t.Fatal("cross-channel Welcome activated the sender")
	}
}

func TestDAVEMLSReWelcomePreservesParticipants(t *testing.T) {
	g := testMLSParticipants(t, "101", "202")
	a, b := g.members[0], g.members[1]
	g.join(t, 1, 0)
	g.transition(t, 0, 0, 1)
	keyPackage, err := b.ResetForReWelcome()
	if err != nil {
		t.Fatal(err)
	}
	g.packages[1] = keyPackage
	remove := g.sender.proposal(t, g.epoch, 3, binary.BigEndian.AppendUint32(nil, 1))
	commit, _ := g.propose(t, remove, 0)
	g.processCommit(t, commit, 0)
	g.join(t, 1, 0)
	g.transition(t, 9, 0, 1)
	testMLSDecrypt(t, b, 1, testMLSEncrypt(t, a))
	testMLSDecrypt(t, a, 2, testMLSEncrypt(t, b))
}

func TestDAVEMLSProposalRevocation(t *testing.T) {
	g := testMLSParticipants(t, "101", "202", "303")
	addB := g.sender.proposal(t, 0, 1, g.packages[1])
	g.propose(t, addB, 0)
	g.propose(t, g.sender.proposal(t, 0, 1, g.packages[2]), 0)

	r := testMLSReader{Reader: bytes.NewReader(addB[1:]), t: t}
	message := r.vector()
	// ProposalRef covers AuthenticatedContent, excluding the MLS version field.
	refInput := append(testMLSVector([]byte("MLS 1.0 Proposal Reference")), testMLSVector(message[2:])...)
	ref := sha256.Sum256(refInput)
	revoke := append([]byte{1}, testMLSVector(testMLSVector(ref[:]))...)
	commit, welcome := g.propose(t, revoke, 0)
	g.processCommit(t, commit, 0)
	err := g.members[1].HandleWelcome(welcome)
	if err == nil {
		t.Fatal("revoked participant joined the committed group")
	}
	err = g.members[2].HandleWelcome(welcome)
	if err != nil {
		t.Fatalf("remaining participant could not join: %v", err)
	}
	g.transition(t, 0, 0, 2)
	testMLSDecrypt(t, g.members[2], 1, testMLSEncrypt(t, g.members[0]))
}

func TestDAVEMLSRetiredEpochAndPassthroughExpire(t *testing.T) {
	downgraded := testMLSParticipants(t, "101", "202")
	downgraded.join(t, 1, 0)
	downgraded.transition(t, 0, 0, 1)
	retiredFrame := testMLSEncrypt(t, downgraded.members[0])
	err := downgraded.members[1].HandlePrepareTransition(0, 0)
	if err != nil {
		t.Fatal(err)
	}

	g := testMLSParticipants(t, "101", "202", "303")
	a, b := g.members[0], g.members[1]
	g.join(t, 1, 0)
	g.transition(t, 0, 0, 1)
	oldEpochFrame := testMLSEncrypt(t, a)
	_, err = b.DecryptFrame(1, testMLSOpus)
	if err == nil {
		t.Fatal("encrypted mode accepted unnegotiated plaintext")
	}
	err = b.HandlePrepareTransition(1, 0)
	if err != nil {
		t.Fatal(err)
	}
	if !b.CanEncrypt() || b.canSendPassthrough() {
		t.Fatal("preparing a downgrade changed the sender before execute")
	}
	testMLSDecrypt(t, b, 1, testMLSOpus)
	err = b.HandleExecuteTransition(1)
	if err != nil {
		t.Fatal(err)
	}
	if b.CanEncrypt() || !b.canSendPassthrough() {
		t.Fatal("executing a downgrade did not switch sender mode")
	}

	g.join(t, 2, 0, 1)
	g.transition(t, 2, 0, 1, 2)
	testMLSDecrypt(t, b, 1, testMLSOpus)
	// Native cryptors use a real steady clock and retain retired keys for 10 seconds.
	time.Sleep(10*time.Second + 100*time.Millisecond)
	_, err = downgraded.members[1].DecryptFrame(1, retiredFrame)
	if err == nil {
		t.Error("standalone downgrade retained its retired epoch key indefinitely")
	}
	testMLSDecrypt(t, downgraded.members[1], 1, testMLSOpus)
	for _, packet := range [][]byte{oldEpochFrame, testMLSOpus} {
		_, err = b.DecryptFrame(1, packet)
		if err == nil {
			t.Fatal("expired epoch key or plaintext passthrough remained usable")
		}
	}
	testMLSDecrypt(t, b, 1, testMLSEncrypt(t, a))
}
