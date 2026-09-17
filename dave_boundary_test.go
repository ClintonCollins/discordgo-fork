package discordgo

import "testing"

func TestDAVEMLSRejectsMalformedMessages(t *testing.T) {
	d := NewDAVESession("123")
	defer d.Close()
	err := d.SetChannelID(testMLSChannel)
	if err != nil {
		t.Fatal(err)
	}
	_, err = d.GenerateKeyPackage()
	if err != nil {
		t.Fatal(err)
	}
	if d.HandleExternalSenderPackage([]byte{0}) == nil {
		t.Error("malformed initial external sender was accepted")
	}
	if d.HandleCommit([]byte{0}) == nil {
		t.Error("malformed membership commit was accepted")
	}
}
