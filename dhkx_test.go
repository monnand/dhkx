package dhkx

import (
	"fmt"
	"testing"
)

type peer struct {
	priv *DHKey
	group *DHGroup
	pub *DHKey
}

func newPeer(g *DHGroup) *peer {
	ret := new(peer)
	ret.priv, _ = g.GeneratePrivateKey(nil)
	ret.group = g
	return ret
}

func (self *peer) getPubKey() []byte {
	return self.priv.Bytes()
}

func (self *peer) recvPeerPubKey(pub []byte) {
	pubKey := NewPublicKey(pub)
	self.pub = pubKey
}

func (self *peer) getKey() []byte {
	k, err := self.group.ComputeKey(self.pub, self.priv)
	if err != nil {
		return nil
	}
	return k.Bytes()
}

func exchangeKey(p1, p2 *peer) error {
	pub1 := p1.getPubKey()
	pub2 := p2.getPubKey()

	p1.recvPeerPubKey(pub2)
	p2.recvPeerPubKey(pub1)

	key1 := p1.getKey()
	key2 := p2.getKey()

	if key1 == nil {
		return fmt.Errorf("p1 has nil key")
	}
	if key2 == nil {
		return fmt.Errorf("p2 has nil key")
	}

	for i, k := range key1 {
		if key2[i] != k {
			return fmt.Errorf("%vth byte does not same")
		}
	}
	return nil
}

func TestKeyExchange(t *testing.T) {
	group, _ := GetGroup(14)
	p1 := newPeer(group)
	p2 := newPeer(group)

	err := exchangeKey(p1, p2)
	if err != nil {
		t.Errorf("%v", err)
	}
}

