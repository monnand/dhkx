package dhkeyex

import (
	"math/big"
)

type DHKey struct {
	k *big.Int
}

func (self *DHKey) Bytes() []byte {
	return self.k.Bytes()
}

func NewKey(s []byte) *DHKey {
	key := new(DHKey)
	key.k = new(big.Int).SetBytes(s)
	return key
}

