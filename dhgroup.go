package dhkx

import (
	"math/big"
	"crypto/rand"
	"io"
	"errors"
)

type DHGroup struct {
	p *big.Int
	g *big.Int
}

func (self *DHGroup) GeneratePrivateKey(randReader io.Reader) (key *DHKey, err error) {
	if randReader == nil {
		randReader = rand.Reader
	}
	var x *big.Int
	x, err = rand.Int(randReader, self.p)
	if err != nil {
		return
	}
	key = new(DHKey)
	key.x = x

	// y = g ^ x mod p
	key.y = new(big.Int).Exp(self.g, x, self.p)
	return
}

func GetGroup(groupID int) (group *DHGroup, err error) {
	switch groupID {
	case 1:
		p, _ := new(big.Int).SetString("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A63A3620FFFFFFFFFFFFFFFF", 16)
		group = &DHGroup {
			g: new(big.Int).SetInt64(2),
			p: p,
		}
	case 2:
		p, _ := new(big.Int).SetString("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381FFFFFFFFFFFFFFFF", 16)
		group = &DHGroup {
			g: new(big.Int).SetInt64(2),
			p: p,
		}
	case 14:
		p, _ := new(big.Int).SetString("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF", 16)
		group = &DHGroup {
			g: new(big.Int).SetInt64(2),
			p: p,
		}
	default:
		group = nil
		err = errors.New("DH: Unknown group")
	}
	return
}

func (self *DHGroup) ComputeKey(pubkey *DHKey, privkey *DHKey) (key *DHKey, err error) {
	if pubkey.y == nil {
		err = errors.New("DH: invalid public key")
		return
	}
	if pubkey.y.Sign() <= 0 || pubkey.y.Cmp(self.p) >= 0 {
		err = errors.New("DH parameter out of bounds")
		return
	}
	if privkey.x == nil {
		err = errors.New("DH: invalid private key")
		return
	}
	if self.p == nil {
		err = errors.New("DH: invalid group")
		return
	}

	k := new(big.Int).Exp(pubkey.y, privkey.x, self.p)
	key = new(DHKey)
	key.y = k
	return
}

