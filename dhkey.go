/*
 * Copyright 2012 Nan Deng
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

package dhkx

import (
	"math/big"
)

type DHKey struct {
	x *big.Int
	y *big.Int
}

func (self *DHKey) Bytes() []byte {
	if self.y == nil {
		return nil
	}
	return self.y.Bytes()
}

func (self *DHKey) String() string {
	if self.y == nil {
		return ""
	}
	return self.y.String()
}

func (self *DHKey) IsPrivateKey() bool {
	return self.x != nil
}

func NewPublicKey(s []byte) *DHKey {
	key := new(DHKey)
	key.y = new(big.Int).SetBytes(s)
	return key
}
