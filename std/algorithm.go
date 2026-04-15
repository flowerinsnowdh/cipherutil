// SPDX-License-Identifier: GPL-3.0-or-later
/*
 * Copyright (C) 2026  flowerinsnow
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */
package std

import "strings"

type CipherAlgorithm interface {
	Name() string
}

type SymmetricCipherAlgorithm interface {
	CipherAlgorithm
	KeySize() int
}

type symmetricCipherAlgorithm struct {
	name    string
	keySize int
}

func (s *symmetricCipherAlgorithm) Name() string {
	return s.name
}

func (s *symmetricCipherAlgorithm) KeySize() int {
	return s.keySize
}

type asymmetricCipherAlgorithm struct {
	name string
}

func (a *asymmetricCipherAlgorithm) Name() string {
	return a.name
}

var (
	ChaCha20 *symmetricCipherAlgorithm = &symmetricCipherAlgorithm{
		name:    "chacha20",
		keySize: 32,
	}

	MLKEM768 *asymmetricCipherAlgorithm = &asymmetricCipherAlgorithm{
		name: "ml-kem-768",
	}
	MLKEM1024 *asymmetricCipherAlgorithm = &asymmetricCipherAlgorithm{
		name: "ml-kem-1024",
	}
	X25519 *asymmetricCipherAlgorithm = &asymmetricCipherAlgorithm{
		name: "x25519",
	}
	Ed25519 *asymmetricCipherAlgorithm = &asymmetricCipherAlgorithm{
		name: "ed25519",
	}
	EC256 *asymmetricCipherAlgorithm = &asymmetricCipherAlgorithm{
		name: "ec-256",
	}
	EC384 *asymmetricCipherAlgorithm = &asymmetricCipherAlgorithm{
		name: "ec-384",
	}
	EC521 *asymmetricCipherAlgorithm = &asymmetricCipherAlgorithm{
		name: "ec-521",
	}
)

var symmetricCipherAlgorithms map[string]*symmetricCipherAlgorithm = map[string]*symmetricCipherAlgorithm{
	"chacha20": ChaCha20,
}

var keyExchangeCipherAlgorithms map[string]*asymmetricCipherAlgorithm = map[string]*asymmetricCipherAlgorithm{
	"ml-kem-768":  MLKEM768,
	"ml-kem-1024": MLKEM1024,
	"x25519":      X25519,
	"ec-256":      EC256,
	"ec-384":      EC384,
	"ec-521":      EC521,
}

var digitalSignatureCipherAlgorithms map[string]*asymmetricCipherAlgorithm = map[string]*asymmetricCipherAlgorithm{
	"ed25519": Ed25519,
	"ec-256":  EC256,
	"ec-384":  EC384,
	"ec-521":  EC521,
}

func GetCipherAlgorithm(name string) (CipherAlgorithm, bool) {
	if c, ok := GetSymmetricCipherAlgorithm(name); ok {
		return c, true
	}
	if c, ok := GetAsymmetricCipherAlgorithm(name); ok {
		return c, true
	}
	return nil, false
}

func GetSymmetricCipherAlgorithm(name string) (SymmetricCipherAlgorithm, bool) {
	if s, ok := symmetricCipherAlgorithms[strings.ToLower(name)]; ok {
		return s, true
	}
	return nil, false
}

func GetAsymmetricCipherAlgorithm(name string) (CipherAlgorithm, bool) {
	if c, ok := GetKeyExchangeCipherAlgorithm(name); ok {
		return c, true
	}
	if c, ok := GetDigitalSignatureCipherAlgorithm(name); ok {
		return c, true
	}
	return nil, false
}

func GetKeyExchangeCipherAlgorithm(name string) (CipherAlgorithm, bool) {
	if c, ok := keyExchangeCipherAlgorithms[strings.ToLower(name)]; ok {
		return c, true
	}
	return nil, false
}

func GetDigitalSignatureCipherAlgorithm(name string) (CipherAlgorithm, bool) {
	if c, ok := digitalSignatureCipherAlgorithms[strings.ToLower(name)]; ok {
		return c, true
	}
	return nil, false
}
