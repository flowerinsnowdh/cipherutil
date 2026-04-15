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
package cli

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/mlkem"
	"crypto/rand"
	"fmt"
	"io"
	"strings"

	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/chacha20"
)

func GenerateEncodedKey(algorithm string) ([]byte, error) {
	switch strings.ToLower(algorithm) {
	case "ml-kem-768":
		var (
			key *mlkem.DecapsulationKey768
			err error
		)
		if key, err = mlkem.GenerateKey768(); err != nil {
			return nil, err
		}
		return key.Bytes(), nil
	case "ml-kem-1024":
		var (
			key *mlkem.DecapsulationKey1024
			err error
		)
		if key, err = mlkem.GenerateKey1024(); err != nil {
			return nil, err
		}
		return key.Bytes(), nil
	case "x25519":
		var (
			key *ecdh.PrivateKey
			err error
		)
		if key, err = ecdh.X25519().GenerateKey(rand.Reader); err != nil {
			return nil, err
		}
		return key.Bytes(), nil
	case "ec-256":
		var (
			key *ecdh.PrivateKey
			err error
		)
		if key, err = ecdh.P256().GenerateKey(rand.Reader); err != nil {
			return nil, err
		}
		return key.Bytes(), nil
	case "ec-384":
		var (
			key *ecdh.PrivateKey
			err error
		)
		if key, err = ecdh.P384().GenerateKey(rand.Reader); err != nil {
			return nil, err
		}
		return key.Bytes(), nil
	case "ec-521":
		var (
			key *ecdh.PrivateKey
			err error
		)
		if key, err = ecdh.P521().GenerateKey(rand.Reader); err != nil {
			return nil, err
		}
		return key.Bytes(), nil
	case "ed25519":
		var (
			key ed25519.PrivateKey
			err error
		)
		if _, key, err = ed25519.GenerateKey(rand.Reader); err != nil {
			return nil, err
		}
		return key.Seed(), err
	case "chacha20":
		var data []byte = make([]byte, 32)

		if _, err := rand.Read(data); err != nil {
			return nil, fmt.Errorf("RNG 异常：%s", err)
		}
		return data, nil
	default:
		return nil, fmt.Errorf("不支持的算法：%s", algorithm)
	}
}

func GenerateSecret(algorithm string, keyData []byte) ([]byte, []byte, error) {
	switch strings.ToLower(algorithm) {
	case "ml-kem-768":
		var pk *mlkem.EncapsulationKey768
		switch len(keyData) {
		case mlkem.SeedSize:
			var (
				sk  *mlkem.DecapsulationKey768
				err error
			)
			if sk, err = mlkem.NewDecapsulationKey768(keyData); err != nil {
				return nil, nil, NewIllegalPrivateKeyError("ML-KEM-768", err)
			}
			pk = sk.EncapsulationKey()
		case mlkem.EncapsulationKeySize768:
			var err error
			if pk, err = mlkem.NewEncapsulationKey768(keyData); err != nil {
				return nil, nil, NewIllegalPublicKeyError("ML-KEM-768", err)
			}
		default:
			return nil, nil, NewIllegalKeyError("ML-KEM-768")
		}
		var (
			shared     []byte
			ciphertext []byte
		)
		shared, ciphertext = pk.Encapsulate()
		var secret [32]byte = blake2b.Sum256(shared)
		return secret[:], ciphertext, nil
	case "ml-kem-1024":
		var pk *mlkem.EncapsulationKey1024
		switch len(keyData) {
		case mlkem.SeedSize:
			var (
				sk  *mlkem.DecapsulationKey1024
				err error
			)
			if sk, err = mlkem.NewDecapsulationKey1024(keyData); err != nil {
				return nil, nil, NewIllegalPrivateKeyError("ML-KEM-1024", err)
			}
			pk = sk.EncapsulationKey()
		case mlkem.EncapsulationKeySize1024:
			var err error
			if pk, err = mlkem.NewEncapsulationKey1024(keyData); err != nil {
				return nil, nil, NewIllegalPublicKeyError("ML-KEM-1024", err)
			}
		default:
			return nil, nil, NewIllegalKeyError("ML-KEM-1024")
		}
		var (
			shared     []byte
			ciphertext []byte
		)
		shared, ciphertext = pk.Encapsulate()
		var secret [32]byte = blake2b.Sum256(shared)
		return secret[:], ciphertext, nil
	case "x25519":
		return generateSecretECDH("X25519", ecdh.X25519(), keyData, 32, 32)
	case "ec-256":
		return generateSecretECDH("EC-256", ecdh.P256(), keyData, 32, 65)
	case "ec-384":
		return generateSecretECDH("EC-384", ecdh.P384(), keyData, 48, 97)
	case "ec-521":
		return generateSecretECDH("EC-521", ecdh.P521(), keyData, 66, 133)
	case "chacha20":
		if len(keyData) != chacha20.KeySize {
			return nil, nil, fmt.Errorf("无效的 ChaCha20 密钥：需要长度 %d，但提供了 %d", chacha20.KeySize, len(keyData))
		}
		return keyData, nil, nil
	default:
		return nil, nil, fmt.Errorf("未知算法：%s", algorithm)
	}
}

func generateSecretECDH(algorithmName string, curve ecdh.Curve, keyData []byte, skSize int, pkSize int) ([]byte, []byte, error) {
	var pk *ecdh.PublicKey
	switch len(keyData) {
	case skSize:
		var (
			sk  *ecdh.PrivateKey
			err error
		)
		if sk, err = curve.NewPrivateKey(keyData); err != nil {
			return nil, nil, NewIllegalPrivateKeyError(algorithmName, err)
		}
		pk = sk.PublicKey()
	case pkSize:
		var err error
		if pk, err = curve.NewPublicKey(keyData); err != nil {
			return nil, nil, NewIllegalPublicKeyError(algorithmName, err)
		}
	default:
		return nil, nil, NewIllegalKeyError(algorithmName)
	}

	var (
		tempSK *ecdh.PrivateKey
		err    error
	)
	if tempSK, err = curve.GenerateKey(rand.Reader); err != nil {
		return nil, nil, fmt.Errorf("RNG 异常：%s", err)
	}
	var (
		tempPK    *ecdh.PublicKey = tempSK.PublicKey()
		sharedKey []byte
	)
	if sharedKey, err = tempSK.ECDH(pk); err != nil {
		return nil, nil, NewEncryptError("Key Exchange", err)
	}
	var secret [32]byte = blake2b.Sum256(sharedKey)
	return secret[:], tempPK.Bytes(), nil
}

func Decapsulate(algorithm string, inputReader io.Reader, skData []byte) ([]byte, error) {
	switch strings.ToLower(algorithm) {
	case "ml-kem-768":
		var (
			sk  *mlkem.DecapsulationKey768
			err error
		)
		if sk, err = mlkem.NewDecapsulationKey768(skData); err != nil {
			return nil, NewIllegalPrivateKeyError("ML-KEM-768", err)
		}
		var ciphertext []byte = make([]byte, mlkem.CiphertextSize768)
		if _, err := io.ReadFull(inputReader, ciphertext); err != nil {
			return nil, NewDecryptError("Ciphertext", err)
		}
		var shared []byte
		if shared, err = sk.Decapsulate(ciphertext); err != nil {
			return nil, NewDecryptError("Decapsulate", err)
		}
		var secret [32]byte = blake2b.Sum256(shared)
		return secret[:], nil
	case "ml-kem-1024":
		var (
			sk  *mlkem.DecapsulationKey1024
			err error
		)
		if sk, err = mlkem.NewDecapsulationKey1024(skData); err != nil {
			return nil, NewIllegalPrivateKeyError("ML-KEM-1024", err)
		}
		var ciphertext []byte = make([]byte, mlkem.CiphertextSize1024)
		if _, err := io.ReadFull(inputReader, ciphertext); err != nil {
			return nil, NewDecryptError("Ciphertext", err)
		}
		var shared []byte
		if shared, err = sk.Decapsulate(ciphertext); err != nil {
			return nil, NewDecryptError("Decapsulate", err)
		}
		var secret [32]byte = blake2b.Sum256(shared)
		return secret[:], nil
	case "x25519":
		return decapsulate(ecdh.X25519(), 32, inputReader, skData, "X25519")
	case "ec-256":
		return decapsulate(ecdh.P256(), 65, inputReader, skData, "EC-256")
	case "ec-384":
		return decapsulate(ecdh.P384(), 97, inputReader, skData, "EC-384")
	case "ec-521":
		return decapsulate(ecdh.P521(), 133, inputReader, skData, "EC-521")
	case "chacha20":
		if len(skData) != chacha20.KeySize {
			return nil, fmt.Errorf("非法 ChaCha20 密钥：需要长度 %d，但提供了 %d", chacha20.KeySize, len(skData))
		}
		return skData, nil
	default:
		return nil, fmt.Errorf("未知算法：%s", algorithm)
	}
}

func decapsulate(curve ecdh.Curve, epkSize int, inputReader io.Reader, skData []byte, algorithmName string) ([]byte, error) {
	var (
		sk  *ecdh.PrivateKey
		err error
	)
	if sk, err = curve.NewPrivateKey(skData); err != nil {
		return nil, NewIllegalPrivateKeyError(algorithmName, err)
	}
	var epkData []byte = make([]byte, epkSize)
	if _, err := io.ReadFull(inputReader, epkData); err != nil {
		return nil, NewDecryptError("Ephemeral Public Key", err)
	}
	var epk *ecdh.PublicKey
	if epk, err = curve.NewPublicKey(epkData); err != nil {
		return nil, NewDecryptError("Ephemeral Public Key", err)
	}
	var shared []byte
	if shared, err = sk.ECDH(epk); err != nil {
		return nil, NewDecryptError("Key Exchange", err)
	}
	var secret [32]byte = blake2b.Sum256(shared)
	return secret[:], nil
}
