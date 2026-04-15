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
	"errors"
	"fmt"
	"strings"

	"github.com/flowerinsnowdh/cipherutil/std"
)

type Args struct {
	Key            string
	KeyDecoding    string
	Input          string
	InputDecoding  string
	Output         string
	OutputEncoding string
	Args           []string
}

func (a *Args) Validate() error {
	if err := a.checkCodec(); err != nil {
		return err
	}
	if err := a.checkCommand(); err != nil {
		return err
	}
	return nil
}

func (a *Args) checkCodec() error {
	switch strings.ToLower(a.KeyDecoding) {
	case "raw", "base64", "hex":
	default:
		return fmt.Errorf("--key-decoding 值 '%s' 不正确，它只能是 'raw'/'base64'/'hex'。", a.KeyDecoding)
	}

	switch strings.ToLower(a.InputDecoding) {
	case "raw", "base64", "hex":
	default:
		return fmt.Errorf("--input-decoding 值 '%s' 不正确，它只能是 'raw'/'base64'/'hex'。", a.InputDecoding)
	}

	switch strings.ToLower(a.OutputEncoding) {
	case "raw", "base64", "hex":
	default:
		return fmt.Errorf("--output-encoding 值 '%s' 不正确，它只能是 'raw'/'base64'/'hex'。", a.OutputEncoding)
	}

	return nil
}

func (a *Args) checkCommand() error {
	if 0 == len(a.Args) {
		return errors.New("需要命令")
	}
	var command string = a.Args[0]
	switch strings.ToLower(command) {
	case "genkey":
		if 2 != len(a.Args) {
			return errors.New("用法：genkey <algorithm> [-oO]")
		}
		var algorithm string = a.Args[1]
		if _, ok := std.GetCipherAlgorithm(algorithm); !ok {
			return fmt.Errorf("genkey: 未知算法：%s", algorithm)
		}
	case "pubkey":
		if len(a.Args) != 2 {
			return errors.New("用法：pubkey <algorithm>")
		}
		var algorithm string = a.Args[1]
		if _, ok := std.GetAsymmetricCipherAlgorithm(algorithm); !ok {
			return fmt.Errorf("pubkey：未知算法：%s", algorithm)
		}
	case "encrypt", "decrypt":
		if 2 != len(a.Args) {
			return fmt.Errorf("用法：%s: <algorithm> [-kKiIoO]", strings.ToLower(command))
		}
		var algorithm string = a.Args[1]
		if _, ok := std.GetKeyExchangeCipherAlgorithm(algorithm); !ok {
			return fmt.Errorf("%s: 未知算法：%s", strings.ToLower(command), algorithm)
		}
	default:
		return fmt.Errorf("未知命令：%s", command)
	}
	return nil
}
