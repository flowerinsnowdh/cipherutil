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
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"strings"
)

func NewEncoderByName(name string, w io.Writer) (io.Writer, io.Closer, error) {
	switch strings.ToLower(name) {
	case "raw":
		return w, nil, nil
	case "base64":
		var wc io.WriteCloser = base64.NewEncoder(base64.StdEncoding, w)
		return wc, wc, nil
	case "hex":
		var wr io.Writer = hex.NewEncoder(w)
		return wr, nil, nil
	default:
		return nil, nil, fmt.Errorf("未知编码：%s", name)
	}
}

func NewDecoderByAlgorithm(name string, r io.Reader) (io.Reader, error) {
	switch strings.ToLower(name) {
	case "raw":
		return r, nil
	case "base64":
		var re io.Reader = base64.NewDecoder(base64.StdEncoding, r)
		return re, nil
	case "hex":
		var re io.Reader = hex.NewDecoder(r)
		return re, nil
	default:
		return nil, fmt.Errorf("未知编码：%s", name)
	}
}
