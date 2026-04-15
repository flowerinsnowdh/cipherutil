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
package util

import "io"

type OnceCloser struct {
	closed bool
	closer io.Closer
}

func NewCloser(closer io.Closer) *OnceCloser {
	return &OnceCloser{
		closed: false,
		closer: closer,
	}
}

func (c *OnceCloser) Close() error {
	if !c.closed {
		c.closed = true
		return c.closer.Close()
	}
	return nil
}
