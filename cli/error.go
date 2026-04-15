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
	"fmt"
	"os"
)

func PrintUnknownError(err error) int {
	if err != nil {
		fmt.Fprintf(os.Stderr, "未知错误：%s\n", err)
	} else {
		fmt.Fprintln(os.Stderr, "未知错误")
	}
	return 2
}

func PrintLogicUnreachableError(err error) int {
	if err != nil {
		fmt.Fprintf(os.Stderr, "逻辑无法到达：%s\n", err)
	} else {
		fmt.Fprintln(os.Stderr, "逻辑无法到达")
	}
	return 2
}

func PrintRNGError(err error) int {
	if err != nil {
		fmt.Fprintf(os.Stderr, "RNG 异常：%s\n", err)
	} else {
		fmt.Fprintln(os.Stderr, "RNG 异常")
	}
	return 2
}

func PrintKeyError(err error) int {
	if err != nil {
		fmt.Fprintf(os.Stderr, "密钥错误：%s\n", err)
	} else {
		fmt.Fprintln(os.Stderr, "密钥错误")
	}
	return 2
}

type EncryptError struct {
	Phase string
	Cause error
}

func (e *EncryptError) Error() string {
	return fmt.Sprintf("加密失败（步骤：%s）：%s", e.Phase, e.Cause)
}

func NewEncryptError(phase string, cause error) *EncryptError {
	return &EncryptError{
		Phase: phase,
		Cause: cause,
	}
}

type DecryptError struct {
	Phase string
	Cause error
}

func (e *DecryptError) Error() string {
	return fmt.Sprintf("解密失败（步骤：%s）：%s", e.Phase, e.Cause)
}

func NewDecryptError(phase string, cause error) *DecryptError {
	return &DecryptError{
		Phase: phase,
		Cause: cause,
	}
}

type IllegalKeyError struct {
	AlgorithmName string
}

func (e *IllegalKeyError) Error() string {
	return fmt.Sprintf("非法 %s 密钥", e.AlgorithmName)
}

func NewIllegalKeyError(algorithmName string) *IllegalKeyError {
	return &IllegalKeyError{
		AlgorithmName: algorithmName,
	}
}

type IllegalPrivateKeyError struct {
	AlgorithmName string
	Cause         error
}

func (e *IllegalPrivateKeyError) Error() string {
	return fmt.Sprintf("非法 %s 私钥：%s", e.AlgorithmName, e.Cause)
}

func NewIllegalPrivateKeyError(algorithmName string, cause error) *IllegalPrivateKeyError {
	return &IllegalPrivateKeyError{
		AlgorithmName: algorithmName,
		Cause:         cause,
	}
}

type IllegalPublicKeyError struct {
	AlgorithmName string
	Cause         error
}

func (e *IllegalPublicKeyError) Error() string {
	return fmt.Sprintf("非法 %s 公钥：%s", e.AlgorithmName, e.Cause)
}

func NewIllegalPublicKeyError(algorithmName string, cause error) *IllegalPublicKeyError {
	return &IllegalPublicKeyError{
		AlgorithmName: algorithmName,
		Cause:         cause,
	}
}
