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
package main

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/mlkem"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/flowerinsnowdh/cipherutil/cli"
	"github.com/flowerinsnowdh/cipherutil/util"
	"github.com/spf13/pflag"
	"golang.org/x/crypto/chacha20"
)

func main() {
	os.Exit(run())
}

var args *cli.Args

func run() int {
	args = &cli.Args{}
	pflag.StringVarP(&args.Key, "key", "k", "-", "指定密钥输入流，默认值 '-'。")
	pflag.StringVarP(&args.KeyDecoding, "key-decoding", "K", "raw", "指定密钥解码格式，可选值 'raw'/'base64'/'hex' 默认值 'raw'。")
	pflag.StringVarP(&args.Input, "input", "i", "-", "指定输入流，默认值 '-'。")
	pflag.StringVarP(&args.InputDecoding, "input-decoding", "I", "raw", "指定输入解码格式，可选值 'raw'/'base64'/'hex' 默认值 'raw'。")
	pflag.StringVarP(&args.Output, "output", "o", "-", "指定输出流，默认值 '-'。")
	pflag.StringVarP(&args.OutputEncoding, "output-encoding", "O", "raw", "指定输出编码格式，可选值 'raw'/'base64'/'hex' 默认值 'raw'。")
	pflag.Parse()
	args.Args = pflag.Args()

	if err := args.Validate(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}

	var command string = args.Args[0]

	var (
		keyNeed   bool
		inputNeed bool
	)
	switch strings.ToLower(command) {
	case "encrypt", "decrypt":
		keyNeed = true
		inputNeed = true
	case "pubkey":
		keyNeed = true
	}
	if keyNeed && inputNeed && "-" == args.Key && "-" == args.Input {
		fmt.Fprintln(os.Stderr, "--key 和 --input 不能同时指定 '-'")
		return 1
	}

	var keyData []byte
	if keyNeed {
		var (
			keyFile       *os.File
			keyFileCloser *util.OnceCloser
		)
		if "-" == args.Key {
			keyFile = os.Stdin
		} else {
			var err error
			if keyFile, err = os.Open(args.Key); err != nil {
				fmt.Fprintf(os.Stderr, "打开密钥文件 %s 失败：%s", args.Key, err)
				fmt.Fprintln(os.Stderr)
				return 2
			}
			keyFileCloser = util.NewCloser(keyFile)
			defer keyFileCloser.Close()
		}

		var (
			keyReader io.Reader
			err       error
		)
		if keyReader, err = cli.NewDecoderByAlgorithm(args.KeyDecoding, keyFile); err != nil {
			panic(err)
		}
		var buffer *bytes.Buffer = &bytes.Buffer{}
		if _, err := io.Copy(buffer, keyReader); err != nil {
			fmt.Fprintf(os.Stderr, "读取密钥失败：%s", err)
			fmt.Fprintln(os.Stderr)
			return 2
		}
		if keyFileCloser != nil {
			if err := keyFileCloser.Close(); err != nil {
				fmt.Fprintf(os.Stderr, "关闭密钥文件 %s 失败：%s", args.Key, err)
				fmt.Fprintln(os.Stderr)
				return 2
			}
		}
		keyData = buffer.Bytes()
	}

	var inputReader io.Reader
	if inputNeed {
		var inputFile *os.File
		if "-" == args.Input {
			inputFile = os.Stdin
		} else {
			var err error
			if inputFile, err = os.Open(args.Input); err != nil {
				fmt.Fprintf(os.Stderr, "打开输入文件 %s 失败：%s", args.Input, err)
				fmt.Fprintln(os.Stderr)
				return 2
			}
			defer inputFile.Close()
		}
		var err error
		if inputReader, err = cli.NewDecoderByAlgorithm(args.InputDecoding, inputFile); err != nil {
			panic(err)
		}
	}

	var outputFile *os.File
	if "-" == args.Output {
		outputFile = os.Stdout
	} else {
		var err error
		if outputFile, err = os.Create(args.Output); err != nil {
			fmt.Fprintf(os.Stderr, "打开输出文件 %s 失败：%s", args.Output, err)
			fmt.Fprintln(os.Stderr)
			return 2
		}
		defer outputFile.Close()
	}
	var (
		outputWriter io.Writer
		outputCloser io.Closer
		err          error
	)
	if outputWriter, outputCloser, err = cli.NewEncoderByName(args.OutputEncoding, outputFile); err != nil {
		panic(err)
	}
	if outputCloser != nil {
		defer outputCloser.Close()
	}

	if len(args.Args) == 2 {
		switch strings.ToLower(command) {
		case "genkey":
			var (
				algorithm  string = args.Args[1]
				encodedKey []byte
			)
			switch strings.ToLower(algorithm) {
			case "ml-kem-768":
				var (
					key *mlkem.DecapsulationKey768
					err error
				)
				if key, err = mlkem.GenerateKey768(); err != nil {
					return cli.PrintRNGError(err)
				}
				encodedKey = key.Bytes()
			case "ml-kem-1024":
				var (
					key *mlkem.DecapsulationKey1024
					err error
				)
				if key, err = mlkem.GenerateKey1024(); err != nil {
					return cli.PrintRNGError(err)
				}
				encodedKey = key.Bytes()
			case "x25519":
				var (
					key *ecdh.PrivateKey
					err error
				)
				if key, err = ecdh.X25519().GenerateKey(rand.Reader); err != nil {
					return cli.PrintRNGError(err)
				}
				encodedKey = key.Bytes()
			case "ed25519":
				var err error
				if _, encodedKey, err = ed25519.GenerateKey(rand.Reader); err != nil {
					return cli.PrintRNGError(err)
				}
			case "ec-256":
				var (
					key *ecdh.PrivateKey
					err error
				)
				if key, err = ecdh.P256().GenerateKey(rand.Reader); err != nil {
					return cli.PrintRNGError(err)
				}
				encodedKey = key.Bytes()
			case "ec-384":
				var (
					key *ecdh.PrivateKey
					err error
				)
				if key, err = ecdh.P384().GenerateKey(rand.Reader); err != nil {
					return cli.PrintRNGError(err)
				}
				encodedKey = key.Bytes()
			case "ec-521":
				var (
					key *ecdh.PrivateKey
					err error
				)
				if key, err = ecdh.P521().GenerateKey(rand.Reader); err != nil {
					return cli.PrintRNGError(err)
				}
				encodedKey = key.Bytes()
			default:
				cli.PrintRNGError(err)
			}
			if _, err = io.Copy(outputWriter, bytes.NewReader(encodedKey)); err != nil {
				fmt.Fprintf(os.Stderr, "写入输出文件 %s 错误：%s", args.Output, err)
				fmt.Fprintln(os.Stderr)
			}
			return 0
		case "pubkey":
			var (
				algorithm  string = args.Args[1]
				encodedKey []byte
			)
			switch strings.ToLower(algorithm) {
			case "ml-kem-768":
				var (
					key *mlkem.DecapsulationKey768
					err error
				)
				if key, err = mlkem.NewDecapsulationKey768(keyData); err != nil {
					fmt.Fprintln(os.Stderr, cli.NewIllegalPrivateKeyError("ML-KEM-768", err))
					return 2
				}
				encodedKey = key.EncapsulationKey().Bytes()
			case "ml-kem-1024":
				var (
					key *mlkem.DecapsulationKey1024
					err error
				)
				if key, err = mlkem.NewDecapsulationKey1024(keyData); err != nil {
					fmt.Fprintln(os.Stderr, cli.NewIllegalPrivateKeyError("ML-KEM-1024", err))
					return 2
				}
				encodedKey = key.EncapsulationKey().Bytes()
			case "x25519":
				var (
					key *ecdh.PrivateKey
					err error
				)
				if key, err = ecdh.X25519().NewPrivateKey(keyData); err != nil {
					fmt.Fprintln(os.Stderr, cli.NewIllegalPrivateKeyError("X25519", err))
					return 2
				}
				encodedKey = key.PublicKey().Bytes()
			case "ec-256":
				var (
					key *ecdh.PrivateKey
					err error
				)
				if key, err = ecdh.P256().NewPrivateKey(keyData); err != nil {
					fmt.Fprintln(os.Stderr, cli.NewIllegalPrivateKeyError("EC-256", err))
					return 2
				}
				encodedKey = key.PublicKey().Bytes()
			case "ec-384":
				var (
					key *ecdh.PrivateKey
					err error
				)
				if key, err = ecdh.P384().NewPrivateKey(keyData); err != nil {
					fmt.Fprintln(os.Stderr, cli.NewIllegalPrivateKeyError("EC-384", err))
					return 2
				}
				encodedKey = key.PublicKey().Bytes()
			case "ec-521":
				var (
					key *ecdh.PrivateKey
					err error
				)
				if key, err = ecdh.P521().NewPrivateKey(keyData); err != nil {
					fmt.Fprintln(os.Stderr, cli.NewIllegalPrivateKeyError("EC-521", err))
					return 2
				}
				encodedKey = key.PublicKey().Bytes()
			default:
				panic(fmt.Errorf("未知算法：%s", algorithm))
			}
			if _, err := io.Copy(outputWriter, bytes.NewReader(encodedKey)); err != nil {
				fmt.Fprintf(os.Stderr, "写入输出文件 %s 失败：%s", args.Output, err)
				fmt.Fprintln(os.Stderr)
				return 2
			}
			return 0
		case "encrypt":
			// Encapsulate
			var (
				algorithm  string = args.Args[1]
				secret     []byte
				ciphertext []byte
				err        error
			)
			if secret, ciphertext, err = cli.GenerateSecret(algorithm, keyData); err != nil {
				fmt.Fprintln(os.Stderr, err)
				return 2
			}

			// Ciphertext
			if ciphertext != nil {
				if _, err := io.Copy(outputWriter, bytes.NewReader(ciphertext)); err != nil {
					fmt.Fprintln(os.Stderr, cli.NewEncryptError("Ciphertext", err))
					return 2
				}
			}

			// Nonce
			var nonce []byte = make([]byte, chacha20.NonceSize)
			if _, err := rand.Read(nonce); err != nil {
				fmt.Fprintln(os.Stderr, cli.NewEncryptError("Nonce", err))
				return 2
			}
			if _, err := io.Copy(outputWriter, bytes.NewReader(nonce)); err != nil {
				fmt.Fprintln(os.Stderr, cli.NewEncryptError("Nonce", err))
				return 2
			}

			// Cipher
			var cipher *chacha20.Cipher
			if cipher, err = chacha20.NewUnauthenticatedCipher(secret, nonce); err != nil {
				panic(err)
			}
			var (
				inputBuffer  []byte = make([]byte, 1024*1024*1024)
				outputBuffer []byte = make([]byte, 1024*1024*1024)
				n            int
			)
			for {
				if n, err = inputReader.Read(inputBuffer); err != nil {
					if err == io.EOF {
						break
					}
					fmt.Fprintln(os.Stderr, cli.NewEncryptError("Cipher Read", err))
					return 2
				}
				cipher.XORKeyStream(outputBuffer[:n], inputBuffer[:n])
				if _, err := io.Copy(outputWriter, bytes.NewReader(outputBuffer[:n])); err != nil {
					fmt.Fprintln(os.Stderr, cli.NewEncryptError("Cipher Write", err))
					return 2
				}
			}
			return 0
		case "decrypt":
			// Decapsulate
			var (
				algorithm string = args.Args[1]
				secret    []byte
				err       error
			)
			if secret, err = cli.Decapsulate(algorithm, inputReader, keyData); err != nil {
				fmt.Fprintln(os.Stderr, err)
				return 2
			}

			// Nonce
			var nonce []byte = make([]byte, chacha20.NonceSize)
			if _, err = io.ReadFull(inputReader, nonce); err != nil {
				fmt.Fprintln(os.Stderr, cli.NewDecryptError("Nonce", err))
				return 2
			}

			// Cipher
			var cipher *chacha20.Cipher
			if cipher, err = chacha20.NewUnauthenticatedCipher(secret, nonce); err != nil {
				return cli.PrintUnknownError(err)
			}
			var (
				inputBuffer  []byte = make([]byte, 1024*1024*1024)
				outputBuffer []byte = make([]byte, 1024*1024*1024)
				n            int
			)
			for {
				if n, err = inputReader.Read(inputBuffer); err != nil {
					if err == io.EOF {
						break
					}
					fmt.Fprintln(os.Stderr, cli.NewDecryptError("Cipher Read", err))
					return 2
				}
				cipher.XORKeyStream(outputBuffer[:n], inputBuffer[:n])
				if _, err = io.Copy(outputWriter, bytes.NewReader(outputBuffer[:n])); err != nil {
					fmt.Fprintln(os.Stderr, cli.NewDecryptError("Cipher Write", err))
					return 2
				}
			}
			return 0
		default:
			panic(fmt.Errorf("未知命令：%s", command))
		}
	}
	panic(errors.New("命令行参数解析失败"))
}
