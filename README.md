# CipherUtil
有关密码运算的 CLI 程序，尽可能无特殊编码（密钥封装除外）

# 用法
## 标记
- `-k`, `--key` `<string>` - 指定密钥输入，默认值 `-`。
- `-K`, `--key-decoding` - 指定密钥解码格式，可选值 `raw`/`base64`/`hex` 默认值 `raw`。
- `-i`, `--input` `<string>` - 指定输入流，默认值 `-`。
- `-I`, `--input-decoding` - 指定输入解码格式，可选值 `raw`/`base64`/`hex` 默认值 `raw`。
- `-o`, `--output` `<string>` - 指定输出流，默认值 `-`。
- `-O`, `--output-encoding` - 指定输出编码格式，可选值 `raw`/`base64`/`hex` 默认值 `raw`。

## 生成密钥

```shell
cipherutil genkey <algorithm> [-oO]
```

## 输出公钥

```shell
cipherutil genkey <algorithm> [-kKoO]
```

## 加密

```shell
cipherutil encrypt <algorithm> [-kKiIoO]
```

## 解密

```shell
cipherutil decrypt <algorithm> [-kKiIoO]
```
