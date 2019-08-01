//////////////////////////////////////////////////
// crypto.go
// 
// 
// 
// MIT License
//
// Copyright (c) 2019 noknow.info
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,
// INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A 
// PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
// HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
// OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE
// OR THE USE OR OTHER DEALINGS IN THE SOFTW//ARE.
//////////////////////////////////////////////////
package crypto

import (
    "crypto/aes"
    "crypto/cipher"
    "crypto/rand"
    "encoding/hex"
    "io"
    "runtime"
    "strings"
)

var (
    version = runtime.Version()
)


//////////////////////////////////////////////////
// Encrypt using CBC mode.
// @param plainText: [string] The plain text.
// @param secretKey: [string] The secret key.
// @return The encrypted text and error. When an error occurs, the encrypted text will be empty string.
//////////////////////////////////////////////////
func EncryptCBC(plainText string, secretKey string) (string, error) {
    p := []byte(padLeft16Times(plainText))
    s := []byte(padLeft16Times(secretKey))
    block, err := aes.NewCipher(s)
    if err != nil {
        return "", err
    }
    cipherText := make([]byte, aes.BlockSize + len(p))
    iv := cipherText[:aes.BlockSize]
    _, err = io.ReadFull(rand.Reader, iv)
    if err != nil {
        return "", err
    }
    cbc := cipher.NewCBCEncrypter(block, iv)
    cbc.CryptBlocks(cipherText[aes.BlockSize:], p)
    return hex.EncodeToString(cipherText), nil
}


//////////////////////////////////////////////////
// Decrypt using CBC mode.
// @param cipherText: [string] The encrypted text.
// @param secretKey: [string] The secret key.
// @return The decrypted text and error. When an error occurs, the encrypted text will be empty string.
//////////////////////////////////////////////////
func DecryptCBC(cipherText string, secretKey string) (string, error) {
    decoded, err := hex.DecodeString(cipherText)
    if err != nil {
        return "", err
    }
    c := []byte(decoded)
    s := []byte(padLeft16Times(secretKey))
    block, err := aes.NewCipher(s)
    if err != nil {
        return "", err
    }
    iv := c[:aes.BlockSize]
    decrypted := make([]byte, len(c[aes.BlockSize:]))
    
    cbc := cipher.NewCBCDecrypter(block, iv)
    cbc.CryptBlocks(decrypted, c[aes.BlockSize:])
    return strings.TrimLeft(string(decrypted), "0"), nil
}


//////////////////////////////////////////////////
// Verify using CBC mode.
// @param plainText: [string] The plain text.
// @param secretKey: [string] The secret key.
// @param cipherText: [string] The encrypted text.
// @return
//////////////////////////////////////////////////
func VerifyCBC(plainText string, secretKey string, cipherText string) bool {
    decrypted, err := DecryptCBC(cipherText, secretKey)
    if err != nil {
        return false
    }
    if plainText == decrypted {
        return true
    } else {
        return false
    }
}


//////////////////////////////////////////////////
// Encrypt using CTR mode.
// @param plainText: [string] The plain text.
// @param secretKey: [string] The secret key.
// @return The encrypted text and error. When an error occurs, the encrypted text will be empty string.
//////////////////////////////////////////////////
func EncryptCTR(plainText string, secretKey string) (string, error) {
    p := []byte(plainText)
    s := []byte(padLeft16Times(secretKey))
    block, err := aes.NewCipher(s)
    if err != nil {
        return "", err
    }
    cipherText := make([]byte, aes.BlockSize + len(p))
    iv := cipherText[:aes.BlockSize]
    _, err = io.ReadFull(rand.Reader, iv)
    if err != nil {
        return "", err
    }
    stream := cipher.NewCTR(block, iv)
    stream.XORKeyStream(cipherText[aes.BlockSize:], p)
    result := hex.EncodeToString(cipherText)
    return result, nil
}


//////////////////////////////////////////////////
// Decrypt using CTR mode.
// @param cipherText: [string] The encrypted text.
// @param secretKey: [string] The secret key.
// @return The decrypted text and error. When an error occurs, the encrypted text will be empty string.
//////////////////////////////////////////////////
func DecryptCTR(cipherText string, secretKey string) (string, error) {
    decoded, err := hex.DecodeString(cipherText)
    if err != nil {
        return "", err
    }
    c := []byte(decoded)
    s := []byte(padLeft16Times(secretKey))
    block, err := aes.NewCipher(s)
    if err != nil {
        return "", err
    }
    decrypted := make([]byte, len(c[aes.BlockSize:]))
    stream := cipher.NewCTR(block, c[:aes.BlockSize])
    stream.XORKeyStream(decrypted, c[aes.BlockSize:])
    return string(decrypted), nil
}


//////////////////////////////////////////////////
// Verify using CTR mode.
// @param plainText: [string] The plain text.
// @param secretKey: [string] The secret key.
// @param cipherText: [string] The encrypted text.
// @return
//////////////////////////////////////////////////
func VerifyCTR(plainText string, secretKey string, cipherText string) bool {
    decrypted, err := DecryptCTR(cipherText, secretKey)
    if err != nil {
        return false
    }
    if plainText == decrypted {
        return true
    } else {
        return false
    }
}


//////////////////////////////////////////////////
// 0 Padding with 16 times from left side.
// @param 
//////////////////////////////////////////////////
func padLeft16Times(text string) string {
    padCnt := aes.BlockSize - len(text) % aes.BlockSize
    if padCnt % aes.BlockSize == 0 {
        return text
    } else {
        return strings.Repeat("0", padCnt) + text
    }
}

