/*
 Copyright (C) 2018 Roopesh Chander S <roop@roopc.net>

 Licensed under the GPLv3: http://www.gnu.org/licenses/gpl-3.0.html
 */

import ChaCha20
import Poly1305

class ChaCha20Poly1305 {

    static var chaCha20BlockSize = 64

    var chaChaContext = ChaCha20.ECRYPT_ctx()
    var key: Array<UInt8>? = nil
    var ivFixedPrefix: Array<UInt8>? = nil /* 4 bytes, used only for testing */

    func setKey(key: [UInt8]) {
        precondition(key.count == 32, "ChaCha20Poly1305.setKey: Key must be exactly 32 bytes long")
        withUnsafePointerTo(key: key) { (keyPtr) in
            withUnsafeMutablePointer(to: &chaChaContext) { chaChaCtxPtr in
                ChaCha20.ECRYPT_keysetup(chaChaCtxPtr, keyPtr, UInt32(key.count * 8) /* key bits */)
            }
        }
        self.key = key
    }

    func encrypt(plaintext: [UInt8], nonce: UInt64, associatedData: [UInt8]) -> (ciphertext: [UInt8], tag: [UInt8]) {
        // Encrypt using AEAD_CHACHA20_POLY1305 from RFC 7539

        guard let key = self.key else { fatalError("ChaCha20Poly1305.encrypt: setKey() not called yet") }
        precondition(associatedData.count > 0, "ChaCha20Poly1305.encrypt: Associated data can't be empty")

        let dataLength = plaintext.count
        let associatedDataLength = associatedData.count
        var ciphertext = Array<UInt8>(repeating: 0, count: dataLength)
        var tag = Array<UInt8>(repeating: 0, count: 16)

        var iv: [UInt8]
        if let ivFixedPrefix = ivFixedPrefix {
            precondition(ivFixedPrefix.count == 4)
            iv = Array<UInt8>(repeating: 0, count: 8 + ivFixedPrefix.count)
            writeBytes(to: &iv, fromArray: ivFixedPrefix)
            writeBytes(to: &iv, offset: ivFixedPrefix.count, fromUInt64: nonce)
        } else {
            iv = Array<UInt8>(repeating: 0, count: 8)
            writeBytes(to: &iv, fromUInt64: nonce)
        }

        var lengthOctets = Array<UInt8>(repeating: 0, count: 16)
        writeBytes(to: &lengthOctets, fromUInt64: UInt64(associatedDataLength))
        writeBytes(to: &lengthOctets, offset: 8, fromUInt64: UInt64(dataLength))
        var oneTimeKey = Array<UInt8>(repeating: 0, count: ChaCha20Poly1305.chaCha20BlockSize)

        withUnsafePointersTo(output: &ciphertext, tag: &tag, oneTimeKey: &oneTimeKey,
                             data: plaintext, key: key,
                             iv: iv, ad: associatedData, lengths: lengthOctets) {
            (ciphertextPtr, tagPtr, oneTimeKeyPtr, plaintextPtr, keyPtr, ivPtr, adPtr, lengthsPtr) in
            withUnsafeMutablePointer(to: &chaChaContext) { chaChaCtxPtr in
                // Generate Poly1305 one-time key Using ChaCha20
                ChaCha20.ECRYPT_ivsetup(chaChaCtxPtr, ivPtr, UInt32(iv.count))
                ChaCha20.ECRYPT_keystream_bytes(chaChaCtxPtr, oneTimeKeyPtr, UInt32(ChaCha20Poly1305.chaCha20BlockSize))
                // Encrypt the plaintext using ChaCha20
                ChaCha20.ECRYPT_ivsetup(chaChaCtxPtr, ivPtr, UInt32(iv.count))
                ChaCha20.ECRYPT_encrypt_bytes(chaChaCtxPtr, plaintextPtr, ciphertextPtr, UInt32(dataLength))
                // Calculate the authentication tag using Poly1305
                var poly1305_ctx = Poly1305.poly1305_ctx()
                withUnsafeMutablePointer(to: &poly1305_ctx) { polyCtxPtr in
                    poly1305_init(polyCtxPtr, oneTimeKeyPtr)
                    poly1305_add_blocks(polyCtxPtr, adPtr, UInt64(associatedDataLength))
                    poly1305_add_blocks(polyCtxPtr, ciphertextPtr, UInt64(dataLength))
                    poly1305_add_blocks(polyCtxPtr, lengthsPtr, UInt64(16))
                    poly1305_finish(polyCtxPtr, tagPtr, oneTimeKeyPtr)
                }
            }
        }

        return (ciphertext: ciphertext, tag: tag)
    }

    func decrypt(ciphertext: [UInt8], nonce: UInt64, associatedData: [UInt8], tag inputTag: [UInt8]) -> [UInt8]? {
        // Decrypt using AEAD_CHACHA20_POLY1305 from RFC 7539

        guard let key = self.key else { fatalError("ChaCha20Poly1305.encrypt: setKey() not called yet") }
        precondition(associatedData.count > 0, "ChaCha20Poly1305.encrypt: Associated data can't be empty")

        let dataLength = ciphertext.count
        let associatedDataLength = associatedData.count
        var plaintext = Array<UInt8>(repeating: 0, count: dataLength)
        var tag = Array<UInt8>(repeating: 0, count: 16)

        var iv: [UInt8]
        if let ivFixedPrefix = ivFixedPrefix {
            precondition(ivFixedPrefix.count == 4)
            iv = Array<UInt8>(repeating: 0, count: 8 + ivFixedPrefix.count)
            writeBytes(to: &iv, fromArray: ivFixedPrefix)
            writeBytes(to: &iv, offset: ivFixedPrefix.count, fromUInt64: nonce)
        } else {
            iv = Array<UInt8>(repeating: 0, count: 8)
            writeBytes(to: &iv, fromUInt64: nonce)
        }

        var lengthOctets = Array<UInt8>(repeating: 0, count: 16)
        writeBytes(to: &lengthOctets, fromUInt64: UInt64(associatedDataLength))
        writeBytes(to: &lengthOctets, offset: 8, fromUInt64: UInt64(dataLength))
        var oneTimeKey = Array<UInt8>(repeating: 0, count: ChaCha20Poly1305.chaCha20BlockSize)

        withUnsafePointersTo(output: &plaintext, tag: &tag, oneTimeKey: &oneTimeKey, data: ciphertext, key: key,
                             iv: iv, ad: associatedData, lengths: lengthOctets) {
            (plaintextPtr, tagPtr, oneTimeKeyPtr, ciphertextPtr, keyPtr, ivPtr, adPtr, lengthsPtr) in
            withUnsafeMutablePointer(to: &chaChaContext) { chaChaCtxPtr in
                // Generate Poly1305 one-time key Using ChaCha20
                ChaCha20.ECRYPT_ivsetup(chaChaCtxPtr, ivPtr, UInt32(iv.count))
                ChaCha20.ECRYPT_keystream_bytes(chaChaCtxPtr, oneTimeKeyPtr, UInt32(ChaCha20Poly1305.chaCha20BlockSize))
                // Decrypt the ciphertext using ChaCha20
                ChaCha20.ECRYPT_ivsetup(chaChaCtxPtr, ivPtr, UInt32(iv.count))
                ChaCha20.ECRYPT_decrypt_bytes(chaChaCtxPtr, ciphertextPtr, plaintextPtr, UInt32(dataLength))
                // Calculate the authentication tag using Poly1305
                var poly1305_ctx = Poly1305.poly1305_ctx()
                withUnsafeMutablePointer(to: &poly1305_ctx) { polyCtxPtr in
                    poly1305_init(polyCtxPtr, oneTimeKeyPtr)
                    poly1305_add_blocks(polyCtxPtr, adPtr, UInt64(associatedDataLength))
                    poly1305_add_blocks(polyCtxPtr, ciphertextPtr, UInt64(dataLength))
                    poly1305_add_blocks(polyCtxPtr, lengthsPtr, UInt64(16))
                    poly1305_finish(polyCtxPtr, tagPtr, oneTimeKeyPtr)
                }
            }
        }

        guard (tag == inputTag) else { return nil }
        return plaintext
    }
}

private func writeBytes(to out: inout Array<UInt8>, offset: Int = 0, fromUInt64 longInt: UInt64) {
    assert(offset + 8 <= out.count)
    var longIntLE = longInt.littleEndian
    withUnsafeBytes(of: &longIntLE) { longIntLEBufPtr in
        let longIntLEPtr = longIntLEBufPtr.bindMemory(to: UInt8.self)
        for i in (0..<8) {
            out[offset + i] = longIntLEPtr[i]
        }
    }
}

private func writeBytes(to out: inout Array<UInt8>, offset: Int = 0, fromArray arr: [UInt8]) {
    assert(offset + arr.count <= out.count)
    for i in (0..<arr.count) {
        out[offset + i] = arr[i]
    }
}

private func withUnsafePointerTo<T>(key: Array<UInt8>, closure: (UnsafePointer<UInt8>) -> T) -> T {
    assert(key.count > 0)
    let returnValue: T = key.withUnsafeBufferPointer { keyBufPtr -> T in
        return closure(keyBufPtr.baseAddress!)
    }
    return returnValue
}

private func withUnsafeMutablePointerTo<T>(keystream: inout Array<UInt8>, closure: (UnsafeMutablePointer<UInt8>) -> T) -> T {
    assert(keystream.count > 0)
    let returnValue: T = keystream.withUnsafeMutableBufferPointer { keyBufPtr -> T in
        return closure(keyBufPtr.baseAddress!)
    }
    return returnValue
}

private func withUnsafePointersTo<T>(output: inout Array<UInt8>, tag: inout Array<UInt8>,
                                     oneTimeKey: inout Array<UInt8>,
                                     data: Array<UInt8>, key: Array<UInt8>, iv: Array<UInt8>,
                                     ad: Array<UInt8>, lengths: Array<UInt8>,
                                     closure: (UnsafeMutablePointer<UInt8>, UnsafeMutablePointer<UInt8>, UnsafeMutablePointer<UInt8>, UnsafePointer<UInt8>, UnsafePointer<UInt8>, UnsafePointer<UInt8>, UnsafePointer<UInt8>, UnsafePointer<UInt8>) -> T) -> T {
    assert(output.count > 0)
    assert(tag.count > 0)
    assert(oneTimeKey.count > 0)
    assert(data.count > 0) // FIXME: We should be able to handle data.count == 0
    assert(key.count > 0)
    assert(iv.count > 0)
    assert(ad.count > 0)
    assert(lengths.count > 0)
    let returnValue: T = output.withUnsafeMutableBufferPointer { (outBufPtr) -> T in
        guard let outPtr = outBufPtr.baseAddress else { fatalError() }
        return tag.withUnsafeMutableBufferPointer { (tagBufPtr) -> T in
            guard let tagPtr = tagBufPtr.baseAddress else { fatalError() }
            return oneTimeKey.withUnsafeMutableBufferPointer { (oneTimeKeyBufPtr) -> T in
                guard let oneTimeKeyPtr = oneTimeKeyBufPtr.baseAddress else { fatalError() }
                return data.withUnsafeBufferPointer { (dataBufPtr) -> T in
                    guard let dataPtr = dataBufPtr.baseAddress else { fatalError() }
                    return iv.withUnsafeBufferPointer { ivBufPtr in
                        guard let ivPtr = ivBufPtr.baseAddress else { fatalError() }
                        return key.withUnsafeBufferPointer { keyBufPtr in
                            guard let keyPtr = keyBufPtr.baseAddress else { fatalError() }
                            return ad.withUnsafeBufferPointer { adBufPtr -> T in
                                guard let adPtr = adBufPtr.baseAddress else { fatalError() }
                                return lengths.withUnsafeBufferPointer { lengthsBufPtr -> T in
                                    guard let lengthsPtr = lengthsBufPtr.baseAddress else { fatalError() }
                                    return closure(outPtr, tagPtr, oneTimeKeyPtr, dataPtr, keyPtr, ivPtr, adPtr, lengthsPtr)
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    return returnValue
}
