/*
 Copyright (C) 2018 Roopesh Chander S <roop@roopc.net>

 Licensed under the GPLv3: http://www.gnu.org/licenses/gpl-3.0.html
 */

import XCTest
@testable import NEWireGuard
import CommonCryptoDigests

class HKDFTests: XCTestCase {

    // We actually have to test HKDF-Blake2s, but we don't have test vectors for that.
    // So we just test HMAC and HKDF using other hash functions for which test vectors are available.

    func testHMAC() {
        let hmacMd5TestVectors: [(key: InputBytes, message: InputBytes, result: InputBytes)] = [
            // HMAC-MD5 test vectors from the Appendix of RFC 2104
            (key: .repeatingByte(byte: 0x0b, count: 16),
             message: .string("Hi There"),
             result: .hexString("9294727a3638bb1c13f48ef8158bfc9d")),
            (key: .string("Jefe"),
             message: .string("what do ya want for nothing?"),
             result: .hexString("750c783e6ab0b503eaa86e310a5db738")),
            (key: .repeatingByte(byte: 0xAA, count: 16),
             message: .repeatingByte(byte: 0xDD, count: 50),
             result: .hexString("56be34521d144c88dbb8c733f0e8b3f6"))
        ]
        for tv in hmacMd5TestVectors {
            let key = tv.key.toByteArray()
            let msg = tv.message.toByteArray()
            let expected = tv.result.toByteArray()
            let actual = HKDF<MD5HashFunction>.hmac(key: key, message: msg)
            XCTAssertEqual(actual, expected, "HMAC mismatch")
        }
    }

    func testHKDF() {
        let hkdfSha1testVectors: [(IKM: InputBytes, salt: InputBytes, info: InputBytes, OKM: InputBytes)] = [
            // HKDF-SHA1 test vectors from sections A.5, A.6 and A.7 of RFC 5869
            // A.5
            ( IKM: .hexString("""
                000102030405060708090a0b0c0d0e0f
                101112131415161718191a1b1c1d1e1f
                202122232425262728292a2b2c2d2e2f
                303132333435363738393a3b3c3d3e3f
                404142434445464748494a4b4c4d4e4f
                """),
              salt: .hexString("""
                606162636465666768696a6b6c6d6e6f
                707172737475767778797a7b7c7d7e7f
                808182838485868788898a8b8c8d8e8f
                909192939495969798999a9b9c9d9e9f
                a0a1a2a3a4a5a6a7a8a9aaabacadaeaf
                """),
              info: .hexString("""
                b0b1b2b3b4b5b6b7b8b9babbbcbdbebf
                c0c1c2c3c4c5c6c7c8c9cacbcccdcecf
                d0d1d2d3d4d5d6d7d8d9dadbdcdddedf
                e0e1e2e3e4e5e6e7e8e9eaebecedeeef
                f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff
                """),
              OKM: .hexString("""
                0bd770a74d1160f7c9f12cd5912a06eb
                ff6adcae899d92191fe4305673ba2ffe
                8fa3f1a4e5ad79f3f334b3b202b2173c
                486ea37ce3d397ed034c7f9dfeb15c5e
                927336d0441f4c4300e2cff0d0900b52
                d3b4
                """)
                ),
            // A.6
            ( IKM: .repeatingByte(byte: 0x0b, count: 22),
              salt: .emptyInput,
              info: .emptyInput,
              OKM: .hexString("""
                0ac1af7002b3d761d1e55298da9d0506
                b9ae52057220a306e07b6b87e8df21d0
                ea00033de03984d34918
                """)
            ),
            // A.7
            ( IKM: .repeatingByte(byte: 0x0c, count: 22),
              salt: .emptyInput,
              info: .emptyInput,
              OKM: .hexString("""
                2c91117204d745f3500d636a62f64f0a
                b3bae548aa53d423b0d1f27ebba6f5e5
                673a081d70cce7acfc48
                """)
            )
        ]
        for tv in hkdfSha1testVectors {
            let IKM = tv.IKM.toByteArray()
            let salt = tv.salt.toByteArray()
            let info = tv.info.toByteArray()
            let expectedOutput = tv.OKM.toByteArray()
            let expectedOutput1 = Array<UInt8>(expectedOutput[0 ..< SHA1HashFunction.hashLength])
            let expectedOutput2 = Array<UInt8>(expectedOutput[SHA1HashFunction.hashLength ..< (SHA1HashFunction.hashLength*2)])
            let expectedOutput3 = Array<UInt8>(expectedOutput[(SHA1HashFunction.hashLength*2)...])
            for n in (2...3) {
                let (actual1, actual2, actual3) = HKDF<SHA1HashFunction>.hkdf(salt: salt, keyMaterial: IKM, info: info, numOfOutputsRequired: n)
                XCTAssertEqual(actual1.count, SHA1HashFunction.hashLength)
                XCTAssertEqual(actual2.count, SHA1HashFunction.hashLength)
                XCTAssertEqual(actual1, expectedOutput1, "Output 1 mismatch (numOfOutputsRequired == \(n))")
                XCTAssertEqual(actual2, expectedOutput2, "Output 2 mismatch (numOfOutputsRequired == \(n))")
                if (n == 3) {
                    XCTAssertNotNil(actual3)
                    if let actual3 = actual3 {
                        XCTAssertEqual(actual3.count, SHA1HashFunction.hashLength)
                        let minLength = min(actual3.count, expectedOutput3.count)
                        XCTAssertEqual(actual3[0..<minLength], expectedOutput3[0..<minLength], "Output 3 mismatch (numOfOutputsRequired == \(n), length = \(minLength)")
                    }
                } else {
                    XCTAssertNil(actual3)
                }
            }
        }
    }

    static var allTests = [
        ("testHMAC", testHMAC),
        ("testHKDF", testHKDF),
    ]
}

private struct MD5HashFunction : HashFunction {
    static var hashLength: Int = Int(CC_MD5_DIGEST_LENGTH)
    static var blockLength: Int = Int(CC_MD5_BLOCK_BYTES)

    static func hash(of data: [UInt8]) -> [UInt8] {
        return hash(of: data, followedBy: [])
    }

    static func hash(of data: [UInt8], followedBy data2: [UInt8]) -> [UInt8] {
        var digest = Array<UInt8>(repeating: 0, count: hashLength)
        digest.withUnsafeMutableBufferPointer { digestBufPtr in
            data.withUnsafeBytes { dataBufPtr in
                data2.withUnsafeBytes { data2BufPtr in
                    var context = CC_MD5_CTX()
                    withUnsafeMutablePointer(to: &context) { ctxPtr in
                        CC_MD5_Init(ctxPtr)
                        CC_MD5_Update(ctxPtr, dataBufPtr.baseAddress, CC_LONG(data.count))
                        if (data2.count > 0) {
                            CC_MD5_Update(ctxPtr, data2BufPtr.baseAddress, CC_LONG(data2.count))
                        }
                        CC_MD5_Final(digestBufPtr.baseAddress, ctxPtr)
                    }
                }
            }
        }
        return digest
    }
}

private struct SHA1HashFunction : HashFunction {
    static var hashLength: Int = Int(CC_SHA1_DIGEST_LENGTH) // 20
    static var blockLength: Int = Int(CC_SHA1_BLOCK_BYTES)  // 64

    static func hash(of data: [UInt8]) -> [UInt8] {
        return hash(of: data, followedBy: [])
    }

    static func hash(of data: [UInt8], followedBy data2: [UInt8]) -> [UInt8] {
        var digest = Array<UInt8>(repeating: 0, count: hashLength)
        digest.withUnsafeMutableBufferPointer { digestBufPtr in
            data.withUnsafeBytes { dataBufPtr in
                data2.withUnsafeBytes { data2BufPtr in
                    var context = CC_SHA1_CTX()
                    withUnsafeMutablePointer(to: &context) { ctxPtr in
                        CC_SHA1_Init(ctxPtr)
                        CC_SHA1_Update(ctxPtr, dataBufPtr.baseAddress, CC_LONG(data.count))
                        if (data2.count > 0) {
                            CC_SHA1_Update(ctxPtr, data2BufPtr.baseAddress, CC_LONG(data2.count))
                        }
                        CC_SHA1_Final(digestBufPtr.baseAddress, ctxPtr)
                    }
                }
            }
        }
        return digest
    }
}

fileprivate enum InputBytes {
    case emptyInput
    case repeatingByte(byte: UInt8, count: Int)
    case hexString(String)
    case string(String)
    func toByteArray() -> [UInt8] {
        switch (self) {
        case .emptyInput:
            return []
        case .repeatingByte(let byte, let count):
            return Array<UInt8>(repeating: byte, count: count)
        case .hexString(let str):
            var byteArray = Array<UInt8>()
            var stringIndex = str.startIndex
            while (stringIndex < str.endIndex) {
                let nextIndex = str.index(after: str.index(after: stringIndex))
                if let byte = UInt8(str[stringIndex ..< nextIndex], radix: 16) {
                    byteArray.append(byte)
                    stringIndex = nextIndex
                } else {
                    // In case we encounter a newline character, we silently ignore it.
                    if (str[stringIndex] == "\n") {
                        stringIndex = str.index(after: stringIndex)
                    } else {
                        fatalError("Unexpected character in InputBytes.hexString string")
                    }
                }
            }
            return byteArray
        case .string(let str):
            let data = str.data(using: .ascii)!
            var ba = Array<UInt8>(repeating: 0, count: data.count)
            ba.withUnsafeMutableBufferPointer { bufPtr in
                let count = data.copyBytes(to: bufPtr)
                assert(count == data.count)
            }
            return ba
        }
    }
}
