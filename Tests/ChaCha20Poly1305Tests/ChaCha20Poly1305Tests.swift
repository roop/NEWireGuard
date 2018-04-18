/*
 Copyright (C) 2018 Roopesh Chander S <roop@roopc.net>

 Licensed under the GPLv3: http://www.gnu.org/licenses/gpl-3.0.html
 */

import XCTest
@testable import NEWireGuard

class ChaCha20Poly1305Tests: XCTestCase {

    func testChaCha20Poly1305AEAD() {
        // Test AEAD using the test vector from RFC 7539 Section 2.8.2

        // Define inputs
        let plaintextString = "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it."
        let plaintextData = plaintextString.data(using: .ascii)!
        var plaintext = Array<UInt8>(repeating: 0, count: plaintextData.count)
        plaintext.withUnsafeMutableBufferPointer { plaintextBufPtr in
            let count = plaintextData.copyBytes(to: plaintextBufPtr)
            assert(count == plaintextData.count)
        }
        let associatedData: [UInt8] = [ 0x50, 0x51, 0x52, 0x53, 0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7 ]
        var key = Array<UInt8>(repeating: 0, count: 32)
        for i in (0..<32) {
            key[i] = UInt8(i) + 0x80
        }
        let nonce: UInt64 = 0x4746454443424140
        // In little-endian representation, this nonce looks like: 40 41 42 43 44 45 46 47
        let ivPrefix: [UInt8] =  [ 0x07, 0x00, 0x00, 0x00 ] // "32-bit fixed common part"

        // Define expected outputs
        let expectedCiphertext: [UInt8] = [
        /* 000 */ 0xd3, 0x1a, 0x8d, 0x34, 0x64, 0x8e, 0x60, 0xdb, 0x7b, 0x86, 0xaf, 0xbc, 0x53, 0xef, 0x7e, 0xc2,
        /* 016 */ 0xa4, 0xad, 0xed, 0x51, 0x29, 0x6e, 0x08, 0xfe, 0xa9, 0xe2, 0xb5, 0xa7, 0x36, 0xee, 0x62, 0xd6,
        /* 032 */ 0x3d, 0xbe, 0xa4, 0x5e, 0x8c, 0xa9, 0x67, 0x12, 0x82, 0xfa, 0xfb, 0x69, 0xda, 0x92, 0x72, 0x8b,
        /* 048 */ 0x1a, 0x71, 0xde, 0x0a, 0x9e, 0x06, 0x0b, 0x29, 0x05, 0xd6, 0xa5, 0xb6, 0x7e, 0xcd, 0x3b, 0x36,
        /* 064 */ 0x92, 0xdd, 0xbd, 0x7f, 0x2d, 0x77, 0x8b, 0x8c, 0x98, 0x03, 0xae, 0xe3, 0x28, 0x09, 0x1b, 0x58,
        /* 080 */ 0xfa, 0xb3, 0x24, 0xe4, 0xfa, 0xd6, 0x75, 0x94, 0x55, 0x85, 0x80, 0x8b, 0x48, 0x31, 0xd7, 0xbc,
        /* 096 */ 0x3f, 0xf4, 0xde, 0xf0, 0x8e, 0x4b, 0x7a, 0x9d, 0xe5, 0x76, 0xd2, 0x65, 0x86, 0xce, 0xc6, 0x4b,
        /* 112 */ 0x61, 0x16
        ]
        let expectedTag: [UInt8] = [
            0x1a, 0xe1, 0x0b, 0x59, 0x4f, 0x09, 0xe2, 0x6a, 0x7e, 0x90, 0x2e, 0xcb, 0xd0, 0x60, 0x06, 0x91
        ]

        // Test encryption
        let aead = ChaCha20Poly1305()
        aead.setKey(key: key)
        aead.ivFixedPrefix = ivPrefix
        let (ciphertext, tag) = aead.encrypt(plaintext: plaintext, nonce: nonce, associatedData: associatedData)
        XCTAssertEqual(ciphertext, expectedCiphertext, "Ciphertext mismatch")
        XCTAssertEqual(tag, expectedTag, "Tag mismatch")

        // Test decryption
        let decrypted = aead.decrypt(ciphertext: ciphertext, nonce: nonce, associatedData: associatedData, tag: tag)
        XCTAssertNotNil(decrypted)
        XCTAssertEqual(plaintext, decrypted, "Decryption mismatch")
    }

    static var allTests = [
        ("testChaCha20Poly1305AEAD", testChaCha20Poly1305AEAD),
    ]
}
