/*
 Copyright (C) 2018 Roopesh Chander S <roop@roopc.net>

 Licensed under the GPLv3: http://www.gnu.org/licenses/gpl-3.0.html
 */

import XCTest
@testable import NEWireGuard

class Curve25519Tests: XCTestCase {
    func testECDH() {
        // Test Curve25519 ECDH using the test vector from RFC 7748 Section 6.1

        // Inputs
        let alicePrivateKey = byteArrayFromHexString("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
        let bobPrivateKey   = byteArrayFromHexString("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb")

        // Expected outputs
        let expectedAlicePublicKey = byteArrayFromHexString("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")
        let expectedBobPublicKey   = byteArrayFromHexString("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f")
        let expectedSharedSecret   = byteArrayFromHexString("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742")

        // Check public key computation
        let aliceKeyPair = try! Curve25519ECDH.generateKeyPair(privateKey: alicePrivateKey)
        let bobKeyPair = try! Curve25519ECDH.generateKeyPair(privateKey: bobPrivateKey)
        XCTAssertEqual(aliceKeyPair.publicKey, expectedAlicePublicKey)
        XCTAssertEqual(bobKeyPair.publicKey, expectedBobPublicKey)

        // Check shared secret computation
        let aliceSharedSecret = Curve25519ECDH.computeSharedSecret(privateKey: alicePrivateKey, otherPublicKey: bobKeyPair.publicKey)
        let bobSharedSecret   = Curve25519ECDH.computeSharedSecret(privateKey: bobPrivateKey, otherPublicKey: aliceKeyPair.publicKey)
        XCTAssertEqual(aliceSharedSecret, expectedSharedSecret)
        XCTAssertEqual(bobSharedSecret, expectedSharedSecret)
    }

    static var allTests = [
        ("testECDH", testECDH),
    ]
}

private func byteArrayFromHexString(_ str: String) -> [UInt8] {
    precondition(str.count % 2 == 0)
    var byteArray = Array<UInt8>(repeating: 0, count: str.count / 2)
    var i = 0
    var stringIndex = str.startIndex
    while (stringIndex < str.endIndex) {
        let nextIndex = str.index(after: str.index(after: stringIndex))
        byteArray[i] = UInt8(str[stringIndex ..< nextIndex], radix: 16)!
        stringIndex = nextIndex
        i = i + 1
    }
    return byteArray
}
