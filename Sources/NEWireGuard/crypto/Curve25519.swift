/*
 Copyright (C) 2018 Roopesh Chander S <roop@roopc.net>

 Licensed under the GPLv3: http://www.gnu.org/licenses/gpl-3.0.html
 */

import Security
import Curve25519

struct Curve25519ECDH {

    static func generateKeyPair(privateKey pk: [UInt8]? = nil) throws -> (privateKey: [UInt8], publicKey: [UInt8]) {

        var privateKey: [UInt8]
        if let pk = pk {
            // Used only for testing
            privateKey = pk
        } else {
            // Generate 32 random bytes
            var randomBytes = Array<UInt8>(repeating: 0, count: 32)
            let result = randomBytes.withUnsafeMutableBytes { randomBytesBufPtr -> Int32 in
                guard let randomBytesRawPtr = randomBytesBufPtr.baseAddress else { fatalError() }
                return SecRandomCopyBytes(kSecRandomDefault, 32, randomBytesRawPtr)
            }
            guard (result == errSecSuccess) else { throw Curve25519Error.unableToGeneratePrivateKey(OSErrorCode: result) }
            privateKey = randomBytes
        }

        // Make the private key compatible with X25519
        privateKey[0] &= 248;
        privateKey[31] &= 127;
        privateKey[31] |= 64;

        // Generate public key
        var publicKey = Array<UInt8>(repeating: 0, count: Curve25519.CURVE25519_PUBLIC_KEY_SIZE)
        publicKey.withUnsafeMutableBufferPointer { publicKeyBufPtr in
            guard let publicKeyPtr = publicKeyBufPtr.baseAddress else { fatalError() }
            privateKey.withUnsafeBufferPointer { privateKeyBufPtr in
                guard let privateKeyPtr = privateKeyBufPtr.baseAddress else { fatalError() }
                Curve25519.crypto_scalarmult_base(publicKeyPtr, privateKeyPtr)
            }
        }

        return (privateKey: privateKey, publicKey: publicKey)
    }

    static func computeSharedSecret(privateKey: [UInt8], otherPublicKey publicKey: [UInt8]) -> [UInt8] {
        var sharedKey = Array<UInt8>(repeating: 0, count: Curve25519.CURVE25519_SHARED_KEY_SIZE)
        sharedKey.withUnsafeMutableBufferPointer { sharedKeyBufPtr in
            guard let sharedKeyPtr = sharedKeyBufPtr.baseAddress else { fatalError() }
            privateKey.withUnsafeBufferPointer { privateKeyBufPtr in
                guard let privateKeyPtr = privateKeyBufPtr.baseAddress else { fatalError() }
                publicKey.withUnsafeBufferPointer { publicKeyBufPtr in
                    guard let publicKeyPtr = publicKeyBufPtr.baseAddress else { fatalError() }
                    Curve25519.crypto_scalarmult(sharedKeyPtr, privateKeyPtr, publicKeyPtr)
                }
            }
        }
        return sharedKey
    }

    enum Curve25519Error: Error {
        case unableToGeneratePrivateKey(OSErrorCode: OSStatus)
    }
}
