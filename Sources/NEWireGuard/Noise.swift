/*
    Copyright (C) 2018 Roopesh Chander S <roop@roopc.net>

    Licensed under the GPLv3: http://www.gnu.org/licenses/gpl-3.0.html
*/

import Foundation

struct Noise {

static let noiseProtocolName = "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s"
static let noisePrologue = "WireGuard v1 zx2c4 Jason@zx2c4.com"

enum NoiseError: Error {
    case DecryptionAuthenticationFailure
}

struct PrivateKey { let key: [UInt8] }
struct PublicKey { let key: [UInt8] }

private struct ECDH {
    let keyLength = Curve25519ECDH.keyLength // 32
    static func generateKeyPair() throws -> (PrivateKey, PublicKey) {
        let (privateKey, publicKey) = try Curve25519ECDH.generateKeyPair()
        return (PrivateKey(key: privateKey), PublicKey(key: publicKey))
    }
    static func computeSharedSecret(privateKey: PrivateKey, otherPublicKey: PublicKey) -> [UInt8] {
        return Curve25519ECDH.computeSharedSecret(privateKey: privateKey.key, otherPublicKey: otherPublicKey.key)
    }
}

private class Cipher {
    let aeadCipher: ChaCha20Poly1305
    init(key: [UInt8]) {
        aeadCipher = ChaCha20Poly1305()
        aeadCipher.setKey(key: key)
    }

    func encrypt(plaintext: [UInt8], nonce: UInt64, associatedData ad: [UInt8]) -> (ciphertext: [UInt8], tag: [UInt8]) {
        return aeadCipher.encrypt(plaintext: plaintext, nonce: nonce, associatedData: ad)
    }

    func decrypt(ciphertext: [UInt8], tag: [UInt8], nonce: UInt64, associatedData ad: [UInt8]) throws -> [UInt8] {
        let plaintext = aeadCipher.decrypt(ciphertext: ciphertext, nonce: nonce, associatedData: ad, tag: tag)
        if let plaintext = plaintext {
            return plaintext
        } else {
            throw NoiseError.DecryptionAuthenticationFailure
        }
    }

    func rekey() {
        // TODO:
    }
}

private struct Hash {
    let hashLength = Blake2s.hashLength // 32
    let blockLength = Blake2s.blockLength // 64

    static func hash(of data: [UInt8]) -> [UInt8] {
        return Blake2s.hash(of: data)
    }

    static func hash(of data: [UInt8], followedBy data2: [UInt8]) -> [UInt8] {
        return Blake2s.hash(of: data, followedBy: data2)
    }

    static func hash(of data: [UInt8], followedBy data2: [UInt8], _ data3: [UInt8]) -> [UInt8] {
        return Blake2s.hash(of: data, followedBy: data2, data3)
    }

    static func hkdfGivingTwoKeyMaterials(chainingKey: [UInt8], inputKeyMaterial: [UInt8]) -> ([UInt8], [UInt8]) {
        let (out1, out2, _) = HKDF<Blake2s>.hkdf(salt: chainingKey, keyMaterial: inputKeyMaterial, info: [], numOfOutputsRequired: 2)
        return (out1, out2)
    }
}

class CipherState {
    private var cipher: Cipher
    private var nonce: UInt64

    init(key: [UInt8]) {
        self.cipher = Cipher(key: key)
        self.nonce = 0
    }

    func encrypt(plaintext: [UInt8], withAdditionalData ad: [UInt8]) -> (ciphertext: [UInt8], tag: [UInt8]) {
        let encrypted = cipher.encrypt(plaintext: plaintext, nonce: nonce, associatedData: ad)
        nonce = nonce + 1
        return encrypted
    }

    func decrypt(ciphertext: [UInt8], tag: [UInt8], withAdditionalData ad: [UInt8]) throws -> [UInt8] {
        let decrypted = try cipher.decrypt(ciphertext: ciphertext, tag: tag, nonce: nonce, associatedData: ad)
        nonce = nonce + 1
        return decrypted
    }

    func rekey() {
        // TODO:
    }
}

class SymmetricState {
    var cipherState: CipherState?
    var chainingKey: [UInt8] // 32-byte data
    var hash: [UInt8] // 32-byte data

    init() {
        hash = Hash.hash(of: bytesFromString(Noise.noiseProtocolName))
        chainingKey = hash
        cipherState = nil
    }

    func mixKey(_ inputKeyMaterial: [UInt8]) {
        let (okm1, okm2) = Hash.hkdfGivingTwoKeyMaterials(chainingKey: chainingKey, inputKeyMaterial: inputKeyMaterial)
        chainingKey = okm1
        cipherState = CipherState(key: okm2)
    }

    func mixHash(_ data: [UInt8]) {
        hash = Hash.hash(of: hash, followedBy: data)
    }

    func mixHash(_ data1: [UInt8], _ data2: [UInt8]) {
        hash = Hash.hash(of: hash, followedBy: data1, data2)
    }

    func encryptAndHash(plaintext: [UInt8]) -> (ciphertext: [UInt8], tag: [UInt8]) {
        guard let cipherState = cipherState else { fatalError("Can't encryptAndHash() before using mixKey()") }
        let (ciphertext, tag) = cipherState.encrypt(plaintext: plaintext, withAdditionalData: hash)
        mixHash(ciphertext, tag)
        return (ciphertext: ciphertext, tag: tag)
    }

    func decryptAndHash(ciphertext: [UInt8], tag: [UInt8]) throws -> [UInt8] {
        guard let cipherState = cipherState else { fatalError("Can't decryptAndHash() before using mixKey()") }
        let plaintext = try cipherState.decrypt(ciphertext: ciphertext, tag: tag, withAdditionalData: hash)
        mixHash(ciphertext, tag)
        return plaintext
    }

    func split() -> (CipherState, CipherState) {
        let (okm1, okm2) = Hash.hkdfGivingTwoKeyMaterials(chainingKey: chainingKey, inputKeyMaterial: [])
        return (CipherState(key: okm1), CipherState(key: okm2))
    }
}

class HandshakeState {
    var symmetricState: SymmetricState

    var localStaticPublicKey: PublicKey
    var localStaticPrivateKey: PrivateKey
    var localEphemeralPublicKey: PublicKey?
    var localEphemeralPrivateKey: PrivateKey?
    var remoteStaticPublicKey: PublicKey
    var remoteEphemeralPublicKey: PublicKey?

    /*
     IK(s, rs):
     <- s
     ...
     -> e, es, s, ss
     <- e, ee, se
     */

    init(localStaticPublicKey: PublicKey, localStaticPrivateKey: PrivateKey, remoteStaticPublicKey: PublicKey) {
        self.localStaticPublicKey = localStaticPublicKey
        self.localStaticPrivateKey = localStaticPrivateKey
        self.remoteStaticPublicKey = remoteStaticPublicKey

        symmetricState = SymmetricState()
        symmetricState.mixHash(bytesFromString(Noise.noisePrologue))
        symmetricState.mixHash(remoteStaticPublicKey.key)
    }
}


}

private func bytesFromString(_ str: String) -> [UInt8] {
    let data = str.data(using: .ascii)!
    var ba = Array<UInt8>(repeating: 0, count: data.count)
    ba.withUnsafeMutableBufferPointer { bufPtr in
        let count = data.copyBytes(to: bufPtr)
        assert(count == data.count)
    }
    return ba
}
