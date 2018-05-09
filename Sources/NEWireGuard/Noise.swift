/*
    Copyright (C) 2018 Roopesh Chander S <roop@roopc.net>

    Licensed under the GPLv3: http://www.gnu.org/licenses/gpl-3.0.html
*/

import Foundation

struct Noise {

static let noiseProtocolName = "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s"

private struct ECDH {
    let keyLength = Curve25519ECDH.keyLength // 32
    static func generateKeyPair() throws -> (privateKey: [UInt8], publicKey: [UInt8]) {
        return try Curve25519ECDH.generateKeyPair()
    }
    static func computeSharedSecret(privateKey: [UInt8], otherPublicKey: [UInt8]) -> [UInt8] {
        return Curve25519ECDH.computeSharedSecret(privateKey: privateKey, otherPublicKey: otherPublicKey)
    }
}

struct Cipher {
    static func encrypt(plaintext: Data, key: Data, nonce: UInt64, associatedData: Data) -> Data {
        // Encrypt using ChaCha20-Poly1305-AEAD
        return Data()
    }

    static func decrypt(ciphertext: Data, key: Data, nonce: UInt64, associatedData: Data) -> Data? {
        // Decrypt using ChaCha20-Poly1305-AEAD
        return Data()
    }

    static func rekey(key: Data) -> Data {
        return Data()
    }
}

struct Hash {
    let hashLength = 32
    let blockLength = 64
    static func hash(_ data: Data) -> Data {
        return Data()
    }
    static func hkdf2(_ data1: Data, _ data2: Data) -> (Data, Data) {
        return (Data(), Data())
    }
}

class CipherState {
    var key: Data? // 32-byte data
    var nonce: UInt64

    init(key: Data?) {
        self.key = key
        self.nonce = 0
    }

    var hasKey: Bool { return (key != nil) }

    func encrypt(plaintext: Data, withAdditionalData ad: Data) -> Data {
        guard let key = key else { return plaintext }
        let encrypted = Cipher.encrypt(plaintext: plaintext, key: key, nonce: nonce, associatedData: ad)
        nonce = nonce + 1
        return encrypted
    }

    func decrypt(ciphertext: Data, withAdditionalData ad: Data) -> Data? {
        guard let key = key else { return ciphertext }
        let decrypted = Cipher.decrypt(ciphertext: ciphertext, key: key, nonce: nonce, associatedData: ad)
        nonce = nonce + 1
        return decrypted
    }

    func rekey(key: Data) {
        self.key = Cipher.rekey(key: key)
    }
}

class SymmetricState {
    var cipherState: CipherState
    var chainingKey: Data // 32-byte data
    var hash: Data // 32-byte data

    init(noiseProtocolName: Data) {
        hash = noiseProtocolName
        chainingKey = hash
        cipherState = CipherState(key: nil)
    }

    func mixKey(_ inputKeyMaterial: Data) {
        let keys = Hash.hkdf2(chainingKey, inputKeyMaterial)
        chainingKey = keys.0
        cipherState = CipherState(key: keys.1)
    }

    func mixHash(_ data: Data) {
        hash = Hash.hash(hash + data)
    }

    func encryptAndHash(plaintext: Data) -> Data {
        let ciphertext = cipherState.encrypt(plaintext: plaintext, withAdditionalData: hash)
        mixHash(ciphertext)
        return ciphertext
    }

    func decryptAndHash(ciphertext: Data) -> Data? {
        let plaintext = cipherState.decrypt(ciphertext: ciphertext, withAdditionalData: hash)
        mixHash(ciphertext)
        return plaintext
    }

    func split() -> (CipherState, CipherState) {
        let keys = Hash.hkdf2(chainingKey, Data())
        return (CipherState(key: keys.0), CipherState(key: keys.1))
    }
}

}
