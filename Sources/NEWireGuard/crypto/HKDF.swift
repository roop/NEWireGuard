/*
 Copyright (C) 2018 Roopesh Chander S <roop@roopc.net>

 Licensed under the GPLv3: http://www.gnu.org/licenses/gpl-3.0.html
 */

protocol HashFunction {
    static var hashLength: Int { get }
    static var blockLength: Int { get }
    static func hash(of: [UInt8]) -> [UInt8] // Returns hash of data
    static func hash(of: [UInt8], followedBy: [UInt8]) -> [UInt8] // Returns hash of data1.appendedWith(data2)
}

struct HKDF<H> where H : HashFunction {
    static func hmac(key: [UInt8], message: [UInt8]) -> [UInt8] {
        // Implementation of HMAC from RFC 2104
        // Populate k with key + zeroes to make a blockLength-long array
        var k: [UInt8] = Array<UInt8>(repeating: 0, count: H.blockLength)
        let keyBytes = (key.count > H.blockLength ? H.hash(of: key) : key)
        for i in (0 ..< keyBytes.count) {
            k[i] = keyBytes[i]
        }
        // XOR with ipad and opad
        var ipadded: [UInt8] = Array<UInt8>(repeating: 0, count: H.blockLength)
        var opadded: [UInt8] = Array<UInt8>(repeating: 0, count: H.blockLength)
        for i in (0 ..< H.blockLength) {
            ipadded[i] = k[i] ^ 0x36
            opadded[i] = k[i] ^ 0x5c
        }
        // Compute HMAC
        return H.hash(of: opadded, followedBy: H.hash(of: ipadded, followedBy: message))
    }

    static func hkdf(salt: [UInt8], keyMaterial: [UInt8], info: [UInt8], numOfOutputsRequired: Int /* 2 or 3 */) -> ([UInt8], [UInt8], [UInt8]?) {
        // Implementation of HKDF from RFC 5869
        // If numOfOutputsRequired == 2, returns (out1, out2, nil).
        // If numOfOutputsRequired == 3, returns (out1, out2, out3).
        // Each of out1, out2, out3 is H.hashLength bytes long.
        // In how HKDF is used in the Noise protocol, info is always empty, but we need it here for testing HKDF.
        let prk = hmac(key: salt, message: keyMaterial)
        var t0 = Array<UInt8>(repeating: 0, count: info.count + 1)
        for i in (0 ..< info.count) {
            t0[i] = info[i]
        }
        t0[info.count] = 0x01
        let output1 = hmac(key: prk, message: t0)
        assert(output1.count == H.hashLength)
        var tn = Array<UInt8>(repeating: 0, count: H.hashLength + info.count + 1)
        for i in (0 ..< H.hashLength) {
            tn[i] = output1[i]
        }
        for i in (0 ..< info.count) {
            tn[H.hashLength + i] = info[i]
        }
        tn[H.hashLength + info.count] = 0x02
        let output2 = hmac(key: prk, message: tn)
        if (numOfOutputsRequired == 2) {
            return (output1, output2, nil)
        }
        for i in (0 ..< H.hashLength) {
            tn[i] = output2[i]
        }
        tn[H.hashLength + info.count] = 0x03
        let output3 = hmac(key: prk, message: tn)
        assert(numOfOutputsRequired == 3)
        return (output1, output2, output3)
    }
}
