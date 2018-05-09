/*
 Copyright (C) 2018 Roopesh Chander S <roop@roopc.net>

 Licensed under the GPLv3: http://www.gnu.org/licenses/gpl-3.0.html
 */

import Blake2s

struct Blake2s {

    static let hashLength = 32
    static let blockLength = 64

    static func hash(of data: [UInt8], followedBy data2: [UInt8], _ data3: [UInt8]? = nil) -> [UInt8] {
        var out = Array<UInt8>(repeating: 0, count: Blake2s.hashLength)
        withUnsafeRawPointersTo(output: &out, data: data, data2: data2, data3: data3) { (outPtr, dataPtr, data2Ptr, data3Ptr) in
            var blakeState = blake2s_state__()
            withUnsafeMutablePointer(to: &blakeState) { blakeStatePtr in
                blake2s_init(blakeStatePtr, Blake2s.hashLength)
                if data.count > 0, let dataPtr = dataPtr {
                    blake2s_update(blakeStatePtr, dataPtr, data.count)
                }
                if data2.count > 0, let data2Ptr = data2Ptr {
                    blake2s_update(blakeStatePtr, data2Ptr, data2.count)
                }
                if let data3 = data3, data3.count > 0, let data3Ptr = data3Ptr {
                    blake2s_update(blakeStatePtr, data3Ptr, data3.count)
                }
                blake2s_final(blakeStatePtr, outPtr, Blake2s.hashLength)
            }
        }
        return out
    }
}

private func withUnsafeRawPointersTo<T>(output: inout Array<UInt8>, data: Array<UInt8>, data2: Array<UInt8>, data3: Array<UInt8>?,
                                        closure: (UnsafeMutableRawPointer, UnsafeRawPointer?, UnsafeRawPointer?, UnsafeRawPointer?) -> T) -> T {
    assert(output.count > 0)
    let returnValue: T = output.withUnsafeMutableBytes { (outBufPtr) -> T in
        guard let outPtr = outBufPtr.baseAddress else { fatalError() }
        return data.withUnsafeBytes { (dataBufPtr) -> T in
            assert(dataBufPtr.baseAddress != nil || data.count == 0)
            return data2.withUnsafeBytes { (data2BufPtr) -> T in
                assert(data2BufPtr.baseAddress != nil || data2.count == 0)
                if let data3 = data3 {
                    return data3.withUnsafeBytes { (data3BufPtr) -> T in
                        assert(data3BufPtr.baseAddress != nil || data.count == 0)
                        return closure(outPtr, dataBufPtr.baseAddress, data2BufPtr.baseAddress, data3BufPtr.baseAddress)
                    }
                } else {
                    return closure(outPtr, dataBufPtr.baseAddress, data2BufPtr.baseAddress, nil)
                }
            }
        }
    }
    return returnValue
}
