/*
 Copyright (C) 2018 Roopesh Chander S <roop@roopc.net>

 Licensed under the GPLv3: http://www.gnu.org/licenses/gpl-3.0.html
 */

import Blake2s

struct Blake2s {

    static let hashLength = 32
    static let blockLength = 64

    static func hash(_ data: Array<UInt8>, followedBy moreData: Array<UInt8>? = nil) -> Array<UInt8> {
        var out = Array<UInt8>(repeating: 0, count: Blake2s.hashLength)
        withUnsafeRawPointersTo(output: &out, data: data, moreData: moreData) { (outPtr, dataPtr, moreDataPtr) in
            var blakeState = blake2s_state__()
            withUnsafeMutablePointer(to: &blakeState) { blakeStatePtr in
                blake2s_init(blakeStatePtr, Blake2s.hashLength)
                if data.count > 0, let dataPtr = dataPtr {
                    blake2s_update(blakeStatePtr, dataPtr, data.count)
                }
                if moreData != nil, moreData!.count > 0, let moreDataPtr = moreDataPtr {
                    blake2s_update(blakeStatePtr, moreDataPtr, moreData!.count)
                }
                blake2s_final(blakeStatePtr, outPtr, Blake2s.hashLength)
            }
        }
        return out
    }
}

private func withUnsafeRawPointersTo<T>(output: inout Array<UInt8>, data: Array<UInt8>, moreData: Array<UInt8>?,
                                        closure: (UnsafeMutableRawPointer, UnsafeRawPointer?, UnsafeRawPointer?) -> T) -> T {
    assert(output.count > 0)
    let returnValue: T = output.withUnsafeMutableBytes { (outBufPtr) -> T in
        guard let outPtr = outBufPtr.baseAddress else { fatalError() }
        return data.withUnsafeBytes { (dataBufPtr) -> T in
            assert(dataBufPtr.baseAddress != nil || data.count == 0)
            if let moreData = moreData {
                return moreData.withUnsafeBytes { (moreDataBufPtr) -> T in
                    assert(moreDataBufPtr.baseAddress != nil || moreData.count == 0)
                    return closure(outPtr, dataBufPtr.baseAddress, moreDataBufPtr.baseAddress)
                }
            } else {
                return closure(outBufPtr.baseAddress!, dataBufPtr.baseAddress, nil)
            }
        }
    }
    return returnValue
}
