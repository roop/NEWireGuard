/*
 Copyright (C) 2018 Roopesh Chander S <roop@roopc.net>

 Licensed under the MIT License: https://opensource.org/licenses/MIT
 */

import Foundation

// MARK: Reading and writing to [UInt8]

enum ByteOrder {
    case bigEndian
    case littleEndian
}

extension FixedWidthInteger {
    func writeBytes(toByteArray out: inout Array<UInt8>, byteOrder: ByteOrder, offset: Int = 0) {
        precondition(Self.isSigned == false)
        let numOfBytes = Self.bitWidth / 8
        assert(offset + numOfBytes <= out.count)
        for i in (0 ..< numOfBytes) {
            // Bitshift works the same for any endianness
            if (byteOrder == .bigEndian) {
                // Least-significant byte goes at the end
                out[offset + numOfBytes - i - 1] = UInt8(truncatingIfNeeded: self >> (i * 8))
            } else {
                // Least-significant byte goes at the beginning
                out[offset + i] = UInt8(truncatingIfNeeded: self >> (i * 8))
            }
        }
    }

    init(byteArray: Array<UInt8>, byteOrder: ByteOrder, offset: Int = 0) {
        precondition(Self.isSigned == false)
        let numOfBytes = Self.bitWidth / 8
        assert(offset + numOfBytes <= byteArray.count)
        var le: Self = 0
        for i in (0 ..< numOfBytes) {
            let byte = (byteOrder == .bigEndian) ? byteArray[offset + numOfBytes - i - 1] : byteArray[offset + i]
            le = le | (Self.init(truncatingIfNeeded: byte) << (i * 8))
        }
        self.init(littleEndian: le)
    }
}

// MARK: Reading and writing to Data

extension FixedWidthInteger {
    func writeBytes(toData out: inout Data, byteOrder: ByteOrder, offset: Int = 0) {
        precondition(Self.isSigned == false)
        let numOfBytes = Self.bitWidth / 8
        assert(offset + numOfBytes <= out.count)
        for i in (0 ..< numOfBytes) {
            if (byteOrder == .bigEndian) {
                out[out.startIndex + offset + numOfBytes - i - 1] = UInt8(truncatingIfNeeded: self >> (i * 8))
            } else {
                out[offset + i] = UInt8(truncatingIfNeeded: self >> (i * 8))
            }
        }
    }

    init(data: Data, byteOrder: ByteOrder, offset: Int = 0) {
        precondition(Self.isSigned == false)
        let numOfBytes = Self.bitWidth / 8
        assert(offset + numOfBytes <= data.count)
        var le: Self = 0
        for i in (0 ..< numOfBytes) {
            let byte = (byteOrder == .bigEndian) ? data[data.startIndex + offset + numOfBytes - i - 1] : data[data.startIndex + offset + i]
            le = le | (Self.init(truncatingIfNeeded: byte) << (i * 8))
        }
        self.init(littleEndian: le)
    }
}
