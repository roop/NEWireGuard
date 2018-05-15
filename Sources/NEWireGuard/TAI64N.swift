/*
 Copyright (C) 2018 Roopesh Chander S <roop@roopc.net>

 Licensed under the GPLv3: http://www.gnu.org/licenses/gpl-3.0.html
 */

import Foundation

struct TAI64N {
    /* See: https://cr.yp.to/libtai/tai64.html */
    static let timestampLength: Int = 12
    private static let calendar = Calendar(identifier: .iso8601)
    static func timestamp(for date: Date) -> [UInt8] {
        let secondsSinceTAI0 = UInt64(Int64(date.timeIntervalSince1970) + /* 2^62 */ 0x4000_0000_0000_0000)
        let nanoseconds = UInt32(calendar.component(.nanosecond, from: date))
        var buffer = Array<UInt8>(repeating: 0, count: TAI64N.timestampLength)
        secondsSinceTAI0.writeBytes(to: &buffer)
        nanoseconds.writeBytes(to: &buffer, offset: 8)
        return buffer
    }
}

private extension FixedWidthInteger {
    func writeBytes(to out: inout Array<UInt8>, offset: Int = 0) {
        let numOfBytes = Self.bitWidth / 8
        assert(offset + numOfBytes <= out.count)
        let le = self.littleEndian
        for i in (0 ..< numOfBytes) {
            out[offset + numOfBytes - i - 1] = UInt8(truncatingIfNeeded: le >> (i * 8))
        }
    }
}
