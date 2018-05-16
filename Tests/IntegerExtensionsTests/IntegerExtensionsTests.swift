import XCTest
@testable import NEWireGuard

class NEWireGuardTests: XCTestCase {

    func testFixedWithIntegerBytes() {
        // Tests for the following extensions to FixedWidthInteger:
        //     extension FixedWidthInteger {
        //         // For byte array
        //         func writeBytes(toByteArray out: inout Array<UInt8>, offset: Int = 0)
        //         init?(byteArray: Array<UInt8>, offset: Int = 0)
        //         // For Data:
        //         func writeBytes(toData out: inout Data, offset: Int = 0)
        //         init?(data: Data, offset: Int = 0)
        //     }

        let u32TestVectors: [(number: UInt32, bytesBigEndian: [UInt8])] = [
            (number: 0x0001_0203, bytesBigEndian: [0x00, 0x01, 0x02, 0x03]),
            (number: 0xf0f1_f2f3, bytesBigEndian: [0xf0, 0xf1, 0xf2, 0xf3])
        ]

        func testWriteBytesU32(number: UInt32, byteOrder: ByteOrder, expectedBytes: [UInt8]) {
            // Byte Array, no offset
            var ba = Array<UInt8>(repeating: 0, count: 4)
            number.writeBytes(toByteArray: &ba, byteOrder: byteOrder)
            XCTAssertEqual(ba, expectedBytes)
            // Byte Array, with offset
            var ba2 = Array<UInt8>(repeating: 0, count: 14)
            number.writeBytes(toByteArray: &ba2, byteOrder: byteOrder, offset: 10)
            XCTAssertEqual(Array<UInt8>(ba2[10..<14]), expectedBytes)
            // Data, no offset
            var data = Data(repeating: 0, count: 4)
            number.writeBytes(toData: &data, byteOrder: byteOrder)
            XCTAssertEqual(data, Data(bytes: expectedBytes))
            // Data, with offset
            var data2 = Data(repeating: 0, count: 14)
            number.writeBytes(toData: &data2, byteOrder: byteOrder, offset: 10)
            XCTAssertEqual(data2[10..<14], Data(bytes: expectedBytes))
        }

        func testReadBytesU32(bytes: [UInt8], byteOrder: ByteOrder, expectedNumber: UInt32) {
            // Byte Array, no offset
            XCTAssertEqual(UInt32(byteArray: bytes, byteOrder: byteOrder), expectedNumber)
            // Byte Array, with offset
            var offsettedBa = bytes
            offsettedBa.insert(contentsOf: Array<UInt8>(repeating: 0, count: 10), at: 0)
            XCTAssertEqual(UInt32(byteArray: offsettedBa, byteOrder: byteOrder, offset: 10), expectedNumber)
            // Data, no offset
            XCTAssertEqual(UInt32(data: Data(bytes: bytes), byteOrder: byteOrder), expectedNumber)
            // Data, with offset
            var offsettedData = Data(bytes: bytes)
            offsettedData.insert(contentsOf: Array<UInt8>(repeating: 0, count: 10), at: 0)
            XCTAssertEqual(UInt32(data: offsettedData, byteOrder: byteOrder, offset: 10), expectedNumber)
        }

        for tv in u32TestVectors {
            testWriteBytesU32(number: tv.number, byteOrder: .bigEndian, expectedBytes: tv.bytesBigEndian)
            testWriteBytesU32(number: tv.number, byteOrder: .littleEndian, expectedBytes: tv.bytesBigEndian.reversed())
            testReadBytesU32(bytes: tv.bytesBigEndian, byteOrder: .bigEndian, expectedNumber: tv.number)
            testReadBytesU32(bytes: tv.bytesBigEndian.reversed(), byteOrder: .littleEndian, expectedNumber: tv.number)
        }

        let u64TestVectors: [(number: UInt64, bytesBigEndian: [UInt8])] = [
            (number: 0x0001_0203_0405_0607, bytesBigEndian: [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07]),
            (number: 0xf0f1_f2f3_f4f5_f6f7, bytesBigEndian: [0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7])
        ]

        func testWriteBytesU64(number: UInt64, byteOrder: ByteOrder, expectedBytes: [UInt8]) {
            // Byte Array, no offset
            var ba = Array<UInt8>(repeating: 0, count: 8)
            number.writeBytes(toByteArray: &ba, byteOrder: byteOrder)
            XCTAssertEqual(ba, expectedBytes)
            // Byte Array, with offset
            var ba2 = Array<UInt8>(repeating: 0, count: 18)
            number.writeBytes(toByteArray: &ba2, byteOrder: byteOrder, offset: 10)
            XCTAssertEqual(Array<UInt8>(ba2[10..<18]), expectedBytes)
            // Data, no offset
            var data = Data(repeating: 0, count: 8)
            number.writeBytes(toData: &data, byteOrder: byteOrder)
            XCTAssertEqual(data, Data(bytes: expectedBytes))
            // Data, with offset
            var data2 = Data(repeating: 0, count: 18)
            number.writeBytes(toData: &data2, byteOrder: byteOrder, offset: 10)
            XCTAssertEqual(data2[10..<18], Data(bytes: expectedBytes))
        }

        func testReadBytesU64(bytes: [UInt8], byteOrder: ByteOrder, expectedNumber: UInt64) {
            // Byte Array, no offset
            XCTAssertEqual(UInt64(byteArray: bytes, byteOrder: byteOrder), expectedNumber)
            // Byte Array, with offset
            var offsettedBa = bytes
            offsettedBa.insert(contentsOf: Array<UInt8>(repeating: 0, count: 10), at: 0)
            XCTAssertEqual(UInt64(byteArray: offsettedBa, byteOrder: byteOrder, offset: 10), expectedNumber)
            // Data, no offset
            XCTAssertEqual(UInt64(data: Data(bytes: bytes), byteOrder: byteOrder), expectedNumber)
            // Data, with offset
            var offsettedData = Data(bytes: bytes)
            offsettedData.insert(contentsOf: Array<UInt8>(repeating: 0, count: 10), at: 0)
            XCTAssertEqual(UInt64(data: offsettedData, byteOrder: byteOrder, offset: 10), expectedNumber)
        }

        for tv in u64TestVectors {
            testWriteBytesU64(number: tv.number, byteOrder: .bigEndian, expectedBytes: tv.bytesBigEndian)
            testWriteBytesU64(number: tv.number, byteOrder: .littleEndian, expectedBytes: tv.bytesBigEndian.reversed())
            testReadBytesU64(bytes: tv.bytesBigEndian, byteOrder: .bigEndian, expectedNumber: tv.number)
            testReadBytesU64(bytes: tv.bytesBigEndian.reversed(), byteOrder: .littleEndian, expectedNumber: tv.number)
        }
    }

    static var allTests = [
        ("testFixedWithIntegerBytes", testFixedWithIntegerBytes),
    ]
}
