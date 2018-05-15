/*
 Copyright (C) 2018 Roopesh Chander S <roop@roopc.net>

 Licensed under the GPLv3: http://www.gnu.org/licenses/gpl-3.0.html
 */

import XCTest
@testable import NEWireGuard

import Foundation

class TAI64NTests: XCTestCase {

    func testTAI64N() {
        var tai64nTestVectors: [(date: Date, result: [UInt8])] = [
            // Test vectors based on the text of https://cr.yp.to/libtai/tai64.html
            (date: Date(timeIntervalSince1970: -1),
             result: [ 0x3f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                       0x00, 0x00, 0x00, 0x00 ]),
            (date: Date(timeIntervalSince1970: 0),
             result: [ 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                       0x00, 0x00, 0x00, 0x00 ]),
            (date: Date(timeIntervalSince1970: 1),
             result: [ 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
                       0x00, 0x00, 0x00, 0x00 ]),
        ]
        let dateFormatter = DateFormatter()
        dateFormatter.locale =  Locale(identifier: "en_US_POSIX")
        dateFormatter.dateFormat = "yyyy-MM-dd HH:mm:ss.S zzz"
        tai64nTestVectors.append(
            // Another test from the text of https://cr.yp.to/libtai/tai64.html
            // (It looks like the UTC time from DateFormatter() includes leap seconds,
            // so we're using the TAI timestamp string from the text)
            (date: dateFormatter.date(from: "1992-06-02 08:07:09.0 UTC")!,
             result: [ 0x40, 0x00, 0x00, 0x00, 0x2a, 0x2b, 0x2c, 0x2d,
                       0x00, 0x00, 0x00, 0x00 ])
        )
        tai64nTestVectors.append(
            // 10 seconds into 1970
            (date: dateFormatter.date(from: "1970-01-01 00:00:10.0 UTC")!,
             result: [ 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0a,
                       0x00, 0x00, 0x00, 0x00 ])
        )
        tai64nTestVectors.append(
            // 10.5 seconds into 1970
            (date: dateFormatter.date(from: "1970-01-01 00:00:10.5 UTC")!,
             result: [ 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0a,
                       0x1d, 0xcd, 0x65, 0x00 /* 500000000 nanoseconds */])
        )
        for tv in tai64nTestVectors {
            let actual = TAI64N.timestamp(for: tv.date)
            let expected = tv.result
            XCTAssertEqual(actual, expected)
        }
    }

    static var allTests = [
        ("testTAI64N", testTAI64N),
    ]
}

