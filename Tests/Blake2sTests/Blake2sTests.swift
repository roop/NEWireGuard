/*
 Copyright (C) 2018 Roopesh Chander S <roop@roopc.net>

 Licensed under the GPLv3: http://www.gnu.org/licenses/gpl-3.0.html
 */

import XCTest
@testable import NEWireGuard
import Blake2sTestVectors

class Blake2sTests: XCTestCase {

    func testBlake2s() {
        let numberOfTestVectors = Int(BLAKE2_KAT_LENGTH)
        var cTestVectors = blake2s_test_vectors
        // Swift imports the C array-of-arrays as a tuple-of-tuples.
        // So to get the data out, we take a pointer to the tuple-of-tuples,
        // bind it to read UInt8 values, and copy each vector to a Array<UInt8>.
        withUnsafeBytes(of: &cTestVectors) { (bufPtr) -> Void in
            let ptr = bufPtr.baseAddress!.bindMemory(to: UInt8.self, capacity: Blake2s.hashLength * numberOfTestVectors)
            for i in (0 ..< numberOfTestVectors) {
                var input = Array<UInt8>(repeating: 0, count: i)
                for j in (0 ..< i) {
                    input[j] = UInt8(j)
                }
                var expectedHash = Array<UInt8>(repeating: 0, count: Blake2s.hashLength)
                for j in (0 ..< Blake2s.hashLength) {
                    expectedHash[j] = ptr[i * Blake2s.hashLength + j]
                }
                let actualHash = Blake2s.hash(of: input, followedBy: [])
                XCTAssertEqual(actualHash, expectedHash)
                if (input.count > 64) {
                    // Split the input into three and check
                    let first = Array<UInt8>(input[..<32])
                    let second = Array<UInt8>(input[32..<64])
                    let third = Array<UInt8>(input[64...])
                    let actualHashWhenSplit = Blake2s.hash(of: first, followedBy: second, third)
                    XCTAssertEqual(actualHashWhenSplit, expectedHash)
                } else if (input.count > 32) {
                    // Split the input into two and check
                    let first = Array<UInt8>(input[..<32])
                    let second = Array<UInt8>(input[32...])
                    let actualHashWhenSplit = Blake2s.hash(of: first, followedBy: second)
                    XCTAssertEqual(actualHashWhenSplit, expectedHash)
                }
            }
        }
    }


    static var allTests = [
        ("testBlake2s", testBlake2s),
    ]
}
