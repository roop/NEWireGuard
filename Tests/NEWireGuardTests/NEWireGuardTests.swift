import XCTest
@testable import NEWireGuard

class NEWireGuardTests: XCTestCase {
    func testExample() {
        XCTAssertEqual(Noise.noiseProtocolName, "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s")
    }


    static var allTests = [
        ("testExample", testExample),
    ]
}
