import XCTest
@testable import HXDataLock

final class CodecTests: XCTestCase {
    func testRoundTrip() throws {
        let password = "correct horse battery staple for hx datalock"
        let keyring = try HxDataLock.createKeyring(masterPassword: password, scryptN: 16384, allowLowScryptN: true)
        let write = keyring["publicWriteKey"] as! [String: Any]
        let envelope = try HxDataLock.lockBytes(publicWriteKey: write, plaintext: Data("swift payload".utf8))
        let opened = try HxDataLock.openBytes(keyring: keyring, masterPassword: password, envelope: envelope)
        XCTAssertEqual(String(data: opened, encoding: .utf8), "swift payload")
    }

    func testLowScryptIsRejected() {
        XCTAssertThrowsError(try HxDataLock.createKeyring(masterPassword: "correct horse battery staple for hx datalock", scryptN: 16384))
    }
}
