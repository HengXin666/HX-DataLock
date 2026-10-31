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

    func testWeakPasswordIsRejectedAndPublicFloorIgnoresAllowWeak() {
        XCTAssertThrowsError(try HxDataLock.createKeyring(masterPassword: "password", scryptN: 16384, allowLowScryptN: true))
        XCTAssertThrowsError(try HxDataLock.createKeyring(masterPassword: "password", scryptN: 16384, allowLowScryptN: true, allowWeakPassword: true, publicKeyring: true))
    }

    func testStreamAndManifestRoundTrip() throws {
        let password = "correct horse battery staple for hx datalock"
        let keyring = try HxDataLock.createKeyring(masterPassword: password, scryptN: 16384, allowLowScryptN: true)
        let write = keyring["publicWriteKey"] as! [String: Any]
        let spki = Data(base64Encoded: write["spki"] as! String)!
        let keyId = write["keyId"] as! String
        let payload = Data("abcdefghijklmnopqrstuvwxyz".utf8)
        let sealed = try HxDataLock.sealChunked(keyId: keyId, recipientSpki: spki, plaintext: payload, chunkSize: 8, fileId: "file-a")
        let material = try HxDataLock.keyMaterial(keyring: keyring, masterPassword: password)
        let opened = try HxDataLock.openChunked(keyId: material.keyId, rawPrivate: material.rawPrivate, recipientSpki: material.spki, manifest: sealed.manifest, sealedChunks: sealed.chunks)
        XCTAssertEqual(opened, payload)
        let keys = HxDataLock.generateAttestationKey()
        let message = Data("hxdl".utf8)
        let signed = try HxDataLock.signManifest(privateKey: keys.privateKey, issuer: "app", payload: ["fileId": "file-a"])
        try HxDataLock.verifySignedManifest(signed, expectedSignerKeyId: (signed["signer"] as! [String: Any])["keyId"] as? String)
        _ = message
    }
}
