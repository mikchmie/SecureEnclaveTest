import Foundation
import Security

// MARK: - Constants
private let cipherAlgorithm = SecKeyAlgorithm.eciesEncryptionCofactorVariableIVX963SHA256AESGCM
private let keyType = kSecAttrKeyTypeECSECPrimeRandom

// MARK: - Key management
public func generateKeyPair(tag: String) throws {
    guard getPrivateKey(tag: tag) == nil else {
        throw SecureEnclaveKitError.keyAlreadyExists
    }

    var error: Unmanaged<CFError>?

    guard let accessControl = SecAccessControlCreateWithFlags(
        kCFAllocatorDefault,
        kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
        [.privateKeyUsage, .userPresence], // Change `userPresence` to `biometryAny` to require biometric authentication
        nil
    ) else {
        throw error!.takeRetainedValue() as Error
    }

    let attributes: NSDictionary = [
        kSecAttrKeyType: keyType,
        kSecAttrKeySizeInBits: 256,
        kSecAttrTokenID: kSecAttrTokenIDSecureEnclave,
        kSecPrivateKeyAttrs: [
            kSecAttrIsPermanent: true,
            kSecAttrApplicationTag: Data(tag.utf8),
            kSecAttrAccessControl: accessControl
        ]
    ]

    let privateKey = SecKeyCreateRandomKey(attributes, &error)

    guard privateKey != nil else {
        throw error!.takeRetainedValue() as Error
    }
}

public func getPublicKeyData(tag: String) throws -> Data? {
    guard let privateKey = getPrivateKey(tag: tag),
          let publicKey = SecKeyCopyPublicKey(privateKey) else {
        return nil
    }

    var error: Unmanaged<CFError>?
    guard let publicKeyData = SecKeyCopyExternalRepresentation(publicKey, &error) as? Data else {
        throw error!.takeRetainedValue() as Error
    }

    return publicKeyData
}

public func getPublicKeyBytes(tag: String) throws -> [UInt8]? {
    try getPublicKeyData(tag: tag).flatMap { Array($0) }
}

public func getPublicKeyBase64String(tag: String) throws -> String? {
    try getPublicKeyData(tag: tag)?.base64EncodedString()
}

public func deleteKeyPair(tag: String) throws {
    let query = privateKeyQuery(tag: tag)
    let status = SecItemDelete(query)

    guard status == errSecSuccess else {
        throw SecureEnclaveKitError.keyDeletionFailed(status)
    }
}

// MARK: - Encryption
public func encrypt(string: String, keyTag: String) throws -> String {
    try encrypt(data: Data(string.utf8), keyTag: keyTag).base64EncodedString()
}

public func encrypt(data: Data, keyTag: String) throws -> Data {
    guard let privateKey = getPrivateKey(tag: keyTag),
          let publicKey = SecKeyCopyPublicKey(privateKey) else {
        throw SecureEnclaveKitError.keyNotFound
    }

    guard SecKeyIsAlgorithmSupported(publicKey, .encrypt, cipherAlgorithm) else {
        throw SecureEnclaveKitError.algorithmNotSupported
    }

    var error: Unmanaged<CFError>?
    guard let encrytpedData = SecKeyCreateEncryptedData(
        publicKey,
        cipherAlgorithm,
        data as CFData,
        &error
    ) as Data? else {
        throw error!.takeRetainedValue() as Error
    }

    return encrytpedData
}

// MARK: - Decryption
public func decrypt(base64String: String, keyTag: String) throws -> String {
    guard let rawData = Data(base64Encoded: base64String) else {
        throw SecureEnclaveKitError.notBase64String
    }

    let decryptedData = try decrypt(data: rawData, keyTag: keyTag)

    guard let decryptedString = String(data: decryptedData, encoding: .utf8) else {
        throw SecureEnclaveKitError.cannnotConvertDataToString
    }

    return decryptedString
}

public func decrypt(data: Data, keyTag: String) throws -> Data {
    guard let privateKey = getPrivateKey(tag: keyTag) else {
        throw SecureEnclaveKitError.keyNotFound
    }

    guard SecKeyIsAlgorithmSupported(privateKey, .decrypt, cipherAlgorithm) else {
        throw SecureEnclaveKitError.algorithmNotSupported
    }

    var error: Unmanaged<CFError>?
    guard let decryptedData = SecKeyCreateDecryptedData(
        privateKey,
        cipherAlgorithm,
        data as CFData,
        &error
    ) as Data? else {
        throw error!.takeRetainedValue() as Error
    }

    return decryptedData
}

// MARK: - Helper functions
private func getPrivateKey(tag: String) -> SecKey? {
    let query = privateKeyQuery(tag: tag)
    var item: CFTypeRef?
    let status = SecItemCopyMatching(query as CFDictionary, &item)

    return status == errSecSuccess ? (item as! SecKey) : nil
}

private func privateKeyQuery(tag: String) -> CFDictionary {
    ([
        kSecClass: kSecClassKey,
        kSecAttrApplicationTag: Data(tag.utf8),
        kSecAttrKeyType: keyType,
        kSecReturnRef: true
    ] as NSDictionary) as CFDictionary
}

// MARK: - Helper types
public enum SecureEnclaveKitError: Swift.Error {
    case keyAlreadyExists
    case keyDeletionFailed(OSStatus)
    case keyNotFound
    case algorithmNotSupported
    case notBase64String
    case cannnotConvertDataToString
}
