import SwiftUI

struct ContentView: View {
    var body: some View {
        VStack {
            Button("Encrypt & decrypt") {
                encryptDecrypt()
            }
            Button("Delete key") {
                deleteKey()
            }
        }
        .padding()
    }

    let tag = "prod_files_ecc_key"

    func encryptDecrypt() {
        do {
            let text = "Hello, world!"

            let publicKey: String
            if let _publicKey = try getPublicKeyBase64String(tag: tag) {
                publicKey = _publicKey
                print("Using existing key pair '\(tag)'")
            } else {
                try generateKeyPair(tag: tag)
                print("Generated key pair '\(tag)'")

                let _publicKey = try getPublicKeyBase64String(tag: tag)

                if let _publicKey {
                    publicKey = _publicKey
                } else {
                    print("Missing public key")
                    return
                }
            }
            print("Public key '\(publicKey)'")

            let encryptedText = try encrypt(string: text, keyTag: tag)
            print("Encrypted text '\(encryptedText)'")

            let decryptedText = try decrypt(base64String: encryptedText, keyTag: tag)
            print("Decrypted text '\(decryptedText)'")
        } catch {
            print(error)
        }
    }

    func deleteKey() {
        do {
            try deleteKeyPair(tag: tag)
            print("Deleted key pair '\(tag)'")
        } catch {
            print(error)
        }
    }
}

struct ContentView_Previews: PreviewProvider {
    static var previews: some View {
        ContentView()
    }
}
