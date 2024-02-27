//
//  ContentView.swift
//  SecureEnclaveKeyGen
//
//  Created by Sourav Mishra on 26/02/24.
//

import SwiftUI
import CryptoKit

struct ContentView: View {
    @State private var publicKey: String = ""
    @State private var privateKey: String = ""
    
    var body: some View {
        VStack {
            Text("Secure Enclave Demo")
                .font(.title)
                .padding()
            
            Button("Show Result") {
                // Uncomment to test key creation in secure enclave
                // let _ = makeAndStoreKey(name: "Sourav3")
                
                // Uncomment to test encryption and decryption of data
                // encryptData()
                
                // Uncomment to test signing and verifying the sign
                // Sign the hash like we do normally
                // Hash function isn't available here so I used plaintext directly
                sign(data: "Hello".data(using: .utf8)!)
            }
            .padding()
        }
    }
    
    func makeAndStoreKey(name: String, requiresBiometry: Bool = false) -> SecKey? {
        
        let flags: SecAccessControlCreateFlags
        if #available(iOS 11.3, *) {
            flags = requiresBiometry ?
            [.privateKeyUsage, .biometryCurrentSet] : .privateKeyUsage
        } else {
            flags = requiresBiometry ?
            [.privateKeyUsage, .touchIDCurrentSet] : .privateKeyUsage
        }
        let access =
        SecAccessControlCreateWithFlags(kCFAllocatorDefault,
                                        kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
                                        flags,
                                        nil)!
        let tag = name.data(using: .utf8)!
        let attributes: [String: Any] = [
            kSecAttrKeyType as String           : kSecAttrKeyTypeEC,
            kSecAttrKeySizeInBits as String     : 256,
            kSecAttrTokenID as String           : kSecAttrTokenIDSecureEnclave,
            kSecPrivateKeyAttrs as String : [
                kSecAttrIsPermanent as String       : true,
                kSecAttrApplicationTag as String    : tag,
                kSecAttrAccessControl as String     : access
            ]
        ]
        
        var error: Unmanaged<CFError>?
        let privateKey = SecKeyCreateRandomKey(attributes as CFDictionary, &error)
        //        print(privateKey!)
        
        // Load the private key once saved using the name/tag
        // let fetchedKey = loadKey(name: "Sourav2")!
        // print(fetchedKey)
        
        // Get Public Key From Private Key [Secure Enclave's]
        // let publicKey = getPubKey(privateKey: privateKey!)!
        // print(publicKey)
        encryptData()
        return privateKey
    }
    
    // THIS FUNCTION LOADS THE PRIVATE KEY ASSOCIATED WITH THE KEY'S NAME
    func loadKey(name: String) -> SecKey? {
        let tag = name.data(using: .utf8)!
        let query: [String: Any] = [
            kSecClass as String                 : kSecClassKey,
            kSecAttrApplicationTag as String    : tag,
            kSecAttrKeyType as String           : kSecAttrKeyTypeEC,
            kSecReturnRef as String             : true
        ]
        
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        guard status == errSecSuccess else {
            return nil
        }
        let _publicKey = SecKeyCopyPublicKey(item as! SecKey)!
        //        print(publicKey)
        
        return (item as! SecKey)
    }
    
    // THIS FUNCTION RETURNS THE PUBLIC KEY ASSOCIATED WITH THE CORRESPONDING PRIVATE KEY
    func getPubKey(privateKey: SecKey) -> SecKey? {
        return SecKeyCopyPublicKey(privateKey)
    }
    
    func encryptData(dataToEncrypt: String = "") {
        let dataToEncrypt = "Hello"
        
        let algorithm: SecKeyAlgorithm = .eciesEncryptionCofactorVariableIVX963SHA256AESGCM
        let publicKey: SecKey = getPubKey(privateKey: loadKey(name: "Sourav3")!)!
        
        var error: Unmanaged<CFError>?
        let clearTextData = dataToEncrypt.data(using: .utf8)!
        let cipherTextData = SecKeyCreateEncryptedData(publicKey, algorithm, clearTextData as CFData, &error) as Data?
        
        print("Encrypted Data:", cipherTextData!.base64EncodedString())
        
        guard cipherTextData != nil else {
            print((error!.takeRetainedValue() as Error).localizedDescription)
            return
        }
        
        decryptData(dataToDecrypt: cipherTextData! as CFData)
    }
    
    func decryptData(dataToDecrypt: CFData) {
        let algorithm: SecKeyAlgorithm = .eciesEncryptionCofactorVariableIVX963SHA256AESGCM
        
        // Don't create new thread if biometric auth is disabled for this
        DispatchQueue.global().async {
            var error: Unmanaged<CFError>?
            let clearTextData = SecKeyCreateDecryptedData(loadKey(name: "Sourav3")!, algorithm, dataToDecrypt, &error) as Data?
            DispatchQueue.main.async {
                guard clearTextData != nil else {
                    print((error!.takeRetainedValue() as Error).localizedDescription)
                    return
                }
                let clearText = String(decoding: clearTextData!, as: UTF8.self)
                print("Decrypted Data:", clearText)
            }
        }
    }
    
    func sign(data: Data) {
        let algorithm: SecKeyAlgorithm = .ecdsaSignatureMessageX962SHA256 // Use when signing a message directly
//        let algorithm: SecKeyAlgorithm = .ecdsaSignatureDigestX962SHA256 // Use when signing a hash(SHA 256)
        // Don't create new thread if biometric auth is disabled for this
        DispatchQueue.global().async {
            var error: Unmanaged<CFError>?
            let signature = SecKeyCreateSignature(loadKey(name: "Sourav3")!, algorithm, data as CFData, &error) as Data?
            DispatchQueue.main.async {
                guard signature != nil else {
                    print((error!.takeRetainedValue() as Error).localizedDescription)
                    return
                }
            }
            verify(signature: signature! as CFData)
        }
    }
    
    func verify(signature: CFData) {
        let publicKey = SecKeyCopyPublicKey(getPubKey(privateKey: loadKey(name: "Sourav3")!)!)!

        let algorithm: SecKeyAlgorithm = .ecdsaSignatureMessageX962SHA256

        let clearTextData = "Hello".data(using: .utf8)!
        var error: Unmanaged<CFError>?
        let result = SecKeyVerifySignature(publicKey, algorithm, clearTextData as CFData, signature, &error)
        print(result)
    }
}

struct ContentView_Previews: PreviewProvider {
    static var previews: some View {
        ContentView()
    }
}
