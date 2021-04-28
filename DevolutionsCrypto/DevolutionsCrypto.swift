//
//  DevolutionsCrypto.swift
//  DevolutionsCrypto
//
//  Created by Sebastien Aubin on 2020-04-22.
//  Copyright © 2020 Devolutions. All rights reserved.
//

import Foundation

public class DevolutionsCrypto {
    public init() {}
    
    public func keySize() -> UInt32 {
        return KeySize()
    }
    
    public func decrypt(encodedData: String, key: [UInt8]) -> String {
        let data = encodedData.data(using: .utf8)
        let decodedStringPointer = UnsafeMutablePointer<UInt8>.allocate(capacity: 65535)
        let resultPointer = UnsafeMutablePointer<UInt8>.allocate(capacity: 65535)
        resultPointer.initialize(repeating: 0, count: 65535)
        var resultCode: Int64 = -1;
        
        data?.withUnsafeBytes{ (bufferRawBufferPointer) -> Void in
            let decodedSize = Decode(bufferRawBufferPointer.baseAddress!.assumingMemoryBound(to: UInt8.self), UInt(encodedData.count), decodedStringPointer, 65535)
            
            if(decodedSize > 0){
                key.withUnsafeBytes{ (bufferRawBufferPointer) -> Void in
                    resultCode = Decrypt(decodedStringPointer, UInt(decodedSize), bufferRawBufferPointer.baseAddress!.assumingMemoryBound(to: UInt8.self), UInt(key.count), resultPointer, 65535)
                }
            }
        }
        
        if resultCode > 0{
            return String(cString: resultPointer)
        }
        
        return ""
    }
    
    public func decryptBytes(encodedData: String, key: [UInt8]) -> [UInt8] {
        let data = encodedData.data(using: .utf8)
        let decodedStringPointer = UnsafeMutablePointer<UInt8>.allocate(capacity: 65535)
        let resultPointer = UnsafeMutablePointer<UInt8>.allocate(capacity: 65535)
        resultPointer.initialize(repeating: 0, count: 65535)
        var decryptLength: Int64 = -1;
        
        data?.withUnsafeBytes{ (bufferRawBufferPointer) -> Void in
            let decodedSize = Decode(bufferRawBufferPointer.baseAddress!.assumingMemoryBound(to: UInt8.self), UInt(encodedData.count), decodedStringPointer, 65535)
            
            if(decodedSize > 0){
                key.withUnsafeBytes{ (bufferRawBufferPointer) -> Void in
                    decryptLength = Decrypt(decodedStringPointer, UInt(decodedSize), bufferRawBufferPointer.baseAddress!.assumingMemoryBound(to: UInt8.self), UInt(key.count), resultPointer, 65535)
                }
            }
        }
        
        if decryptLength > 0{
            let data = Data(bytesNoCopy: resultPointer, count: Int(decryptLength), deallocator: .free)
            return [UInt8](data)
        }
        
        return []
    }
    
    public func decryptBigDataBytes(encodedData: String, key: [UInt8]) -> [UInt8] {
        let data = encodedData.data(using: .utf8)
        let decodedStringPointer = UnsafeMutablePointer<UInt8>.allocate(capacity: 65535 * 256)
        let resultPointer = UnsafeMutablePointer<UInt8>.allocate(capacity: 65535 * 256)
        resultPointer.initialize(repeating: 0, count: 65535 * 256)
        var decryptLength: Int64 = -1;
        
        data?.withUnsafeBytes{ (bufferRawBufferPointer) -> Void in
            let decodedSize = Decode(bufferRawBufferPointer.baseAddress!.assumingMemoryBound(to: UInt8.self), UInt(encodedData.count), decodedStringPointer, 65535 * 256)
            
            if(decodedSize > 0){
                key.withUnsafeBytes{ (bufferRawBufferPointer) -> Void in
                    decryptLength = Decrypt(decodedStringPointer, UInt(decodedSize), bufferRawBufferPointer.baseAddress!.assumingMemoryBound(to: UInt8.self), UInt(key.count), resultPointer, 65535 * 256)
                }
            }
        }
        
        if decryptLength > 0{
            let data = Data(bytesNoCopy: resultPointer, count: Int(decryptLength), deallocator: .free)
            return [UInt8](data)
        }
        
        return []
    }
    
    public func encrypt(decryptedData: String, key: [UInt8]) -> String{
        let encryptSize = EncryptSize(UInt(decryptedData.count), 0)
        
        let resultEncryptedPointer = UnsafeMutablePointer<UInt8>.allocate(capacity: Int(encryptSize))
        resultEncryptedPointer.initialize(repeating: 0, count: Int(encryptSize))
        
        let data = decryptedData.data(using: .utf8)
        var encryptedSize: Int64 = -1;
        
        data?.withUnsafeBytes{ (bufferRawBufferPointer) -> Void in
            key.withUnsafeBytes{ (keyBufferRawBufferPointer) -> Void in
                encryptedSize = Encrypt(bufferRawBufferPointer.baseAddress!.assumingMemoryBound(to: UInt8.self), UInt(decryptedData.count), keyBufferRawBufferPointer.baseAddress!.assumingMemoryBound(to: UInt8.self), UInt(key.count), resultEncryptedPointer, UInt(encryptSize), 0)
            }
        }
        
        if(encryptedSize > 0){
            let final = Data(bytesNoCopy: resultEncryptedPointer, count: Int(encryptedSize), deallocator: .free)
            return final.base64EncodedString()
        }
        
        return ""
    }
    
    public func encryptBytes(data: [UInt8], key: [UInt8]) -> [UInt8]{
        let encryptSize = EncryptSize(UInt(data.count), 0)
        
        let resultEncryptedPointer = UnsafeMutablePointer<UInt8>.allocate(capacity: Int(encryptSize))
        resultEncryptedPointer.initialize(repeating: 0, count: Int(encryptSize))
        
        var encryptedSize: Int64 = -1;
        
        data.withUnsafeBytes{ (bufferRawBufferPointer) -> Void in
            key.withUnsafeBytes{ (keyBufferRawBufferPointer) -> Void in
                encryptedSize = Encrypt(bufferRawBufferPointer.baseAddress!.assumingMemoryBound(to: UInt8.self), UInt(data.count), keyBufferRawBufferPointer.baseAddress!.assumingMemoryBound(to: UInt8.self), UInt(key.count), resultEncryptedPointer, UInt(encryptSize), 0)
            }
        }
        
        if(encryptedSize > 0){
            let final = Data(bytesNoCopy: resultEncryptedPointer, count: Int(encryptedSize), deallocator: .free)
            return [UInt8](final)
        }
        
        return []
    }
    
    public func generateKeyString(keyLength: Int) -> String{
        let keyPointer = UnsafeMutablePointer<UInt8>.allocate(capacity: Int(keyLength))
        keyPointer.initialize(repeating: 0, count: Int(keyLength))
        
        if GenerateKey(keyPointer, UInt(keyLength)) == 0{
            let final = Data(bytesNoCopy: keyPointer, count: Int(keyLength), deallocator: .free)
            
            return final.base64EncodedString()
        }
        
        return ""
    }
    
    public func generateKeyPair() -> [String: String?]{
        let size = GenerateKeyPairSize()
        let publicPointer = UnsafeMutablePointer<UInt8>.allocate(capacity: Int(size))
        let privatePointer = UnsafeMutablePointer<UInt8>.allocate(capacity: Int(size))
        
        let generated = GenerateKeyPair(privatePointer, UInt(size), publicPointer, UInt(size))
        
        if(generated == 0){
            let privateData = Data(bytesNoCopy: privatePointer, count: Int(size), deallocator: .free)
            let privateDataInCorrectFormat = [UInt8](privateData)
            let privateEncoded = Base64FS.encode(data: privateDataInCorrectFormat)
            let privateString = String(bytes: privateEncoded, encoding: .utf8)
            
            let publicData = Data(bytesNoCopy: publicPointer, count: Int(size), deallocator: .free)
            let publicDataInCorrectFormat = [UInt8](publicData)
            let publicEncoded = Base64FS.encode(data: publicDataInCorrectFormat)
            let publicString = String(bytes: publicEncoded, encoding: .utf8)
            
            return ["publicKey": publicString, "privateKey": privateString]
        }
        
        return [:]
    }
    
    public func validateHeader(encodedData: String, type: Int) -> Bool{
        let data = encodedData.data(using: .utf8)
        
        let decodedPointer = UnsafeMutablePointer<UInt8>.allocate(capacity: 65535)
        decodedPointer.initialize(repeating: 0, count: 65535)
        
        var resultCode: Int64 = -1;
        
        data?.withUnsafeBytes{ (bufferRawBufferPointer) -> Void in
            let decodedLength = Decode(bufferRawBufferPointer.baseAddress!.assumingMemoryBound(to: UInt8.self), UInt(encodedData.count), decodedPointer, 65535)
            
            resultCode = ValidateHeader(decodedPointer, UInt(decodedLength), UInt16(type))
        }
        
        if resultCode > 0{
            return true
        }
        
        return false
    }
    
    public func decodeBase64(encodedData: String) -> [UInt8]{
        let data = encodedData.data(using: .utf8)
        guard data != nil else { return [] }
        return Base64FS.decode(data: [UInt8](data!))
    }
    
    public func generateKey(keyLength: Int = 32) -> [UInt8]{
        let keyPointer = UnsafeMutablePointer<UInt8>.allocate(capacity: Int(keyLength))
        keyPointer.initialize(repeating: 0, count: Int(keyLength))
        
        _ = GenerateKey(keyPointer, UInt(keyLength));
        let final = Data(bytesNoCopy: keyPointer, count: Int(keyLength), deallocator: .free)
        return [UInt8](final)
    }
    
    public func encryptAsymmetric(toEncrypt: [UInt8], with: [UInt8]) -> [UInt8]? {
        let intermediateKey = Data(toEncrypt)
        let publicKey = Data(with)
        
        return doEncryptAsymmetric(toEncrypt: intermediateKey, with: publicKey)
    }
    
    func doEncryptAsymmetric(toEncrypt: Data, with: Data) -> [UInt8]?{
        var result: [UInt8]?
        let encryptSize = EncryptAsymmetricSize(UInt(toEncrypt.count), 0)
        
        let resultEncryptedPointer = UnsafeMutablePointer<UInt8>.allocate(capacity: Int(encryptSize))
        resultEncryptedPointer.initialize(repeating: 0, count: Int(encryptSize))
        
        toEncrypt.withUnsafeBytes{ (bufferRawBufferPointer) -> Void in
            with.withUnsafeBytes{ (keyBufferRawBufferPointer) -> Void in
                
                let encryptedSize = EncryptAsymmetric(
                    bufferRawBufferPointer.baseAddress!.assumingMemoryBound(to: UInt8.self),
                    UInt(toEncrypt.count),
                    keyBufferRawBufferPointer.baseAddress!.assumingMemoryBound(to: UInt8.self),
                    UInt(with.count),
                    resultEncryptedPointer,
                    UInt(encryptSize),
                    0)
                
                let final = Data(bytesNoCopy: resultEncryptedPointer, count: Int(encryptedSize), deallocator: .free)
                result = [UInt8](final)
            }
        }
        
        return result
    }
    
    public func decryptAsymmetric(toDecrypt: String, with: String) -> String?{
        let toDecrypt = padBase64(value: toDecrypt)
        let with = padBase64(value: with)
        var result: String?
        
        if let toDecryptData = Data(base64urlEncoded: toDecrypt), let withData = Data(base64urlEncoded: with){

            let toDecryptArrayData = Data([UInt8](toDecryptData))
            let withArrayData = Data([UInt8](withData))
            
            let resultDecryptedPointer = UnsafeMutablePointer<UInt8>.allocate(capacity: 65535)
            resultDecryptedPointer.initialize(repeating: 0, count: 65535)
            
            toDecryptArrayData.withUnsafeBytes{ (bufferRawBufferPointer) -> Void in
                withArrayData.withUnsafeBytes{ (keyBufferRawBufferPointer) -> Void in
                    let decryptedSize = DecryptAsymmetric(
                        bufferRawBufferPointer.baseAddress!.assumingMemoryBound(to: UInt8.self),
                        UInt(toDecryptArrayData.count),
                        keyBufferRawBufferPointer.baseAddress!.assumingMemoryBound(to: UInt8.self),
                        UInt(withArrayData.count),
                        resultDecryptedPointer,
                        UInt(65535))
                    
                    if(decryptedSize > 0){
                        let final = Data(bytesNoCopy: resultDecryptedPointer, count: Int(decryptedSize), deallocator: .free)
                        let dataInCorrectFormat = [UInt8](final)
                        let dataEncoded = Base64FS.encode(data: dataInCorrectFormat)
                        result = String(bytes: dataEncoded, encoding: .utf8)
                    }
                }
            }
        }
        
        return result
    }
    
    public func getArgon2ParametersBase64() -> [UInt8]?{
        let size = GetDefaultArgon2ParametersSize()
        let argon2ParamsBytes = UnsafeMutablePointer<UInt8>.allocate(capacity: Int(size))
        argon2ParamsBytes.initialize(repeating: 0, count: Int(size))
        
        GetDefaultArgon2Parameters(argon2ParamsBytes, UInt(size))
        
        let final = Data(bytesNoCopy: argon2ParamsBytes, count: Int(size), deallocator: .free)
        let finalArray = [UInt8](final)
        return finalArray
    }
    
    public func deriveKeyArgon2(password: String, params: [UInt8]) -> [UInt8]?{
        var result: [UInt8]?
        
        let passwordDerivedBytes = UnsafeMutablePointer<UInt8>.allocate(capacity: Int(32))
        passwordDerivedBytes.initialize(repeating: 0, count: Int(32))
        
        let data = password.data(using: .utf8)
        data?.withUnsafeBytes{ (bufferRawBufferPointer) -> Void in
            let resultArgon = DeriveKeyArgon2(bufferRawBufferPointer.baseAddress!.assumingMemoryBound(to: UInt8.self), UInt(password.count), params, UInt(params.count), passwordDerivedBytes, UInt(32))
            
            if(resultArgon >= 0){
                let final = Data(bytesNoCopy: passwordDerivedBytes, count: Int(32), deallocator: .free)
                result = [UInt8](final)
            }
        }
        
        return result
    }
    
    public func scryptSimple(passwordBytes: [UInt8], saltBytes: [UInt8], log_n: Int, r: Int, p: Int) -> [UInt8]?{
        var result: [UInt8]?
        
        let size = ScryptSimpleSize()
        
        let sCryptedBytes = UnsafeMutablePointer<UInt8>.allocate(capacity: Int(size))
        sCryptedBytes.initialize(repeating: 0, count: Int(size))
        
        passwordBytes.withUnsafeBytes{ (passwordBuffer) -> Void in
            saltBytes.withUnsafeBytes{ (saltBuffer) -> Void in
                let size = ScryptSimple(
                    passwordBuffer.baseAddress!.assumingMemoryBound(to: UInt8.self),
                    UInt(passwordBytes.count),
                    saltBuffer.baseAddress!.assumingMemoryBound(to: UInt8.self),
                    UInt(saltBytes.count),
                    UInt8(log_n),
                    UInt32(r),
                    UInt32(p),
                    sCryptedBytes,
                    UInt(size))
                
                if(size >= 0){
                    let final = Data(bytesNoCopy: sCryptedBytes, count: Int(size), deallocator: .free)
                    result = [UInt8](final)
                }
            }
        }
        
        return result
    }
    
    func padBase64(value: String) -> String{
        if(value.count % 4 == 2){
            return "\(value)=="
        }
        
        if(value.count % 4 == 3){
            return "\(value)="
        }
        
        return value
    }
}

public extension Data {
    init?(base64urlEncoded input: String) {
        var base64 = input
        base64 = base64.replacingOccurrences(of: "-", with: "+")
        base64 = base64.replacingOccurrences(of: "_", with: "/")
        while base64.count % 4 != 0 {
            base64 = base64.appending("=")
        }
        self.init(base64Encoded: base64)
    }

    func base64urlEncodedString() -> String {
        var result = self.base64EncodedString()
        result = result.replacingOccurrences(of: "+", with: "-")
        result = result.replacingOccurrences(of: "/", with: "_")
        result = result.replacingOccurrences(of: "=", with: "")
        return result
    }
}
