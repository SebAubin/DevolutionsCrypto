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
    
    public func generateKey(keyLength: Int) -> String{
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
}
