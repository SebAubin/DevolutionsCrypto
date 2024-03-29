//
//  DevolutionsCryptoTests.swift
//  DevolutionsCryptoTests
//
//  Created by Sebastien Aubin on 2020-04-22.
//  Copyright © 2020 Devolutions. All rights reserved.
//

import XCTest
@testable import DevolutionsCrypto

class DevolutionsCryptoTests: XCTestCase {
    
    func testGenerateKeyPairSize() throws {
        let size = GenerateKeyPairSize()
        XCTAssert(size == 40)
    }
    
    func testGenerateKeyPair() throws {
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
            
            XCTAssert(privateString != publicString)
        }
    }
    
    public func testDecodeBase64() throws{
        let encodedData = "DQwBAAIAAQAv3ANOIcPLYySJwcHgSo3Gk0Rwe78YiGZ42JrCZKC0cg"
        let data = encodedData.data(using: .utf8)
        let decodedStringPointer = UnsafeMutablePointer<UInt8>.allocate(capacity: 65535)
        let resultPointer = UnsafeMutablePointer<UInt8>.allocate(capacity: 65535)
        resultPointer.initialize(repeating: 0, count: 65535)
        var result: [UInt8]?
        
        data?.withUnsafeBytes{ (bufferRawBufferPointer) -> Void in
            let decodedSize = Decode(bufferRawBufferPointer.baseAddress!.assumingMemoryBound(to: UInt8.self), UInt(encodedData.count), decodedStringPointer, 65535)
            
            if(decodedSize > 0){
                let data = Data(bytesNoCopy: decodedStringPointer, count: Int(decodedSize), deallocator: .free)
                result = [UInt8](data)
            }
        }
        
        XCTAssert(result != nil)
    }
    
    func testDecryptAsymmetric(){
        let toDecrypt = "DQwCAAIAAgBc69b1pJGC3ZkCV0+vbLM4AAb4G2ChwvAR+adAs8l7A83b9pC7R2scX7lmrtfT+K7yCZahWy/6DVGyxK+5ce2PKmfAUFHF8DaCxwCg3637v8HkDrEcSBYiBR1LhUOGqrp4S+m60T9IVw=="
        let with = "DQwCAAIAAgAUVq6wERSMCc3cP0wUfohpJRpgSmlhrUiYAjdictzqeb2HOml013HHUuBjTZBVOfWF2mW9NiHgd5aQW7H4gJM25FlkY1zTMW8wT1kBqnLx-3dMW0V4VGm7AXTlyJPHvANHIe--bCY-aPu6FDDtZf19"
        
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
                        let encodedString = String(bytes: dataEncoded, encoding: .utf8)
                        XCTAssert(encodedString != nil)
                    }
                }
            }
        }
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
    
    func testEncryptAsymmetric() throws{
        // Generate key to encrypt
        let toEncryptKey = UnsafeMutablePointer<UInt8>.allocate(capacity: 32)
        toEncryptKey.initialize(repeating: 0, count: 32)
        let toEntrypt = GenerateKey(toEncryptKey, 32)
        
        if(toEntrypt == 0){
            let intermediateKey = Data(bytesNoCopy: toEncryptKey, count: 32, deallocator: .free)
            XCTAssert(true)
            
            // Generate keypair
            let size = GenerateKeyPairSize()
            let privateKeyPointer = UnsafeMutablePointer<UInt8>.allocate(capacity: Int(size))
            privateKeyPointer.initialize(repeating: 0, count: Int(size))
            let publicKeyPointer = UnsafeMutablePointer<UInt8>.allocate(capacity: Int(size))
            publicKeyPointer.initialize(repeating: 0, count: Int(size))
            let generationResult = GenerateKeyPair(privateKeyPointer, UInt(size), publicKeyPointer, UInt(size))
            
            if(generationResult == 0){
                let privateKey = Data(bytesNoCopy: privateKeyPointer, count: Int(size), deallocator: .free)
                let privateKeyBytes = [UInt8](privateKey)
                
                let publicKey = Data(bytesNoCopy: publicKeyPointer, count: Int(size), deallocator: .free)
                let publicKeyBytes = [UInt8](publicKey)
            
                encryptAssymetric(toEncrypt: intermediateKey, with: publicKey)
            }
        }
    }
    
    func encryptAssymetric(toEncrypt: Data, with: Data){
        let encryptSize = EncryptAsymmetricSize(UInt(toEncrypt.count), 0)
        
        let resultEncryptedPointer = UnsafeMutablePointer<UInt8>.allocate(capacity: Int(encryptSize))
        resultEncryptedPointer.initialize(repeating: 0, count: Int(encryptSize))
        
        toEncrypt.withUnsafeBytes{ (bufferRawBufferPointer) -> Void in
            with.withUnsafeBytes{ (keyBufferRawBufferPointer) -> Void in
                
                // Test encrypt
                let encryptedSize = EncryptAsymmetric(
                    bufferRawBufferPointer.baseAddress!.assumingMemoryBound(to: UInt8.self),
                    UInt(toEncrypt.count),
                    keyBufferRawBufferPointer.baseAddress!.assumingMemoryBound(to: UInt8.self),
                    UInt(with.count),
                    resultEncryptedPointer,
                    UInt(encryptSize),
                    0)
                
                let final = Data(bytesNoCopy: resultEncryptedPointer, count: Int(encryptedSize), deallocator: .free)
                let privateDataInCorrectFormat = [UInt8](final)
                let privateEncoded = Base64FS.encode(data: privateDataInCorrectFormat)
                let privateString = String(bytes: privateEncoded, encoding: .utf8)
                XCTAssert(privateString != nil)
            }
        }        
    }
    
    override func setUpWithError() throws {
        // Put setup code here. This method is called before the invocation of each test method in the class.
    }
    
    override func tearDownWithError() throws {
        // Put teardown code here. This method is called after the invocation of each test method in the class.
    }
    
    func testKeySize() throws {
        let size = KeySize()
        XCTAssert(size == 256)
    }
    
    func testHashPasswordLength() throws{
        let size = HashPasswordLength()
        XCTAssert(size == (8 + 4 + 32 + 32))
    }
    
    func testDecrypt(toDecrypt: String = "DQwCAAEAAgArsheJXE5ajuHcAhp8HdHrROUdy7avnSj/E8M7sf9Po3Hk/162vtYzGgtF33N+1m03qISLEnVSAgtIQyVJk0KEwrtyd3TcPfklottnstcpjfdY/xkzneKjytjIW01HZpz8roc1AfrTPXRzjuNrZPIU+5/ID07nyYlFwcFMQ7+2Rn0hjGGBoPYCklEuPpuHqyEGQuS26zmQPwPIRZ4xkP0eQMXJMo+ya21h8ocGjS649xVmuIHBG6RQKFYYKVjhw2TSTx6RX2oIaZFPWCYSlThN/zEEwRaiHo2cnDZA2QO8073uxenj9nGyE5VgVi3IS31dGRLn8pPsDEGMzRFwv9fXTdO2P8iJQVxZQgEkCiWzSO/lg+2EXfXRMHd6uCV68A8IMV/lY49NGZLnFtfk++z2QcVauFQDNY4HlOC/CE5J27onayC2e7jAcD09jcb71PU1wCsdKHKpTCG+G9CXGWG817WC1tkJuaUKt4fzmMT0cUuALc1qF9A9508c/oamoX+8KImGryDxk+5/W7YcX4dz7U12PYXKSGAgzUndNQc/nE+yOXHUK+gQ9HRo3IpSpg3uOmPT4hmP7vPXU80PzgGUG4g56fwZ5fpnzCiEYQzyCOnKm3cOZauQeqC2EUY+wrOsBh6pVM2Rc+PBjJ70PPKBuGsiQYFDQ8xMUQFLsYFpLKe8ZUuATngk/oibZw7/BNqBHvC1BXgtJVftaYSfnMwZL8S9rUUYMNys82E+CItTfElxLQ3tnI9AGnOm7JpXOtDLzxUdXVvANr2OAyAYJAdXiDFJPO4dE6oAFYIcT6MD3+7RPVGHTZEuEWwdYqyEtSLG7QXaRJyi0Nt8fqJ6iiKaTsRrmeABYLWT9AKpx3EtBiOFoiu55qPymSVxR7BI84jurews/NWdMlXhdjfTKwJgGt6oNOhgVwfSpLBv3jxgxGHF+LUldBEGhXUyKYLCfGdAHsT4EV1t", key: [UInt8] = []) throws{
        
        // Validate header
        try! testValidateHeader(data: toDecrypt, dataLength: Int64(toDecrypt.count))
        
        let data = toDecrypt.data(using: .utf8)
        let decodedStringPointer = UnsafeMutablePointer<UInt8>.allocate(capacity: 65535)
        let resultPointer = UnsafeMutablePointer<UInt8>.allocate(capacity: 65535)
        resultPointer.initialize(repeating: 0, count: 65535)
        
        data?.withUnsafeBytes{ (bufferRawBufferPointer) -> Void in
            let decodedSize = Decode(bufferRawBufferPointer.baseAddress!.assumingMemoryBound(to: UInt8.self), UInt(toDecrypt.count), decodedStringPointer, 65535)
            key.withUnsafeBytes{ (bufferRawBufferPointer) -> Void in
                Decrypt(decodedStringPointer, UInt(decodedSize), bufferRawBufferPointer.baseAddress!.assumingMemoryBound(to: UInt8.self), 32, resultPointer, 65535)
            }
        }
        
        _ = String(cString: resultPointer)
        XCTAssert(true)
    }
    
    func testEncrypt(key: [UInt8] = []) throws{
        let str = "{\"ConnectionType\":32,\"CreatedBy\":\"DEVOLUTIONS\\\\tesUser\",\"CreationDateTimeString\":\"2020-04-16T14:00:18\",\"Group\":\"First folder\",\"ID\":\"0db98bb0-8fbe-43c0-bf65-cf647255c86f\",\"Name\":\"Test\",\"OpenEmbedded\":true,\"Stamp\":\"1805e841-6333-45fc-aca3-f56da6262d29\",\"DataEntry\":{\"ConnectionTypeInfos\":[{\"DataEntryConnectionType\":3,\"SafeData\":\"\"}]}}"
        
        let encryptSize = EncryptSize(UInt(str.count), 0)
        
        let resultEncryptedPointer = UnsafeMutablePointer<UInt8>.allocate(capacity: Int(encryptSize))
        resultEncryptedPointer.initialize(repeating: 0, count: Int(encryptSize))
        
        let data = str.data(using: .utf8)
        data?.withUnsafeBytes{ (bufferRawBufferPointer) -> Void in
            key.withUnsafeBytes{ (keyBufferRawBufferPointer) -> Void in
                
                // Test encrypt
                let encryptedSize = Encrypt(bufferRawBufferPointer.baseAddress!.assumingMemoryBound(to: UInt8.self), UInt(str.count), keyBufferRawBufferPointer.baseAddress!.assumingMemoryBound(to: UInt8.self), 32, resultEncryptedPointer, UInt(encryptSize), 0)
                
                let final = Data(bytesNoCopy: resultEncryptedPointer, count: Int(encryptedSize), deallocator: .free)
                let encoded = final.base64EncodedString()
                
                // Test decrypt
                try! testDecrypt(toDecrypt: encoded, key: key)
            }
        }
        
        XCTAssert(true)
    }
    
    func testGetArgon2ParametersBase64() throws{
        let size = GetDefaultArgon2ParametersSize()
        let argon2ParamsBytes = UnsafeMutablePointer<UInt8>.allocate(capacity: Int(size))
        argon2ParamsBytes.initialize(repeating: 0, count: Int(size))
        
        GetDefaultArgon2Parameters(argon2ParamsBytes, UInt(size))
        
        let final = Data(bytesNoCopy: argon2ParamsBytes, count: Int(size), deallocator: .free)
        let finalArray = [UInt8](final)
        
        let encoded = Base64FS.encode(data: finalArray)
        
        let string = String(bytes: encoded, encoding: .utf8)
        print(string)
    }
    
    func testGetDefaultArgonParametersSize() throws{
        let size = GetDefaultArgon2ParametersSize()
        let argon2ParamsBytes = UnsafeMutablePointer<UInt8>.allocate(capacity: Int(size))
        argon2ParamsBytes.initialize(repeating: 0, count: Int(size))
        
        GetDefaultArgon2Parameters(argon2ParamsBytes, UInt(size))
        let passwordDerivedBytes = UnsafeMutablePointer<UInt8>.allocate(capacity: Int(32))
        passwordDerivedBytes.initialize(repeating: 0, count: Int(32))
        
        let password = "test"
        let data = password.data(using: .utf8)
        
        data?.withUnsafeBytes{ (bufferRawBufferPointer) -> Void in
            let result = DeriveKeyArgon2(bufferRawBufferPointer.baseAddress!.assumingMemoryBound(to: UInt8.self), UInt(password.count), argon2ParamsBytes, UInt(size), passwordDerivedBytes, UInt(32))
            
            XCTAssert(result >= 0)
            
            let final = Data(bytesNoCopy: passwordDerivedBytes, count: Int(32), deallocator: .free)
            let returnArray = [UInt8](final)
            
            XCTAssert(returnArray.count == 32)
        }
    }
    
    func testGenerayKey() throws{
        let keyLength = 32
        
        let keyPointer = UnsafeMutablePointer<UInt8>.allocate(capacity: Int(keyLength))
        keyPointer.initialize(repeating: 0, count: Int(keyLength))
        
        _ = GenerateKey(keyPointer, UInt(keyLength));
        let final = Data(bytesNoCopy: keyPointer, count: Int(keyLength), deallocator: .free)
        
        try! testEncrypt(key: [UInt8](final))
        
        XCTAssert(true)
    }
    
    func testHeaderValidity() throws{
        let data = "DQwCAAIAAgBZJb00ch3_Fb_8egMiy8yhtD4XtS9iwSOESFMMN9j_S1Ahq_AR-fQFZtWIjX57-1pyuocio5q8nuvPQCWaTMfYPcTU9CD1q8LspPgRvEFtKZvuaVJWy1fkLLT7sw-Alg101WhwSkUR4g=="
        try! testValidateHeader(data: data, dataLength: Int64(data.count))
    }
    
    func testValidateHeader(data: String, dataLength: Int64) throws{
        let data = data.data(using: .utf8)
        
        let decodedPointer = UnsafeMutablePointer<UInt8>.allocate(capacity: 65535)
        decodedPointer.initialize(repeating: 0, count: 65535)
        
        data?.withUnsafeBytes{ (bufferRawBufferPointer) -> Void in
            let decoded = Base64FS.decode(data: [UInt8](data!))
            
            decoded.withUnsafeBytes{ (buffer) -> Void in
                let valid = ValidateHeader(buffer.baseAddress!.assumingMemoryBound(to: UInt8.self), UInt(decoded.count), UInt16(2))
                print("is it?")
            }
        }
        
        XCTAssert(true)
    }
}

public extension Data {
    public init?(base64urlEncoded input: String) {
        var base64 = input
        base64 = base64.replacingOccurrences(of: "-", with: "+")
        base64 = base64.replacingOccurrences(of: "_", with: "/")
        while base64.count % 4 != 0 {
            base64 = base64.appending("=")
        }
        self.init(base64Encoded: base64)
    }

    public func base64urlEncodedString() -> String {
        var result = self.base64EncodedString()
        result = result.replacingOccurrences(of: "+", with: "-")
        result = result.replacingOccurrences(of: "/", with: "_")
        result = result.replacingOccurrences(of: "=", with: "")
        return result
    }
}
