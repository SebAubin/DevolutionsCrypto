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
        let decodedStringPointer = UnsafeMutablePointer<UInt8>.allocate(capacity: 2048)
        let resultPointer = UnsafeMutablePointer<UInt8>.allocate(capacity: 2048)
        resultPointer.initialize(repeating: 0, count: 2048)
        
        data?.withUnsafeBytes{ (bufferRawBufferPointer) -> Void in
            let decodedSize = Decode(bufferRawBufferPointer.baseAddress!.assumingMemoryBound(to: UInt8.self), UInt(toDecrypt.count), decodedStringPointer, 2048)
            key.withUnsafeBytes{ (bufferRawBufferPointer) -> Void in
                Decrypt(decodedStringPointer, UInt(decodedSize), bufferRawBufferPointer.baseAddress!.assumingMemoryBound(to: UInt8.self), 32, resultPointer, 2048)
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
    
    func testGenerayKey() throws{
        let keyLength = 32
        
        let keyPointer = UnsafeMutablePointer<UInt8>.allocate(capacity: Int(keyLength))
        keyPointer.initialize(repeating: 0, count: Int(keyLength))
        
        _ = GenerateKey(keyPointer, UInt(keyLength));
        let final = Data(bytesNoCopy: keyPointer, count: Int(keyLength), deallocator: .free)
        
        try! testEncrypt(key: [UInt8](final))
        
        XCTAssert(true)
    }
    
    func testValidateHeader(data: String, dataLength: Int64) throws{
        let data = data.data(using: .utf8)
           
        let decodedPointer = UnsafeMutablePointer<UInt8>.allocate(capacity: 2048)
        decodedPointer.initialize(repeating: 0, count: 2048)

        data?.withUnsafeBytes{ (bufferRawBufferPointer) -> Void in
            let decodedLength = Decode(bufferRawBufferPointer.baseAddress!.assumingMemoryBound(to: UInt8.self), UInt(dataLength), decodedPointer, 2048)

            _ = ValidateHeader(decodedPointer, UInt(decodedLength), UInt16(2))
        }
           
        XCTAssert(true)
    }
}
