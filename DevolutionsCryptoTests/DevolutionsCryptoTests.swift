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
    
    func testDecrypt(toDecrypt: String = "DQwCAAEAAgArsheJXE5ajuHcAhp8HdHrROUdy7avnSj/E8M7sf9Po3Hk/162vtYzGgtF33N+1m03qISLEnVSAgtIQyVJk0KEwrtyd3TcPfklottnstcpjfdY/xkzneKjytjIW01HZpz8roc1AfrTPXRzjuNrZPIU+5/ID07nyYlFwcFMQ7+2Rn0hjGGBoPYCklEuPpuHqyEGQuS26zmQPwPIRZ4xkP0eQMXJMo+ya21h8ocGjS649xVmuIHBG6RQKFYYKVjhw2TSTx6RX2oIaZFPWCYSlThN/zEEwRaiHo2cnDZA2QO8073uxenj9nGyE5VgVi3IS31dGRLn8pPsDEGMzRFwv9fXTdO2P8iJQVxZQgEkCiWzSO/lg+2EXfXRMHd6uCV68A8IMV/lY49NGZLnFtfk++z2QcVauFQDNY4HlOC/CE5J27onayC2e7jAcD09jcb71PU1wCsdKHKpTCG+G9CXGWG817WC1tkJuaUKt4fzmMT0cUuALc1qF9A9508c/oamoX+8KImGryDxk+5/W7YcX4dz7U12PYXKSGAgzUndNQc/nE+yOXHUK+gQ9HRo3IpSpg3uOmPT4hmP7vPXU80PzgGUG4g56fwZ5fpnzCiEYQzyCOnKm3cOZauQeqC2EUY+wrOsBh6pVM2Rc+PBjJ70PPKBuGsiQYFDQ8xMUQFLsYFpLKe8ZUuATngk/oibZw7/BNqBHvC1BXgtJVftaYSfnMwZL8S9rUUYMNys82E+CItTfElxLQ3tnI9AGnOm7JpXOtDLzxUdXVvANr2OAyAYJAdXiDFJPO4dE6oAFYIcT6MD3+7RPVGHTZEuEWwdYqyEtSLG7QXaRJyi0Nt8fqJ6iiKaTsRrmeABYLWT9AKpx3EtBiOFoiu55qPymSVxR7BI84jurews/NWdMlXhdjfTKwJgGt6oNOhgVwfSpLBv3jxgxGHF+LUldBEGhXUyKYLCfGdAHsT4EV1t") throws{

        let data = toDecrypt.data(using: .utf8)
        let decodedStringPointer = UnsafeMutablePointer<UInt8>.allocate(capacity: 2048)
        let resultPointer = UnsafeMutablePointer<UInt8>.allocate(capacity: 2048)
        resultPointer.initialize(repeating: 0, count: 2048)
        
        data?.withUnsafeBytes{ (bufferRawBufferPointer) -> Void in
            let decodedSize = Decode(bufferRawBufferPointer.baseAddress!.assumingMemoryBound(to: UInt8.self), UInt(toDecrypt.count), decodedStringPointer, 2048)
            let key: [UInt8] = [18, 152, 149, 167, 226, 17, 80, 196, 157, 252, 61, 12, 71, 63, 245, 58, 210, 210, 40, 141, 97, 38, 63, 66, 17, 104, 245, 131, 143, 23, 0, 160]
            key.withUnsafeBytes{ (bufferRawBufferPointer) -> Void in
                Decrypt(decodedStringPointer, UInt(decodedSize), bufferRawBufferPointer.baseAddress!.assumingMemoryBound(to: UInt8.self), 32, resultPointer, 2048)
            }
        }
        
        let resultString = String(cString: resultPointer)
        XCTAssert(true)
    }
    
    func testEncrypt() throws{
        let str = "{\"ConnectionType\":32,\"CreatedBy\":\"DEVOLUTIONS\\\\sverreault\",\"CreationDateTimeString\":\"2020-04-16T14:00:18\",\"Group\":\"First folder\",\"ID\":\"0db98bb0-8fbe-43c0-bf65-cf647255c86f\",\"Name\":\"Seb\",\"OpenEmbedded\":true,\"Stamp\":\"1805e841-6333-45fc-aca3-f56da6262d29\",\"DataEntry\":{\"ConnectionTypeInfos\":[{\"DataEntryConnectionType\":3,\"SafeData\":\"\"}]}}"
        
        let encryptSize = EncryptSize(UInt(str.count), 0)
        
        let resultEncryptedPointer = UnsafeMutablePointer<UInt8>.allocate(capacity: Int(encryptSize))
        resultEncryptedPointer.initialize(repeating: 0, count: Int(encryptSize))
        
        let data = str.data(using: .utf8)
        data?.withUnsafeBytes{ (bufferRawBufferPointer) -> Void in
            let key: [UInt8] = [18, 152, 149, 167, 226, 17, 80, 196, 157, 252, 61, 12, 71, 63, 245, 58, 210, 210, 40, 141, 97, 38, 63, 66, 17, 104, 245, 131, 143, 23, 0, 160]
            key.withUnsafeBytes{ (keyBufferRawBufferPointer) -> Void in
               
                // Test encrypt
                let encryptedSize = Encrypt(bufferRawBufferPointer.baseAddress!.assumingMemoryBound(to: UInt8.self), UInt(str.count), keyBufferRawBufferPointer.baseAddress!.assumingMemoryBound(to: UInt8.self), 32, resultEncryptedPointer, UInt(encryptSize), 0)
                
                let final = Data(bytesNoCopy: resultEncryptedPointer, count: Int(encryptedSize), deallocator: .free)
                let encoded = final.base64EncodedString()
                
                // Test decrypt
                try! testDecrypt(toDecrypt: encoded)
            }
        }
        
    }
}
