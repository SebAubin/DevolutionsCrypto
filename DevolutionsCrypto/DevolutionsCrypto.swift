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
        let decodedStringPointer = UnsafeMutablePointer<UInt8>.allocate(capacity: 2048)
        let resultPointer = UnsafeMutablePointer<UInt8>.allocate(capacity: 2048)
        resultPointer.initialize(repeating: 0, count: 2048)
        
        data?.withUnsafeBytes{ (bufferRawBufferPointer) -> Void in
            let decodedSize = Decode(bufferRawBufferPointer.baseAddress!.assumingMemoryBound(to: UInt8.self), UInt(encodedData.count), decodedStringPointer, 2048)
            key.withUnsafeBytes{ (bufferRawBufferPointer) -> Void in
                Decrypt(decodedStringPointer, UInt(decodedSize), bufferRawBufferPointer.baseAddress!.assumingMemoryBound(to: UInt8.self), 32, resultPointer, 2048)
            }
        }
        
        return String(cString: resultPointer)
    }
}
