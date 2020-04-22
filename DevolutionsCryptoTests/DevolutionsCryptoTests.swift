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

    func testExample() throws {
        let size = KeySize()
        XCTAssert(size == 256)
    }

}
