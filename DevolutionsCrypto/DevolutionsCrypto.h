//
//  DevolutionsCrypto.h
//  DevolutionsCrypto
//
//  Created by Sebastien Aubin on 2020-04-22.
//  Copyright © 2020 Devolutions. All rights reserved.
//

#import <Foundation/Foundation.h>

//! Project version number for DevolutionsCrypto.
FOUNDATION_EXPORT double DevolutionsCryptoVersionNumber;

//! Project version string for DevolutionsCrypto.
FOUNDATION_EXPORT const unsigned char DevolutionsCryptoVersionString[];

// In this header, you should import all the public headers of your framework using statements like #import <DevolutionsCrypto/PublicHeader.h>

unsigned int KeySize();

long HashPasswordLength();

int64_t EncryptSize(uintptr_t data_length, uint16_t version);

int64_t GenerateKey(uint8_t *key, uintptr_t key_length);

int64_t GenerateKeyPairSize();

int64_t GenerateKeyPair(uint8_t *private_, uintptr_t private_length, uint8_t *public_, uintptr_t public_length);

int64_t ValidateHeader(const uint8_t *data, uintptr_t data_length, uint16_t data_type);

int64_t Decode(const uint8_t *input, uintptr_t input_length, uint8_t *output, uintptr_t output_length);

int64_t Decrypt(const uint8_t *data, uintptr_t data_length, const uint8_t *key, uintptr_t key_length, uint8_t *result, uintptr_t result_length);

int64_t Encrypt(const uint8_t *data, uintptr_t data_length, const uint8_t *key, uintptr_t key_length, uint8_t *result, uintptr_t result_length, uint16_t version);

int64_t EncryptAsymmetric(const uint8_t *data, uintptr_t data_length, const uint8_t *public_key, uintptr_t public_key_length, uint8_t *result, uintptr_t result_length, uint16_t version);

int64_t EncryptAsymmetricSize(uintptr_t data_length, uint16_t version);
