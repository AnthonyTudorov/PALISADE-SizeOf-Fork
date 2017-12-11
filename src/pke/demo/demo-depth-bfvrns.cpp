/*
 * @file demo_she.cpp - PALISADE library.
 * @author  TPOC: palisade@njit.edu
 *
 * @section LICENSE
 *
 * Copyright (c) 2017, New Jersey Institute of Technology (NJIT)
 * All rights reserved.
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:
 * 1. Redistributions of source code must retain the above copyright notice, this
 * list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice, this
 * list of conditions and the following disclaimer in the documentation and/or other
 * materials provided with the distribution.
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR
 * ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
 * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
 * IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * @section DESCRIPTION
 * Demos for a homomorphic multiplication of depth 6 and two different approaches for depth 3 multiplications
 *
 */

#include <iostream>
#include <fstream>
#include <iterator>
#include <chrono>
#include <iterator>

#include "palisade.h"
#include "cryptocontexthelper.h"
#include "cryptocontextgen.h"
#include "encoding/encodings.h"
#include "utils/debug.h"
#include "utils/serializablehelper.h"

#define PROFILE

using namespace std;
using namespace lbcrypto;

int main(int argc, char *argv[]) {

	////////////////////////////////////////////////////////////
	// Set-up of parameters
	////////////////////////////////////////////////////////////


	std::cout << "\nThis code demonstrates the use of the BFVrns scheme for homomorphic multiplication. " << std::endl;
	std::cout << "This code shows how to auto-generate parameters during run-time based on desired plaintext moduli and security levels. " << std::endl;
	std::cout << "In this demonstration we use three input plaintext and show how to both add them together and multiply them together. " << std::endl;

	// benchmarking variables
	TimeVar t;
	double processingTime(0.0);

	usint plaintextModulus = 536903681;
	double sigma = 3.2;
	double rootHermiteFactor = 1.006;

	//Set Crypto Parameters
	CryptoContext<DCRTPoly> cryptoContext = CryptoContextFactory<DCRTPoly>::genCryptoContextBFVrns(
			plaintextModulus, rootHermiteFactor, sigma, 0, 6, 0, OPTIMIZED,2);

	// enable features that you wish to use
	cryptoContext->Enable(ENCRYPTION);
	cryptoContext->Enable(SHE);

	std::cout << "\np = " << cryptoContext->GetCryptoParameters()->GetPlaintextModulus() << std::endl;
	std::cout << "n = " << cryptoContext->GetCryptoParameters()->GetElementParams()->GetCyclotomicOrder() / 2 << std::endl;
	std::cout << "log2 q = " << log2(cryptoContext->GetCryptoParameters()->GetElementParams()->GetModulus().ConvertToDouble()) << std::endl;

	// Initialize Public Key Containers
	LPKeyPair<DCRTPoly> keyPair;

	////////////////////////////////////////////////////////////
	// Perform Key Generation Operation
	////////////////////////////////////////////////////////////

	std::cout << "\nRunning key generation (used for source data)..." << std::endl;

	TIC(t);

	keyPair = cryptoContext->KeyGen();

	processingTime = TOC(t);
	std::cout << "Key generation time: " << processingTime << "ms" << std::endl;

	if( !keyPair.good() ) {
		std::cout << "Key generation failed!" << std::endl;
		exit(1);
	}

	std::cout << "Running key generation for homomorphic multiplication evaluation keys..." << std::endl;

	TIC(t);

	cryptoContext->EvalMultKeysGen(keyPair.secretKey);

	processingTime = TOC(t);
	std::cout << "Key generation time for homomorphic multiplication evaluation keys: " << processingTime << "ms" << std::endl;

	//cryptoContext->EvalMultKeyGen(keyPair.secretKey);

	////////////////////////////////////////////////////////////
	// Encode source data
	////////////////////////////////////////////////////////////

	std::vector<uint32_t> vectorOfInts1 = {1,2,3,4,5,6,7,8,9,10,11,12};
	Plaintext plaintext1 = cryptoContext->MakePackedPlaintext(vectorOfInts1);

	std::vector<uint32_t> vectorOfInts2 = {1,2,3,4,5,6,7,8,9,10,11,12};
	Plaintext plaintext2 = cryptoContext->MakePackedPlaintext(vectorOfInts2);

	std::vector<uint32_t> vectorOfInts3 = {2,1,3,4,5,6,7,8,9,10,11,12};
	Plaintext plaintext3 = cryptoContext->MakePackedPlaintext(vectorOfInts3);

	std::vector<uint32_t> vectorOfInts4 = {2,1,3,4,5,6,7,8,9,10,11,12};
	Plaintext plaintext4 = cryptoContext->MakePackedPlaintext(vectorOfInts4);

	std::vector<uint32_t> vectorOfInts5 = {3,2,1,4,5,6,7,8,9,10,11,12};
	Plaintext plaintext5 = cryptoContext->MakePackedPlaintext(vectorOfInts5);

	std::vector<uint32_t> vectorOfInts6 = {3,2,1,4,5,6,7,8,9,10,11,12};
	Plaintext plaintext6 = cryptoContext->MakePackedPlaintext(vectorOfInts6);

	std::vector<uint32_t> vectorOfInts7 = {1,2,3,4,5,6,7,8,9,10,11,12};
	Plaintext plaintext7 = cryptoContext->MakePackedPlaintext(vectorOfInts7);

	////////////////////////////////////////////////////////////
	// Encryption
	////////////////////////////////////////////////////////////

	vector<Ciphertext<DCRTPoly>> ciphertexts;

	TIC(t);

	ciphertexts.push_back(cryptoContext->Encrypt(keyPair.publicKey, plaintext1));
	ciphertexts.push_back(cryptoContext->Encrypt(keyPair.publicKey, plaintext2));
	ciphertexts.push_back(cryptoContext->Encrypt(keyPair.publicKey, plaintext3));
	ciphertexts.push_back(cryptoContext->Encrypt(keyPair.publicKey, plaintext4));
	ciphertexts.push_back(cryptoContext->Encrypt(keyPair.publicKey, plaintext5));
	ciphertexts.push_back(cryptoContext->Encrypt(keyPair.publicKey, plaintext6));
	ciphertexts.push_back(cryptoContext->Encrypt(keyPair.publicKey, plaintext7));

	processingTime = TOC(t);
	std::cout << "Average encryption time: " << processingTime/7 << "ms" << std::endl;

	TIC(t);

	auto ciphertextMult = cryptoContext->EvalMult(ciphertexts[0],ciphertexts[1]);

	processingTime = TOC(t);
	std::cout << "Total time of multiplying 2 ciphertexts using EvalMult: " << processingTime << "ms" << std::endl;

	Plaintext plaintextDecMult;

	TIC(t);

	cryptoContext->Decrypt(keyPair.secretKey, ciphertextMult, &plaintextDecMult);

	processingTime = TOC(t);
	std::cout << "Decryption time: " << processingTime << "ms" << std::endl;

	plaintextDecMult->SetLength(plaintext1->GetLength());

	cout << "\n Original Plaintext #1: \n";
	cout << plaintext1 << endl;

	cout << "\n Original Plaintext #2: \n";
	cout << plaintext2 << endl;

	cout << "\n Result of their homomorphic multiplication: \n";
	cout << plaintextDecMult << endl;

	TIC(t);

	auto ciphertextMult7 = cryptoContext->EvalMultMany(ciphertexts);

	processingTime = TOC(t);
	std::cout << "\n Total time of multiplying 7 ciphertexts using EvalMultMany: " << processingTime << "ms" << std::endl;

	Plaintext plaintextDecMult7;

	cryptoContext->Decrypt(keyPair.secretKey, ciphertextMult7, &plaintextDecMult7);

	plaintextDecMult7->SetLength(plaintext1->GetLength());

	cout << "\n Result of 6 homomorphic multiplications: \n";
	cout << plaintextDecMult7 << endl;

	return 0;
}
