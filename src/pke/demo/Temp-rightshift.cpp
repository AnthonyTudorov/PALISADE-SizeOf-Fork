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
 * Demo software for BFV multiparty operations.
 *
 */

#include <iostream>
#include <fstream>
#include <iterator>
#include <chrono>
#include <iterator>

#include "palisade.h"
#include "cryptocontexthelper.h"
#include "utils/debug.h"

using namespace std;
using namespace lbcrypto;

void TestBFV();
void TestNull();

int main(int argc, char *argv[]) {

	TestBFV();
	TestNull();

	return 0;
}

void TestBFV() {
		////////////////////////////////////////////////////////////
		// Set-up of parameters
		////////////////////////////////////////////////////////////


		std::cout << "\nThis code demonstrates the use of the BFVrns scheme for EvalRightShift. " << std::endl;


		//Generate parameters.
		double diff, start, finish;

		int plaintextModulus = 8192;
		double sigma =3.2;
		double rootHermiteFactor = 1.006;

		//Set Crypto Parameters
		CryptoContext<DCRTPoly> cryptoContext = CryptoContextFactory<DCRTPoly>::genCryptoContextBFVrns(
				plaintextModulus, rootHermiteFactor, sigma, 0, 1, 0, OPTIMIZED,2);

		// enable features that you wish to use
		cryptoContext->Enable(ENCRYPTION);
		cryptoContext->Enable(SHE);

		std::cout << "p = " << cryptoContext->GetCryptoParameters()->GetPlaintextModulus() << std::endl;
		std::cout << "n = " << cryptoContext->GetCryptoParameters()->GetElementParams()->GetCyclotomicOrder() / 2 << std::endl;
		std::cout << "log2 q = " << log2(cryptoContext->GetCryptoParameters()->GetElementParams()->GetModulus().ConvertToDouble()) << std::endl;

		//std::cout << "Press any key to continue." << std::endl;
		//std::cin.get();

		// Initialize Public Key Containers
		LPKeyPair<DCRTPoly> keyPair;

		////////////////////////////////////////////////////////////
		// Perform Key Generation Operation
		////////////////////////////////////////////////////////////

		std::cout << "Running key generation (used for source data)..." << std::endl;

		start = currentDateTime();

		keyPair = cryptoContext->KeyGen();
		//cryptoContext->EvalMultKeyGen(keyPair.secretKey);

		finish = currentDateTime();
		diff = finish - start;
		cout << "Key generation time: " << "\t" << diff << " ms" << endl;

		if( !keyPair.good() ) {
			std::cout << "Key generation failed!" << std::endl;
			exit(1);
		}

		////////////////////////////////////////////////////////////
		// Encode source data
		////////////////////////////////////////////////////////////

		size_t truncatedBits = 2;
		int64_t inputnumber = 1427;

		Plaintext plaintext1 = cryptoContext->MakeFractionalPlaintext(inputnumber);

		////////////////////////////////////////////////////////////
		// Encryption
		////////////////////////////////////////////////////////////

		start = currentDateTime();

		auto ciphertext1 = cryptoContext->Encrypt(keyPair.publicKey, plaintext1);

		finish = currentDateTime();
		diff = finish - start;
		cout << "Encryption time: " << "\t" << diff << " ms" << endl;


		////////////////////////////////////////////////////////////
		// EvalMult Operation
		////////////////////////////////////////////////////////////

		start = currentDateTime();

		auto ciphertextShifted = cryptoContext->EvalRightShift(ciphertext1,truncatedBits);

		finish = currentDateTime();
		diff = finish - start;
		cout << "EvalMult time: " << "\t" << diff << " ms" << endl;


		////////////////////////////////////////////////////////////
		//Decryption after Accumulation Operation on Re-Encrypted Data
		////////////////////////////////////////////////////////////

		Plaintext plaintextMul;

		start = currentDateTime();

		cryptoContext->Decrypt(keyPair.secretKey, ciphertextShifted, &plaintextMul);

		finish = currentDateTime();
		diff = finish - start;

		//std::cin.get();

		cout << "\n Original Plaintext: \n";
		cout << plaintext1 << endl;

		cout << "\n Resulting Plaintext (after shifting by 2 bits): \n";
		cout << plaintextMul << endl;

		cout << "\n";
		////////////////////////////////////////////////////////////
		// Done
		////////////////////////////////////////////////////////////

		std::cout << "Execution Completed." << std::endl;
		}


void TestNull() {
		////////////////////////////////////////////////////////////
		// Set-up of parameters
		////////////////////////////////////////////////////////////


		std::cout << "\nThis code demonstrates the use of the NULL scheme for EvalRightShift. " << std::endl;


		//Generate parameters.
		double diff, start, finish;

		int plaintextModulus = 1<<30;
		//double sigma =3.2;
		//double rootHermiteFactor = 1.006;

		usint m = 2048;

		CryptoContext<Poly> cryptoContext = CryptoContextFactory<Poly>::genCryptoContextNull(m, plaintextModulus);

		// enable features that you wish to use
		cryptoContext->Enable(ENCRYPTION);
		cryptoContext->Enable(SHE);

		std::cout << "p = " << cryptoContext->GetCryptoParameters()->GetPlaintextModulus() << std::endl;
		std::cout << "n = " << cryptoContext->GetCryptoParameters()->GetElementParams()->GetCyclotomicOrder() / 2 << std::endl;
		std::cout << "log2 q = " << log2(cryptoContext->GetCryptoParameters()->GetElementParams()->GetModulus().ConvertToDouble()) << std::endl;

		//std::cout << "Press any key to continue." << std::endl;
		//std::cin.get();

		// Initialize Public Key Containers
		LPKeyPair<Poly> keyPair;

		////////////////////////////////////////////////////////////
		// Perform Key Generation Operation
		////////////////////////////////////////////////////////////

		std::cout << "Running key generation (used for source data)..." << std::endl;

		start = currentDateTime();

		keyPair = cryptoContext->KeyGen();
		//cryptoContext->EvalMultKeyGen(keyPair.secretKey);

		finish = currentDateTime();
		diff = finish - start;
		cout << "Key generation time: " << "\t" << diff << " ms" << endl;

		if( !keyPair.good() ) {
			std::cout << "Key generation failed!" << std::endl;
			exit(1);
		}

		////////////////////////////////////////////////////////////
		// Encode source data
		////////////////////////////////////////////////////////////

		size_t truncatedBits = 1;
		int64_t inputnumber = 1;

		Plaintext plaintext1 = cryptoContext->MakeFractionalPlaintext(inputnumber);

		////////////////////////////////////////////////////////////
		// Encryption
		////////////////////////////////////////////////////////////

		start = currentDateTime();

		auto ciphertext1 = cryptoContext->Encrypt(keyPair.publicKey, plaintext1);

		finish = currentDateTime();
		diff = finish - start;
		cout << "Encryption time: " << "\t" << diff << " ms" << endl;


		////////////////////////////////////////////////////////////
		// EvalMult Operation
		////////////////////////////////////////////////////////////

		start = currentDateTime();

		auto ciphertextShifted = cryptoContext->EvalRightShift(ciphertext1,truncatedBits);

		finish = currentDateTime();
		diff = finish - start;
		cout << "EvalMult time: " << "\t" << diff << " ms" << endl;


		////////////////////////////////////////////////////////////
		//Decryption after Accumulation Operation on Re-Encrypted Data
		////////////////////////////////////////////////////////////

		Plaintext plaintextMul;

		start = currentDateTime();

		cryptoContext->Decrypt(keyPair.secretKey, ciphertextShifted, &plaintextMul);

		finish = currentDateTime();
		diff = finish - start;

		//std::cin.get();

		cout << "\n Original Plaintext: \n";
		cout << plaintext1 << endl;

		cout << "\n Resulting Plaintext (after shifting by 2 bits): \n";
		cout << plaintextMul << endl;

		cout << "\n";
		////////////////////////////////////////////////////////////
		// Done
		////////////////////////////////////////////////////////////

		std::cout << "Execution Completed." << std::endl;
		}

