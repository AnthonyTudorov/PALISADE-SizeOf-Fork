/*
 * @file 
 * @author  TPOC: palisade@njit.edu
 *
 * @copyright Copyright (c) 2017, New Jersey Institute of Technology (NJIT)
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
 */
 /*
BFV RNS testing programs
*/

#include <iostream>
#include <fstream>
#include <limits>

#include "palisade.h"


#include "cryptocontexthelper.h"

#include "encoding/encodings.h"

#include "utils/debug.h"
#include <random>

#include "math/nbtheory.h"

typedef std::numeric_limits< double > dbl;

using namespace std;
using namespace lbcrypto;


#include <iterator>


void SHETestCoeff();

int main() {


	SHETestCoeff();


	//std::cout << "Please press any key to continue..." << std::endl;

	//cin.get();
	return 0;
}


void SHETestCoeff() {

	std::cout << "\n===========TESTING SHE - MULTIPLYING BY -x^i where i in Z_m^* - COEFFICIENT ENCODING===============: " << std::endl;

	std::cout << "\nThis code demonstrates the use of the BFV-RNS scheme for basic homomorphic encryption operations. " << std::endl;
	std::cout << "This code shows how to auto-generate parameters during run-time based on desired plaintext moduli and security levels. " << std::endl;
	std::cout << "In this demonstration we use three input plaintext and show how to both add them together and multiply them together. " << std::endl;

	//Generate parameters.
	double diff, start, finish;

	usint ptm = 1<<31;
	double sigma = 3.2;
	double rootHermiteFactor = 1.006;

	//Set Crypto Parameters
	CryptoContext<DCRTPoly> cryptoContext = CryptoContextFactory<DCRTPoly>::genCryptoContextBFVrns(
			ptm, rootHermiteFactor, sigma, 0, 2, 0, OPTIMIZED,2);

	// enable features that you wish to use
	cryptoContext->Enable(ENCRYPTION);
	cryptoContext->Enable(SHE);

	std::cout << "p = " << cryptoContext->GetCryptoParameters()->GetPlaintextModulus() << std::endl;
	std::cout << "n = " << cryptoContext->GetCryptoParameters()->GetElementParams()->GetCyclotomicOrder() / 2 << std::endl;
	std::cout << "log2 q = " << log2(cryptoContext->GetCryptoParameters()->GetElementParams()->GetModulus().ConvertToDouble()) << std::endl;

	// Initialize Public Key Containers
	LPKeyPair<DCRTPoly> keyPair;

	////////////////////////////////////////////////////////////
	// Perform Key Generation Operation
	////////////////////////////////////////////////////////////

	std::cout << "Running key generation (used for source data)..." << std::endl;

	start = currentDateTime();

	keyPair = cryptoContext->KeyGen();

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

	std::vector<int64_t> vectorOfInts1 = {1,2,3,4,5,6,7,8,9,10,11,12};
	Plaintext plaintext1 = cryptoContext->MakeCoefPackedPlaintext(vectorOfInts1);

	std::vector<int64_t> vectorOfInts2 = {0,0,0,-1,0,0,0,0,0,0,0,0};
	Plaintext plaintext2 = cryptoContext->MakeCoefPackedPlaintext(vectorOfInts2);

	////////////////////////////////////////////////////////////
	// Encryption
	////////////////////////////////////////////////////////////

	start = currentDateTime();

	auto ciphertext1 = cryptoContext->Encrypt(keyPair.publicKey, plaintext1);

	finish = currentDateTime();
	diff = finish - start;
	cout << "Encryption time: " << "\t" << diff << " ms" << endl;

	// Plaintext multiplication

	auto ciphertextMult = cryptoContext->EvalMult(ciphertext1,plaintext2);

	////////////////////////////////////////////////////////////
	//Decryption of Ciphertext
	////////////////////////////////////////////////////////////

	Plaintext plaintextDec;

	start = currentDateTime();

	cryptoContext->Decrypt(keyPair.secretKey, ciphertextMult, &plaintextDec);

	finish = currentDateTime();
	diff = finish - start;
	cout << "Decryption time: " << "\t" << diff << " ms" << endl;

	//std::cin.get();

	Plaintext plaintextDecMult;
	cryptoContext->Decrypt(keyPair.secretKey, ciphertextMult, &plaintextDecMult);
	plaintextDecMult->SetLength(plaintext1->GetLength());

	cout << "\n Original Plaintext #1: \n";
	cout << plaintext1 << endl;

	cout << "\n Original Plaintext #2: \n";
	cout << plaintext2 << endl;

	cout << "\n Resulting Decryption of the product: \n";
	cout << plaintextDec << endl;

	cout << "\n";

}
