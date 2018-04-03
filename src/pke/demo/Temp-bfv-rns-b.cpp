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

//Poly tests
void PKE();
void SHETestPacked();
void SHETestPackedRelin();

size_t COUNTER = 0;

int main() {

	PKE();
	SHETestPacked();
	SHETestPackedRelin();

	std::cout << "total number of errors: " << COUNTER << std::endl;

	//std::cout << "Please press any key to continue..." << std::endl;

	//cin.get();
	return 0;
}


void PKE() {

	std::cout << "\n===========TESTING PKE===============: " << std::endl;

	std::cout << "\nThis code demonstrates the use of the BFV-RNS scheme for basic homomorphic encryption operations. " << std::endl;
	std::cout << "This code shows how to auto-generate parameters during run-time based on desired plaintext moduli and security levels. " << std::endl;
	std::cout << "In this demonstration we use three input plaintext and show how to both add them together and multiply them together. " << std::endl;

	//Generate parameters.
	double diff, start, finish;

	usint ptm = 1<<31;
	double sigma = 3.2;
	double rootHermiteFactor = 1.006;

	//Set Crypto Parameters
	CryptoContext<DCRTPoly> cryptoContext = CryptoContextFactory<DCRTPoly>::genCryptoContextBFVrnsB(
			ptm, rootHermiteFactor, sigma, 0, 6, 0, OPTIMIZED,7);

	std::cout << "ran context gen" << std::endl;

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

	std::vector<int64_t> vectorOfInts = {1<<28,(1<<28)-1,1<<30,202,301,302,1<<30,402,501,502,601,602};
	Plaintext plaintext = cryptoContext->MakeCoefPackedPlaintext(vectorOfInts);

	////////////////////////////////////////////////////////////
	// Encryption
	////////////////////////////////////////////////////////////

	start = currentDateTime();

	auto ciphertext = cryptoContext->Encrypt(keyPair.publicKey, plaintext);

	finish = currentDateTime();
	diff = finish - start;
	cout << "Encryption time: " << "\t" << diff << " ms" << endl;

	////////////////////////////////////////////////////////////
	//Decryption of Ciphertext
	////////////////////////////////////////////////////////////

	Plaintext plaintextDec;

	start = currentDateTime();

	cryptoContext->Decrypt(keyPair.secretKey, ciphertext, &plaintextDec);

	finish = currentDateTime();
	diff = finish - start;
	cout << "Decryption time: " << "\t" << diff << " ms" << endl;

	//std::cin.get();

	plaintextDec->SetLength(plaintext->GetLength());

	cout << "\n Original Plaintext: \n";
	cout << plaintext << endl;

	cout << "\n Resulting Decryption of Ciphertext: \n";
	cout << plaintextDec << endl;

	cout << "\n";


}

void SHETestPacked() {

	std::cout << "\n===========TESTING SHE - ADDITION, SUBTRACTION, NEGATION - PACKED ENCODING===============: " << std::endl;

	std::cout << "\nThis code demonstrates the use of the BFV-RNS scheme for basic homomorphic encryption operations. " << std::endl;
	std::cout << "This code shows how to auto-generate parameters during run-time based on desired plaintext moduli and security levels. " << std::endl;
	std::cout << "In this demonstration we use three input plaintext and show how to both add them together and multiply them together. " << std::endl;

	//Generate parameters.
	double diff, start, finish;

	usint ptm = 65537;
	double sigma = 3.2;
	double rootHermiteFactor = 1.006;

	//Set Crypto Parameters
	CryptoContext<DCRTPoly> cryptoContext = CryptoContextFactory<DCRTPoly>::genCryptoContextBFVrnsB(
			ptm, rootHermiteFactor, sigma, 0, 3, 0, OPTIMIZED,3);

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

	std::vector<uint64_t> vectorOfInts1 = {1,2,3,4,5,6,7,8,9,10,11,12};
	Plaintext plaintext1 = cryptoContext->MakePackedPlaintext(vectorOfInts1);

	std::vector<uint64_t> vectorOfInts2 = {1,2,3,4,5,6,7,8,9,10,11,12};
	Plaintext plaintext2 = cryptoContext->MakePackedPlaintext(vectorOfInts2);

	////////////////////////////////////////////////////////////
	// Encryption
	////////////////////////////////////////////////////////////

	start = currentDateTime();

	auto ciphertext1 = cryptoContext->Encrypt(keyPair.publicKey, plaintext1);

	finish = currentDateTime();
	diff = finish - start;
	cout << "Encryption time: " << "\t" << diff << " ms" << endl;

	auto ciphertext2 = cryptoContext->Encrypt(keyPair.publicKey, plaintext2);

	// Operations

	auto ciphertextSum = cryptoContext->EvalAdd(ciphertext1,ciphertext2);

	auto ciphertextSub = cryptoContext->EvalSub(ciphertext1,ciphertext2);

	auto ciphertextNeg = cryptoContext->EvalNegate(ciphertext1);

	start = currentDateTime();

	auto ciphertextMul = cryptoContext->EvalMultNoRelin(ciphertext1,ciphertext2);

	finish = currentDateTime();
	diff = finish - start;
	cout << "Homomorphic multiplication time - #1: " << "\t" << diff << " ms" << endl;


	start = currentDateTime();

	auto ciphertextCube = cryptoContext->EvalMultNoRelin(ciphertextMul,ciphertext1);

	finish = currentDateTime();
	diff = finish - start;
	cout << "Homomorphic multiplication time - #2: " << "\t" << diff << " ms" << endl;

	////////////////////////////////////////////////////////////
	//Decryption of Ciphertext
	////////////////////////////////////////////////////////////

	Plaintext plaintextDecSub;
	cryptoContext->Decrypt(keyPair.secretKey, ciphertextSub, &plaintextDecSub);
	plaintextDecSub->SetLength(plaintext1->GetLength());

	Plaintext plaintextDec;

	start = currentDateTime();

	cryptoContext->Decrypt(keyPair.secretKey, ciphertextSum, &plaintextDec);

	finish = currentDateTime();
	diff = finish - start;
	cout << "Decryption time: " << "\t" << diff << " ms" << endl;

	//std::cin.get();

	plaintextDec->SetLength(plaintext1->GetLength());

	Plaintext plaintextDecNeg;
	cryptoContext->Decrypt(keyPair.secretKey, ciphertextNeg, &plaintextDecNeg);
	plaintextDecNeg->SetLength(plaintext1->GetLength());

	Plaintext plaintextDecMul;
	cryptoContext->Decrypt(keyPair.secretKey, ciphertextMul, &plaintextDecMul);
	plaintextDecMul->SetLength(plaintext1->GetLength());

	Plaintext plaintextDecCube;
	cryptoContext->Decrypt(keyPair.secretKey, ciphertextCube, &plaintextDecCube);
	plaintextDecCube->SetLength(plaintext1->GetLength());

	cout << "\n Original Plaintext #1: \n";
	cout << plaintext1 << endl;

	cout << "\n Original Plaintext #2: \n";
	cout << plaintext2 << endl;

	cout << "\n Resulting Decryption of the Sum: \n";
	cout << plaintextDec << endl;

	cout << "\n Resulting Decryption of the Subtraction: \n";
	cout << plaintextDecSub << endl;

	cout << "\n Resulting Decryption of the Negation: \n";
	cout << plaintextDecNeg << endl;

	cout << "\n Resulting Decryption of the Multiplication: \n";
	cout << plaintextDecMul << endl;

	cout << "\n Resulting Decryption of the computing the Cube: \n";
	cout << plaintextDecCube << endl;

	cout << "\n";

	start = currentDateTime();
	cryptoContext->EvalMultKeyGen(keyPair.secretKey);
	finish = currentDateTime();
	diff = finish - start;
	cout << "EvalMult key generation time: " << "\t" << diff << " ms" << endl;

	start = currentDateTime();

	auto ciphertextRelin = cryptoContext->EvalMult(ciphertext1,ciphertext2);

	finish = currentDateTime();
	diff = finish - start;
	cout << "Homomorphic multiplication time - with relinearization: " << "\t" << diff << " ms" << endl;

	Plaintext plaintextDecRelin;
	cryptoContext->Decrypt(keyPair.secretKey, ciphertextRelin, &plaintextDecRelin);
	plaintextDecRelin->SetLength(plaintext1->GetLength());

	cout << "\n Resulting Decryption of the Multiplication with Relinearization: \n";
	cout << plaintextDecRelin << endl;

	cout << "\n";

	start = currentDateTime();

	auto evalKeys = cryptoContext->EvalAutomorphismKeyGen(keyPair.secretKey,{5,25});

	finish = currentDateTime();
	diff = finish - start;
	cout << "Automorphism key gen time: " << "\t" << diff << " ms" << endl;

	start = currentDateTime();

	auto ciphertextRotated = cryptoContext->EvalAutomorphism(ciphertext1, 5, *evalKeys);

	finish = currentDateTime();
	diff = finish - start;
	cout << "Automorphism time: " << "\t" << diff << " ms" << endl;

	Plaintext plaintextDecRotated;
	cryptoContext->Decrypt(keyPair.secretKey, ciphertextRotated, &plaintextDecRotated);
	plaintextDecRotated->SetLength(plaintext1->GetLength());
	cout << plaintextDecRotated << endl;

}

void SHETestPackedRelin() {

	std::cout << "\n===========TESTING SHE - ADDITION, SUBTRACTION, NEGATION - PACKED ENCODING===============: " << std::endl;

	std::cout << "\nThis code demonstrates the use of the BFV-RNS scheme for basic homomorphic encryption operations. " << std::endl;
	std::cout << "This code shows how to auto-generate parameters during run-time based on desired plaintext moduli and security levels. " << std::endl;
	std::cout << "In this demonstration we use three input plaintext and show how to both add them together and multiply them together. " << std::endl;

	//Generate parameters.
	double diff, start, finish;

	usint ptm = 65537;
	double sigma = 3.2;
	double rootHermiteFactor = 1.006;
	uint32_t relinWindow = 30;

	//Set Crypto Parameters
	CryptoContext<DCRTPoly> cryptoContext = CryptoContextFactory<DCRTPoly>::genCryptoContextBFVrnsB(
			ptm, rootHermiteFactor, sigma, 0, 3, 0, OPTIMIZED,3,relinWindow,60);

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

	std::vector<uint64_t> vectorOfInts1 = {1,2,3,4,5,6,7,8,9,10,11,12};
	Plaintext plaintext1 = cryptoContext->MakePackedPlaintext(vectorOfInts1);

	std::vector<uint64_t> vectorOfInts2 = {1,2,3,4,5,6,7,8,9,10,11,12};
	Plaintext plaintext2 = cryptoContext->MakePackedPlaintext(vectorOfInts2);

	////////////////////////////////////////////////////////////
	// Encryption
	////////////////////////////////////////////////////////////

	start = currentDateTime();

	auto ciphertext1 = cryptoContext->Encrypt(keyPair.publicKey, plaintext1);

	finish = currentDateTime();
	diff = finish - start;
	cout << "Encryption time: " << "\t" << diff << " ms" << endl;

	auto ciphertext2 = cryptoContext->Encrypt(keyPair.publicKey, plaintext2);

	// Operations

	auto ciphertextSum = cryptoContext->EvalAdd(ciphertext1,ciphertext2);

	auto ciphertextSub = cryptoContext->EvalSub(ciphertext1,ciphertext2);

	auto ciphertextNeg = cryptoContext->EvalNegate(ciphertext1);

	start = currentDateTime();

	auto ciphertextMul = cryptoContext->EvalMultNoRelin(ciphertext1,ciphertext2);

	finish = currentDateTime();
	diff = finish - start;
	cout << "Homomorphic multiplication time - #1: " << "\t" << diff << " ms" << endl;


	start = currentDateTime();

	auto ciphertextCube = cryptoContext->EvalMultNoRelin(ciphertextMul,ciphertext1);

	finish = currentDateTime();
	diff = finish - start;
	cout << "Homomorphic multiplication time - #2: " << "\t" << diff << " ms" << endl;

	////////////////////////////////////////////////////////////
	//Decryption of Ciphertext
	////////////////////////////////////////////////////////////

	Plaintext plaintextDecSub;
	cryptoContext->Decrypt(keyPair.secretKey, ciphertextSub, &plaintextDecSub);
	plaintextDecSub->SetLength(plaintext1->GetLength());

	Plaintext plaintextDec;

	start = currentDateTime();

	cryptoContext->Decrypt(keyPair.secretKey, ciphertextSum, &plaintextDec);

	finish = currentDateTime();
	diff = finish - start;
	cout << "Decryption time: " << "\t" << diff << " ms" << endl;

	//std::cin.get();

	plaintextDec->SetLength(plaintext1->GetLength());

	Plaintext plaintextDecNeg;
	cryptoContext->Decrypt(keyPair.secretKey, ciphertextNeg, &plaintextDecNeg);
	plaintextDecNeg->SetLength(plaintext1->GetLength());

	Plaintext plaintextDecMul;
	cryptoContext->Decrypt(keyPair.secretKey, ciphertextMul, &plaintextDecMul);
	plaintextDecMul->SetLength(plaintext1->GetLength());

	Plaintext plaintextDecCube;
	cryptoContext->Decrypt(keyPair.secretKey, ciphertextCube, &plaintextDecCube);
	plaintextDecCube->SetLength(plaintext1->GetLength());

	cout << "\n Original Plaintext #1: \n";
	cout << plaintext1 << endl;

	cout << "\n Original Plaintext #2: \n";
	cout << plaintext2 << endl;

	cout << "\n Resulting Decryption of the Sum: \n";
	cout << plaintextDec << endl;

	cout << "\n Resulting Decryption of the Subtraction: \n";
	cout << plaintextDecSub << endl;

	cout << "\n Resulting Decryption of the Negation: \n";
	cout << plaintextDecNeg << endl;

	cout << "\n Resulting Decryption of the Multiplication: \n";
	cout << plaintextDecMul << endl;

	cout << "\n Resulting Decryption of the computing the Cube: \n";
	cout << plaintextDecCube << endl;

	cout << "\n";

	start = currentDateTime();
	cryptoContext->EvalMultKeyGen(keyPair.secretKey);
	finish = currentDateTime();
	diff = finish - start;
	cout << "EvalMult key generation time: " << "\t" << diff << " ms" << endl;

	start = currentDateTime();

	auto ciphertextRelin = cryptoContext->EvalMult(ciphertext1,ciphertext2);

	finish = currentDateTime();
	diff = finish - start;
	cout << "Homomorphic multiplication time - with relinearization: " << "\t" << diff << " ms" << endl;

	Plaintext plaintextDecRelin;
	cryptoContext->Decrypt(keyPair.secretKey, ciphertextRelin, &plaintextDecRelin);
	plaintextDecRelin->SetLength(plaintext1->GetLength());

	cout << "\n Resulting Decryption of the Multiplication with Relinearization: \n";
	cout << plaintextDecRelin << endl;

	cout << "\n";

	start = currentDateTime();

	auto evalKeys = cryptoContext->EvalAutomorphismKeyGen(keyPair.secretKey,{5,25});

	finish = currentDateTime();
	diff = finish - start;
	cout << "Automorphism key gen time: " << "\t" << diff << " ms" << endl;

	start = currentDateTime();

	auto ciphertextRotated = cryptoContext->EvalAutomorphism(ciphertext1, 5, *evalKeys);

	finish = currentDateTime();
	diff = finish - start;
	cout << "Automorphism time: " << "\t" << diff << " ms" << endl;

	Plaintext plaintextDecRotated;
	cryptoContext->Decrypt(keyPair.secretKey, ciphertextRotated, &plaintextDecRotated);
	plaintextDecRotated->SetLength(plaintext1->GetLength());
	cout << plaintextDecRotated << endl;

}

