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
 * Demo software for FV multiparty operations.
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
#include "encoding/byteplaintextencoding.h"
#include "utils/debug.h"
#include "utils/serializablehelper.h"

using namespace std;
using namespace lbcrypto;

int main(int argc, char *argv[]) {

	////////////////////////////////////////////////////////////
	// Set-up of parameters
	////////////////////////////////////////////////////////////


	std::cout << "\nThis code demonstrates the use of the FV scheme for basic homomorphic encryption operations. " << std::endl;
	std::cout << "This code shows how to auto-generate parameters during run-time based on desired plaintext moduli and security levels. " << std::endl;
	std::cout << "In this demonstration we use three input plaintext and show how to both add them together and multiply them together. " << std::endl;


	//Generate parameters.
	double diff, start, finish;

	int relWindow = 1;
	int plaintextModulus = 256;
	double sigma = 4;
	double rootHermiteFactor = 1.006;

	//Set Crypto Parameters
	shared_ptr<CryptoContext<Poly>> cryptoContext = CryptoContextFactory<Poly>::genCryptoContextFV(
			plaintextModulus, rootHermiteFactor, relWindow, sigma, 0, 5, 0, OPTIMIZED, 6);

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

	//Create evaluation key vector to be used in keyswitching
	shared_ptr<vector<shared_ptr<LPEvalKey<Poly>>>> evalKeys = cryptoContext->GetEncryptionAlgorithm()->EvalMultKeysGen(keyPair.secretKey);

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

	std::vector<uint32_t> vectorOfInts1 = {5,4,3,2,1,0,5,4,3,2,1,0};
	std::vector<uint32_t> vectorOfInts2 = {2,0,0,0,0,0,0,0,0,0,0,0};
	std::vector<uint32_t> vectorOfInts3 = {2,0,0,0,0,0,0,0,0,0,0,0};
	std::vector<uint32_t> vectorOfInts4 = {2,0,0,0,0,0,0,0,0,0,0,0};
	std::vector<uint32_t> vectorOfInts5 = {2,0,0,0,0,0,0,0,0,0,0,0};
	std::vector<uint32_t> vectorOfInts6 = {1,0,0,0,0,0,0,0,0,0,0,0};

	IntPlaintextEncoding plaintext1(vectorOfInts1);
	IntPlaintextEncoding plaintext2(vectorOfInts2);
	IntPlaintextEncoding plaintext3(vectorOfInts3);
	IntPlaintextEncoding plaintext4(vectorOfInts4);
	IntPlaintextEncoding plaintext5(vectorOfInts5);
	IntPlaintextEncoding plaintext6(vectorOfInts6);

	////////////////////////////////////////////////////////////
	// Encryption
	////////////////////////////////////////////////////////////


	vector<shared_ptr<Ciphertext<Poly>>> ciphertext1;
	vector<shared_ptr<Ciphertext<Poly>>> ciphertext2;
	vector<shared_ptr<Ciphertext<Poly>>> ciphertext3;
	vector<shared_ptr<Ciphertext<Poly>>> ciphertext4;
	vector<shared_ptr<Ciphertext<Poly>>> ciphertext5;
	vector<shared_ptr<Ciphertext<Poly>>> ciphertext6;

	start = currentDateTime();

	ciphertext1 = cryptoContext->Encrypt(keyPair.publicKey, plaintext1, true);
	ciphertext2 = cryptoContext->Encrypt(keyPair.publicKey, plaintext2, true);
	ciphertext3 = cryptoContext->Encrypt(keyPair.publicKey, plaintext3, true);
	ciphertext4 = cryptoContext->Encrypt(keyPair.publicKey, plaintext4, true);
	ciphertext5 = cryptoContext->Encrypt(keyPair.publicKey, plaintext5, true);
	ciphertext6 = cryptoContext->Encrypt(keyPair.publicKey, plaintext6, true);

	finish = currentDateTime();
	diff = finish - start;
	cout << "Encryption time: " << "\t" << diff << " ms" << endl;

	////////////////////////////////////////////////////////////
	//Decryption of Ciphertext
	////////////////////////////////////////////////////////////

	IntPlaintextEncoding plaintext1Dec;
	IntPlaintextEncoding plaintext2Dec;
	IntPlaintextEncoding plaintext3Dec;
	IntPlaintextEncoding plaintext4Dec;
	IntPlaintextEncoding plaintext5Dec;
	IntPlaintextEncoding plaintext6Dec;

	start = currentDateTime();

	cryptoContext->Decrypt(keyPair.secretKey, ciphertext1, &plaintext1Dec, true);
	cryptoContext->Decrypt(keyPair.secretKey, ciphertext2, &plaintext2Dec, true);
	cryptoContext->Decrypt(keyPair.secretKey, ciphertext3, &plaintext3Dec, true);
	cryptoContext->Decrypt(keyPair.secretKey, ciphertext4, &plaintext4Dec, true);
	cryptoContext->Decrypt(keyPair.secretKey, ciphertext5, &plaintext5Dec, true);
	cryptoContext->Decrypt(keyPair.secretKey, ciphertext6, &plaintext6Dec, true);


	finish = currentDateTime();
	diff = finish - start;
	cout << "Decryption time: " << "\t" << diff << " ms" << endl;

	//std::cin.get();

	plaintext1Dec.resize(plaintext1.size());
	plaintext2Dec.resize(plaintext1.size());
	plaintext3Dec.resize(plaintext1.size());
	plaintext4Dec.resize(plaintext1.size());
	plaintext5Dec.resize(plaintext1.size());
	plaintext6Dec.resize(plaintext1.size());

	cout << "\n Original Plaintext: \n";
	cout << plaintext1 << endl;
	cout << plaintext2 << endl;
	cout << plaintext3 << endl;
	cout << plaintext4 << endl;
	cout << plaintext5 << endl;
	cout << plaintext6 << endl;

	cout << "\n Resulting Decryption of Ciphertext: \n";
	cout << plaintext1Dec << endl;
	cout << plaintext2Dec << endl;
	cout << plaintext3Dec << endl;
	cout << plaintext4Dec << endl;
	cout << plaintext5Dec << endl;
	cout << plaintext6Dec << endl;

	cout << "\n";

	////////////////////////////////////////////////////////////
	// EvalMult Operation
	////////////////////////////////////////////////////////////

	shared_ptr<Ciphertext<Poly>> ciphertextMul12;
	shared_ptr<Ciphertext<Poly>> ciphertextMul123;
	shared_ptr<Ciphertext<Poly>> ciphertextMul1234;
	shared_ptr<Ciphertext<Poly>> ciphertextMul12345;
	shared_ptr<Ciphertext<Poly>> ciphertextMul123456;

	vector<shared_ptr<Ciphertext<Poly>>> ciphertextMulVect1;
	vector<shared_ptr<Ciphertext<Poly>>> ciphertextMulVect2;
	vector<shared_ptr<Ciphertext<Poly>>> ciphertextMulVect3;
	vector<shared_ptr<Ciphertext<Poly>>> ciphertextMulVect4;
	vector<shared_ptr<Ciphertext<Poly>>> ciphertextMulVect5;

	start = currentDateTime();
	//Perform consecutive multiplications and do a keyswtiching at the end.
	ciphertextMul12     = cryptoContext->GetEncryptionAlgorithm()->EvalMult(ciphertext1[0],ciphertext2[0]);
	ciphertextMul123    = cryptoContext->GetEncryptionAlgorithm()->EvalMult(ciphertextMul12, ciphertext3[0]);
	ciphertextMul1234   = cryptoContext->GetEncryptionAlgorithm()->EvalMult(ciphertextMul123, ciphertext4[0]);
	ciphertextMul12345  = cryptoContext->GetEncryptionAlgorithm()->EvalMult(ciphertextMul1234, ciphertext5[0]);
	ciphertextMul123456 = cryptoContext->GetEncryptionAlgorithm()->EvalMultAndRelinearize(ciphertextMul12345, ciphertext6[0], evalKeys);

	ciphertextMulVect1.push_back(ciphertextMul12);
	ciphertextMulVect2.push_back(ciphertextMul123);
	ciphertextMulVect3.push_back(ciphertextMul1234);
	ciphertextMulVect4.push_back(ciphertextMul12345);
	ciphertextMulVect5.push_back(ciphertextMul123456);

	finish = currentDateTime();
	diff = finish - start;
	cout << "EvalMult time: " << "\t" << diff << " ms" << endl;

	////////////////////////////////////////////////////////////
	//Decryption after Accumulation Operation on Re-Encrypted Data
	////////////////////////////////////////////////////////////

	IntPlaintextEncoding plaintextMul1;
	IntPlaintextEncoding plaintextMul2;
	IntPlaintextEncoding plaintextMul3;
	IntPlaintextEncoding plaintextMul4;
	IntPlaintextEncoding plaintextMul5;

	start = currentDateTime();

	cryptoContext->Decrypt(keyPair.secretKey, ciphertextMulVect1, &plaintextMul1, true);
	cryptoContext->Decrypt(keyPair.secretKey, ciphertextMulVect2, &plaintextMul2, true);
	cryptoContext->Decrypt(keyPair.secretKey, ciphertextMulVect3, &plaintextMul3, true);
	cryptoContext->Decrypt(keyPair.secretKey, ciphertextMulVect4, &plaintextMul4, true);
	cryptoContext->Decrypt(keyPair.secretKey, ciphertextMulVect5, &plaintextMul5, true);

	finish = currentDateTime();
	diff = finish - start;

	//std::cin.get();

	plaintextMul1.resize(plaintext1.size());
	plaintextMul2.resize(plaintext1.size());
	plaintextMul3.resize(plaintext1.size());
	plaintextMul4.resize(plaintext1.size());
	plaintextMul5.resize(plaintext1.size());

	cout << "\n Original Plaintext: \n";
	cout << plaintext1 << endl;
	cout << plaintext2 << endl;
	cout << plaintext3 << endl;
	cout << plaintext4 << endl;
	cout << plaintext5 << endl;
	cout << plaintext6 << endl;

	cout << "\n Resulting Plaintext (after polynomial multiplication): \n";
	cout << plaintextMul1 << endl;
	cout << plaintextMul2 << endl;
	cout << plaintextMul3 << endl;
	cout << plaintextMul4 << endl;
	cout << plaintextMul5 << endl;

	cout << "\n";

	////////////////////////////////////////////////////////////
	// EvalAdd Operation
	////////////////////////////////////////////////////////////

	shared_ptr<Ciphertext<Poly>> ciphertextAdd12;
	shared_ptr<Ciphertext<Poly>> ciphertextAdd123;

	vector<shared_ptr<Ciphertext<Poly>>> ciphertextAddVect1;
	vector<shared_ptr<Ciphertext<Poly>>> ciphertextAddVect2;

	start = currentDateTime();

	ciphertextAdd12 = cryptoContext->EvalAdd(ciphertextMul12, ciphertextMul12345);
	ciphertextAdd123 = cryptoContext->EvalAdd(ciphertextAdd12, ciphertextMul123456);

	ciphertextAddVect1.push_back(ciphertextAdd12);
	ciphertextAddVect2.push_back(ciphertextAdd123);

	finish = currentDateTime();
	diff = finish - start;
	cout << "EvalAdd time: " << "\t" << diff << " ms" << endl;


	////////////////////////////////////////////////////////////
	//Decryption after Accumulation Operation
	////////////////////////////////////////////////////////////

	IntPlaintextEncoding plaintextAdd1;
	IntPlaintextEncoding plaintextAdd2;

	start = currentDateTime();

	cryptoContext->Decrypt(keyPair.secretKey, ciphertextAddVect1, &plaintextAdd1, true);
	cryptoContext->Decrypt(keyPair.secretKey, ciphertextAddVect2, &plaintextAdd2, true);

	finish = currentDateTime();
	diff = finish - start;

	//std::cin.get();

	plaintextAdd1.resize(plaintext1.size());
	plaintextAdd2.resize(plaintext1.size());

	cout << "\n Original Plaintext: \n";
	cout << plaintextMul1 << endl;
	cout << plaintextMul4 << endl;
	cout << plaintextMul5 << endl;

	cout << "\n Resulting Added Plaintext: \n";
	cout << plaintextAdd1 << endl;
	cout << plaintextAdd2 << endl;

	cout << "\n";


	////////////////////////////////////////////////////////////
	// Done
	////////////////////////////////////////////////////////////

	std::cout << "Execution Completed." << std::endl;

	return 0;
}
