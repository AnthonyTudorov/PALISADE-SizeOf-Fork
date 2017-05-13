/*
 * @file Source_json.cpp - PALISADE library.
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
 * Demo software for FV pke operations.
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

static const usint ORDER = 2048;
static const usint PTM = 256;
//double currentDateTime();

void usage()
{
	cout << "args are:" << endl;
	cout << "-dojson : includes the json tests" << endl;
}

int main(int argc, char *argv[]) {

	////////////////////////////////////////////////////////////
	// Set-up of parameters
	////////////////////////////////////////////////////////////


	cout << "\nStarting FV PKE demo in the RLWE mode" << endl;

	int relWindow = 1;
	int plaintextModulus = 64;
	double sigma = 4;
	double alpha = 9;
	double rootHermiteFactor = 1.006;

	//Set Crypto Parameters	
	
	CryptoContext<ILVector2n> cc = CryptoContextFactory<ILVector2n>::genCryptoContextFV(
			plaintextModulus, 
			rootHermiteFactor,
			relWindow, 
			sigma, 
			1, 0, 0);

/*

	bool	doJson = false;

	while( argc-- > 1 ) {
		string arg(*++argv);

		if( arg == "-dojson" )
			doJson = true;
		else if( arg == "-help" || arg == "-?" ) {
			usage();
			return 0;
		}
		else if( arg[0] == '-' ) {
			usage();
			return(0);
		}
	}

	std::cout << "Choose parameter set: ";
	CryptoContextHelper::printAllParmSetNames(std::cout);

	string input;
	std::cin >> input;

	CryptoContext<ILVector2n> cc = CryptoContextHelper::getNewContext(input);
	if( !cc ) {
		cout << "Error on " << input << endl;
		return 0;
	}
*/
	//CryptoContext<ILVector2n> cc = GenCryptoContextElementLTV(ORDER, PTM);

	//Turn on features
	cc.Enable(ENCRYPTION);
	cc.Enable(SHE);	
	cc.Enable(PRE);	

	//Generate parameters.
	double diff, start, finish;

	start = currentDateTime();

	cc.GetEncryptionAlgorithm()->ParamsGen(cc.GetCryptoParameters(), 0, 1);

	finish = currentDateTime();
	diff = finish - start;

	std::cout << "n = " << cc.GetCryptoParameters()->GetElementParams()->GetCyclotomicOrder() / 2 << std::endl;
	std::cout << "log2 q = " << log2(cc.GetCryptoParameters()->GetElementParams()->GetModulus().ConvertToDouble()) << std::endl;

	cout << "Param generation time: " << "\t" << diff << " ms" << endl;

	//std::cout << "Press any key to continue." << std::endl;
	//std::cin.get();
	
	// Initialize Public Key Containers
	LPKeyPair<ILVector2n> kp1;
	LPKeyPair<ILVector2n> kp2;

	LPKeyPair<ILVector2n> kpFusion;

	shared_ptr<LPEvalKey<ILVector2n>> evalKey1;
	shared_ptr<LPEvalKey<ILVector2n>> evalKey2;
	
	////////////////////////////////////////////////////////////
	// Perform Key Generation Operation
	////////////////////////////////////////////////////////////

	std::cout << "Running key generation (used for source data)..." << std::endl;

	start = currentDateTime();

	kp1 = cc.KeyGen();
	kp2 = cc.FusionKeyGen(kp1.publicKey);

	finish = currentDateTime();
	diff = finish - start;
	cout << "Key generation time: " << "\t" << diff << " ms" << endl;

	if( !kp1.good() ) {
		std::cout << "Key generation failed!" << std::endl;
		exit(1);
	}

	if( !kp2.good() ) {
		std::cout << "Key generation failed!" << std::endl;
		exit(1);
	}

	//std::cout << "Press any key to continue." << std::endl;
	//std::cin.get();

	////////////////////////////////////////////////////////////
	//Perform the second key generation operation.
	// This generates the keys which should be able to decrypt the ciphertext after the re-encryption operation.
	////////////////////////////////////////////////////////////

	std::cout << "Generating a fusion key..." << std::endl;

	start = currentDateTime();

	kpFusion = cc.FusionKeyGen(kp1.secretKey,kp2.secretKey);	// This is the same core key generation operation.

	finish = currentDateTime();
	diff = finish - start;
	cout << "Key generation time: " << "\t" << diff << " ms" << endl;

	if( !kpFusion.good() ) {
		std::cout << "Key generation failed!" << std::endl;
		exit(1);
	}

	//std::cout << "Press any key to continue." << std::endl;
	//std::cin.get();	

	////////////////////////////////////////////////////////////
	//Perform the proxy re-encryption key generation operation.
	// This generates the keys which are used to perform the key switching.
	////////////////////////////////////////////////////////////

	std::cout <<"\n"<< "Generating proxy re-encryption key..." << std::endl;


	start = currentDateTime();

	evalKey1 = cc.ReKeyGen(kpFusion.secretKey, kp1.secretKey);
	evalKey2 = cc.ReKeyGen(kpFusion.secretKey, kp2.secretKey);

	finish = currentDateTime();
	diff = finish - start;
	cout << "Key generation time: " << "\t" << diff << " ms" << endl;

	//std::cout << "Press any key to continue." << std::endl;
	//std::cin.get();	


	////////////////////////////////////////////////////////////
	// Encode source data
	////////////////////////////////////////////////////////////

	std::vector<uint32_t> vectorOfInts1 = {2,2,2,2,2,2,0,0,0,0,0,0};
	std::vector<uint32_t> vectorOfInts2 = {3,3,3,3,3,0,0,0,0,0,0,0};
	IntPlaintextEncoding plaintext1(vectorOfInts1);
	IntPlaintextEncoding plaintext2(vectorOfInts2);

	//std::vector<uint32_t> vectorOfIntsAdd = { 2, 1, 1, 3, 0, 0, 0, 0, 3, 0, 3, 3, 3, 3 };
	//IntPlaintextEncoding plaintextAdd(vectorOfIntsAdd);

	////////////////////////////////////////////////////////////
	// Encryption
	////////////////////////////////////////////////////////////

	std::vector<vector<shared_ptr<Ciphertext<ILVector2n>>>> numeratorCiphertextInt(100); // Defaults to zero initial value
	std::vector<vector<shared_ptr<Ciphertext<ILVector2n>>>> denominatorCiphertextInt(100); // Defaults to zero initial value

	start = currentDateTime();

	vector<shared_ptr<Ciphertext<ILVector2n>>> ciphertext1;
	vector<shared_ptr<Ciphertext<ILVector2n>>> ciphertext2;

	ciphertext1 = cc.Encrypt(kp1.publicKey, plaintext1, true);
	ciphertext2 = cc.Encrypt(kp2.publicKey, plaintext2, true);
	
	finish = currentDateTime();
	diff = finish - start;
	cout << "Encryption time: " << "\t" << diff << " ms" << endl;

	//std::cout << "Press any key to continue." << std::endl;
	//std::cin.get();

	////////////////////////////////////////////////////////////
	// Re-Encryption
	////////////////////////////////////////////////////////////


	start = currentDateTime();

	vector<shared_ptr<Ciphertext<ILVector2n>>> ciphertext1New;
	vector<shared_ptr<Ciphertext<ILVector2n>>> ciphertext2New;

	ciphertext1New = cc.ReEncrypt(evalKey1, ciphertext1);
	ciphertext2New = cc.ReEncrypt(evalKey2, ciphertext2);

	finish = currentDateTime();
	diff = finish - start;
	cout << "Re-Encryption time: " << "\t" << diff << " ms" << endl;

	//std::cout << "Press any key to continue." << std::endl;
	//std::cin.get();

	////////////////////////////////////////////////////////////
	// EvalAdd Operation on Re-Encrypted Data
	////////////////////////////////////////////////////////////

	vector<shared_ptr<Ciphertext<ILVector2n>>> ciphertextAddVectNew;
	shared_ptr<Ciphertext<ILVector2n>> ciphertextAddNew;

	start = currentDateTime();

	ciphertextAddNew = cc.EvalAdd(ciphertext1New[0],ciphertext2New[0]);

	ciphertextAddVectNew.push_back(ciphertextAddNew);

	finish = currentDateTime();
	diff = finish - start;
	cout << "Re-Encrypted Data Evaluation time: " << "\t" << diff << " ms" << endl;

	//std::cout << "Press any key to continue." << std::endl;
	//std::cin.get();

	////////////////////////////////////////////////////////////
	//Decryption after Accumulation Operation on Re-Encrypted Data
	////////////////////////////////////////////////////////////

	IntPlaintextEncoding plaintextAddNew;

	start = currentDateTime();

	DecryptResult resultNew = cc.Decrypt(kpFusion.secretKey, ciphertextAddVectNew, &plaintextAddNew, true);

	finish = currentDateTime();
	diff = finish - start;

	//std::cin.get();

	plaintextAddNew.resize(plaintext1.size());

	cout << "\n Original Plaintext: \n";
	cout << plaintext1 << endl;
	cout << plaintext2 << endl;

	cout << "\n Resulting Added Plaintext with Re-Encryption: \n";
	cout << plaintextAddNew << endl;

	cout << "\n";

	////////////////////////////////////////////////////////////
	// Done
	////////////////////////////////////////////////////////////

	std::cout << "Execution Completed. Press any key to continue." << std::endl;

	std::cin.get();

	return 0;
}
