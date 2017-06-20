/*
 * @file PrettyJson.cpp -- JSON operations in PALISADE library.
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
 *
 */


#include <iostream>
#include <fstream>
#include <string>
using namespace std;

#define RAPIDJSON_HAS_STDSTRING 1

#include "utils/serializablehelper.h"

void
usage(const string& cmd, const string& msg) {
	cout << msg << endl;
	cout << "Usage is: " << cmd << " filename1 filename2 ..." << endl;
	cout << "to read from standard input, do not specify any filenames" << endl;
}

int
main( int argc, char *argv[] )
{

	////////////////////////////////////////////////////////////
	// Set-up of parameters
	////////////////////////////////////////////////////////////

	//Generate parameters.
	double diff, start, finish;

	int relWindow = 1;
	int plaintextModulus = 1024;
	double sigma = 4;
	double rootHermiteFactor = 1.006;	

	//Set Crypto Parameters	
	CryptoContext<ILVector2n> cryptoContext = CryptoContextFactory<ILVector2n>::genCryptoContextFV(
			plaintextModulus, rootHermiteFactor, relWindow, sigma, 0, 2, 0);

	// enable features that you wish to use
	cryptoContext.Enable(ENCRYPTION);
	cryptoContext.Enable(SHE);
	
	start = currentDateTime();

	cryptoContext.GetEncryptionAlgorithm()->ParamsGen(cryptoContext.GetCryptoParameters(), 0, 2);

	finish = currentDateTime();
	diff = finish - start;

	cout << "Param generation time: " << "\t" << diff << " ms" << endl;

	std::cout << "p = " << cryptoContext.GetCryptoParameters()->GetPlaintextModulus() << std::endl;
	std::cout << "n = " << cryptoContext.GetCryptoParameters()->GetElementParams()->GetCyclotomicOrder() / 2 << std::endl;
	std::cout << "log2 q = " << log2(cryptoContext.GetCryptoParameters()->GetElementParams()->GetModulus().ConvertToDouble()) << std::endl;

	//std::cout << "Press any key to continue." << std::endl;
	//std::cin.get();
	
	// Initialize Public Key Containers
	LPKeyPair<ILVector2n> keyPair;
	
	////////////////////////////////////////////////////////////
	// Perform Key Generation Operation
	////////////////////////////////////////////////////////////

	std::cout << "Running key generation (used for source data)..." << std::endl;

	start = currentDateTime();

	keyPair = cryptoContext.KeyGen();	
	cryptoContext.EvalMultKeyGen(keyPair.secretKey);

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

	std::vector<uint32_t> vectorOfInts1 = {3,2,1,3,2,1,0,0,0,0,0,0};
	std::vector<uint32_t> vectorOfInts2 = {2,0,0,0,0,0,0,0,0,0,0,0};
	std::vector<uint32_t> vectorOfInts3 = {1,0,0,0,0,0,0,0,0,0,0,0};
	IntPlaintextEncoding plaintext1(vectorOfInts1);
	IntPlaintextEncoding plaintext2(vectorOfInts2);
	IntPlaintextEncoding plaintext3(vectorOfInts3);

	////////////////////////////////////////////////////////////
	// Encryption
	////////////////////////////////////////////////////////////


	vector<shared_ptr<Ciphertext<ILVector2n>>> ciphertext1;
	vector<shared_ptr<Ciphertext<ILVector2n>>> ciphertext2;
	vector<shared_ptr<Ciphertext<ILVector2n>>> ciphertext3;

	start = currentDateTime();

	ciphertext1 = cryptoContext.Encrypt(keyPair.publicKey, plaintext1, true);
	ciphertext2 = cryptoContext.Encrypt(keyPair.publicKey, plaintext2, true);
	ciphertext3 = cryptoContext.Encrypt(keyPair.publicKey, plaintext3, true);
	
	finish = currentDateTime();
	diff = finish - start;
	cout << "Encryption time: " << "\t" << diff << " ms" << endl;

	////////////////////////////////////////////////////////////
	//Decryption of Ciphertext
	////////////////////////////////////////////////////////////

	IntPlaintextEncoding plaintext1Dec;
	IntPlaintextEncoding plaintext2Dec;
	IntPlaintextEncoding plaintext3Dec;

	start = currentDateTime();

	cryptoContext.Decrypt(keyPair.secretKey, ciphertext1, &plaintext1Dec, true);
	cryptoContext.Decrypt(keyPair.secretKey, ciphertext2, &plaintext2Dec, true);
	cryptoContext.Decrypt(keyPair.secretKey, ciphertext3, &plaintext3Dec, true);

	finish = currentDateTime();
	diff = finish - start;
	cout << "Decryption time: " << "\t" << diff << " ms" << endl;

	//std::cin.get();

	plaintext1Dec.resize(plaintext1.size());
	plaintext2Dec.resize(plaintext1.size());
	plaintext3Dec.resize(plaintext1.size());

	cout << "\n Original Plaintext: \n";
	cout << plaintext1 << endl;
	cout << plaintext2 << endl;
	cout << plaintext3 << endl;

	cout << "\n Resulting Decryption of Ciphertext: \n";
	cout << plaintext1Dec << endl;
	cout << plaintext2Dec << endl;
	cout << plaintext3Dec << endl;

	cout << "\n";

	////////////////////////////////////////////////////////////
	// EvalAdd Operation
	////////////////////////////////////////////////////////////

	shared_ptr<Ciphertext<ILVector2n>> ciphertextAdd12;
	shared_ptr<Ciphertext<ILVector2n>> ciphertextAdd123;

	vector<shared_ptr<Ciphertext<ILVector2n>>> ciphertextAddVect;

	start = currentDateTime();

	ciphertextAdd12 = cryptoContext.EvalAdd(ciphertext1[0],ciphertext2[0]);
	ciphertextAdd123 = cryptoContext.EvalAdd(ciphertextAdd12,ciphertext3[0]);

	ciphertextAddVect.push_back(ciphertextAdd123);

	finish = currentDateTime();
	diff = finish - start;
	cout << "Re-Encrypted Data Evaluation time: " << "\t" << diff << " ms" << endl;


	////////////////////////////////////////////////////////////
	//Decryption after Accumulation Operation
	////////////////////////////////////////////////////////////

	IntPlaintextEncoding plaintextAdd;

	start = currentDateTime();

	cryptoContext.Decrypt(keyPair.secretKey, ciphertextAddVect, &plaintextAdd, true);

	finish = currentDateTime();
	diff = finish - start;

	//std::cin.get();

	plaintextAdd.resize(plaintext1.size());

	cout << "\n Original Plaintext: \n";
	cout << plaintext1 << endl;
	cout << plaintext2 << endl;
	cout << plaintext3 << endl;

	cout << "\n Resulting Added Plaintext with Re-Encryption: \n";
	cout << plaintextAdd << endl;

	cout << "\n";



	istream *br = &cin;
	ifstream fil;

	if( argc > 1 && string(argv[1]) == "-help" ) {
		usage(argv[0], "");
		return 0;
	}

	for( int i = 1; i <= argc; i++ ) {
		if( argc > 1 ) {
			fil.open(argv[i]);
			if( !fil.is_open() ) {
				cout << "File '" << argv[i] << "' could not be opened, skipping" << endl;
				continue;
			}

			br = &fil;
		}

		// set up to read from br and write to stdout

		lbcrypto::IStreamWrapper is(*br);

		rapidjson::Document doc;

		while( br->good() ) {
			lbcrypto::OStreamWrapper oo(cout);
			rapidjson::PrettyWriter<lbcrypto::OStreamWrapper> ww(oo);

			doc.ParseStream<rapidjson::kParseStopWhenDoneFlag>(is);

			if( !br->good() )
				break;

			if( doc.HasParseError() && doc.GetParseError() != rapidjson::kParseErrorDocumentEmpty ) {
				cout << "Parse error " << doc.GetParseError() << " at " << doc.GetErrorOffset() << endl;
				break;
			}

			doc.Accept(ww);
			cout << endl;
		}

		fil.close();
	}

	return 0;
}
