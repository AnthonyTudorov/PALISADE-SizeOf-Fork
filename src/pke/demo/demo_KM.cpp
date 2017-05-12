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
#include "encoding/byteplaintextencoding.h"
#include "utils/debug.h"
#include "utils/serializablehelper.h"

using namespace std;
using namespace lbcrypto;

//double currentDateTime();

int main() {

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
			100, 0, 0);

	//Turn on features
	cc.Enable(ENCRYPTION);
	cc.Enable(SHE);	

	//Generate parameters.
	double diff, start, finish;

	start = currentDateTime();

	cc.GetEncryptionAlgorithm()->ParamsGen(cc.GetCryptoParameters(), 0, 1);

	finish = currentDateTime();
	diff = finish - start;

	std::cout << "n = " << cc.GetCryptoParameters()->GetElementParams()->GetCyclotomicOrder() / 2 << std::endl;
	std::cout << "log2 q = " << log2(cc.GetCryptoParameters()->GetElementParams()->GetModulus().ConvertToDouble()) << std::endl;

	cout << "Param generation time: " << "\t" << diff << " ms" << endl;

	std::cout << "Press any key to continue." << std::endl;
	std::cin.get();
	
	// Initialize Public Key Containers
	LPKeyPair<ILVector2n> kp;
	
	////////////////////////////////////////////////////////////
	// Perform Key Generation Operation
	////////////////////////////////////////////////////////////

	start = currentDateTime();

	kp = cc.KeyGen();

	finish = currentDateTime();
	diff = finish - start;
	cout << "Key generation time: " << "\t" << diff << " ms" << endl;

	if( !kp.good() ) {
		std::cout << "Key generation failed!" << std::endl;
		exit(1);
	}

	std::cout << "Press any key to continue." << std::endl;
	std::cin.get();

	////////////////////////////////////////////////////////////
	// Encode source data
	////////////////////////////////////////////////////////////


	std::vector<IntPlaintextEncoding> numeratorInts(100); // Defaults to zero initial value
	std::vector<IntPlaintextEncoding> denominatorInts(100); // Defaults to zero initial value

	ifstream file ( "mkdata.csv" ); // declare file stream: http://www.cplusplus.com/reference/iostream/ifstream/
	string value1,value2,value3;
	getline ( file, value1, ',' ); 
	getline ( file, value2, ',' ); 
	getline ( file, value3, ',' ); 
	cout << "*-" << string( value1 ) << ", " << string( value2 ) << ", " << string( value3 ) << "-*\n"; 
	getline ( file, value1, ',' ); 
	getline ( file, value2, ',' ); 
	getline ( file, value3, ',' ); 

	int i=0;

	start = currentDateTime();

	while ( file.good() )
	{
		uint32_t value1uint = (uint32_t)(atoi(value1.c_str()));
		uint32_t value2uint = (uint32_t)(atoi(value2.c_str()));
		uint32_t value3uint = (uint32_t)(atoi(value3.c_str()));
		cout << "Patient #: " << value1uint << ", Survival Time: " << value2uint << ", Not Censored: " << value3uint << "\n"; 
		getline ( file, value1, ',' ); 
		getline ( file, value2, ',' ); 
		getline ( file, value3, ',' );

		std::vector<uint32_t> vectorOfInts1 = {0,0,0,0,0,0,0,0,0,0,0,0};
		std::vector<uint32_t> vectorOfInts2 = {0,0,0,0,0,0,0,0,0,0,0,0};

		if(value3uint==1) {
			//cout << "Not Censored\n";
			for(uint32_t j=0;j<value2uint-1;j=j+1) {
				vectorOfInts1[j]=1;
				vectorOfInts2[j]=1;
			}
			vectorOfInts2[value2uint-1]=1;
			if(value2uint==12){
				vectorOfInts1[value2uint-1]=1;
			}
		} else {
			//cout << "Censored\n";
			for(uint32_t j=0;j<value2uint;j=j+1) {
				vectorOfInts1[j]=1;
				vectorOfInts2[j]=1;
			}
		}

		IntPlaintextEncoding plaintext1(vectorOfInts1);
		IntPlaintextEncoding plaintext2(vectorOfInts2);

		numeratorInts[i]= plaintext1;
		denominatorInts[i] = plaintext2;

		//cout << plaintext1 << "\n" << plaintext2 << endl;
		i=i+1;

	}

	std::vector<uint32_t> vectorOfInts1 = {0,0,0,0,0,0,0,0,0,0,0,0};
	IntPlaintextEncoding plaintext1(vectorOfInts1);

	std::vector<uint32_t> vectorOfInts2 = {0,0,0,0,0,0,0,0,0,0,0,0};
	IntPlaintextEncoding plaintext2(vectorOfInts2);

	std::vector<uint32_t> vectorOfIntsAdd = { 2, 1, 1, 3, 0, 0, 0, 0, 3, 0, 3, 3, 3, 3 };
	IntPlaintextEncoding plaintextAdd(vectorOfIntsAdd);

	////////////////////////////////////////////////////////////
	// Encryption
	////////////////////////////////////////////////////////////

	std::vector<vector<shared_ptr<Ciphertext<ILVector2n>>>> numeratorCiphertextInt(100); // Defaults to zero initial value
	std::vector<vector<shared_ptr<Ciphertext<ILVector2n>>>> denominatorCiphertextInt(100); // Defaults to zero initial value

	start = currentDateTime();

	for(uint32_t j=0;j<100;j=j+1) {
		vector<shared_ptr<Ciphertext<ILVector2n>>> ciphertext1;
		vector<shared_ptr<Ciphertext<ILVector2n>>> ciphertext2;

		plaintext1 = numeratorInts[j];
		plaintext2 = denominatorInts[j];

		ciphertext1 = cc.Encrypt(kp.publicKey, plaintext1, true);
		ciphertext2 = cc.Encrypt(kp.publicKey, plaintext2, true);

		numeratorCiphertextInt[j] = ciphertext1;
		denominatorCiphertextInt[j] = ciphertext2;		
	}

	finish = currentDateTime();
	diff = finish - start;
	cout << "Encryption time: " << "\t" << diff << " ms" << endl;

	std::cout << "Press any key to continue." << std::endl;
	std::cin.get();

	////////////////////////////////////////////////////////////
	// EvalAdd Operation
	////////////////////////////////////////////////////////////

	vector<shared_ptr<Ciphertext<ILVector2n>>> ciphertextAdd1;
	vector<shared_ptr<Ciphertext<ILVector2n>>> ciphertextAdd2;

	shared_ptr<Ciphertext<ILVector2n>> ciphertextTempAdd1;
	shared_ptr<Ciphertext<ILVector2n>> ciphertextTempAdd2;

	start = currentDateTime();

	ciphertextTempAdd1 = cc.EvalAdd(numeratorCiphertextInt[0][0], numeratorCiphertextInt[1][0]);
	ciphertextTempAdd2 = cc.EvalAdd(denominatorCiphertextInt[0][0], denominatorCiphertextInt[1][0]);

	for(uint32_t j=2;j<100;j=j+1) {	
		ciphertextTempAdd1 = cc.EvalAdd(ciphertextTempAdd1, numeratorCiphertextInt[j][0]);
		ciphertextTempAdd2 = cc.EvalAdd(ciphertextTempAdd2, denominatorCiphertextInt[j][0]);		
	}

	ciphertextAdd1.push_back(ciphertextTempAdd1);
	ciphertextAdd2.push_back(ciphertextTempAdd2);

	finish = currentDateTime();
	diff = finish - start;
	cout << "Evaluation time: " << "\t" << diff << " ms" << endl;

	std::cout << "Press any key to continue." << std::endl;
	std::cin.get();

	////////////////////////////////////////////////////////////
	//Decryption after Accumulation Operation
	////////////////////////////////////////////////////////////

	IntPlaintextEncoding plaintextNewAdd1;
	IntPlaintextEncoding plaintextNewAdd2;

	start = currentDateTime();

	DecryptResult result1 = cc.Decrypt(kp.secretKey, ciphertextAdd1, &plaintextNewAdd1, true);
	DecryptResult result2 = cc.Decrypt(kp.secretKey, ciphertextAdd2, &plaintextNewAdd2, true);

	finish = currentDateTime();
	diff = finish - start;

	//std::cin.get();

	plaintextNewAdd1.resize(plaintext1.size());
	plaintextNewAdd2.resize(plaintext2.size());

	//cout << plaintextNewAdd1 << "\n" << plaintextNewAdd2 << endl;

	std::vector<float> ratioVector = {0.0,0.0,0.0,0.0,0.0,0.0,0.0,0.0,0.0,0.0,0.0,0.0};
	std::vector<float> productVector = {0.0,0.0,0.0,0.0,0.0,0.0,0.0,0.0,0.0,0.0,0.0,0.0};

	cout << "\n\n\n\n Kaplan-Meier Survival Curve Output: \n";

	float product = 1.0;
	for(int k=0;k<12;k=k+1) {
		float ratio = (float)plaintextNewAdd1[k] / (float)plaintextNewAdd2[k];
		ratioVector[k] = ratio;
		product = product*ratio;
		productVector[k]=product;
		cout << product << " ";
	}
	cout << "\n";


	////////////////////////////////////////////////////////////
	// Done
	////////////////////////////////////////////////////////////

	std::cout << "Execution Completed. Press any key to continue." << std::endl;

	std::cin.get();

	return 0;
}
