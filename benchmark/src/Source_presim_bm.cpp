//High-level Execution/Demonstration
/*
PRE SCHEME PROJECT, Crypto Lab, NJIT
Version:
v00.01
Last Edited:
6/17/2015 4:37AM
List of Authors:
TPOC:
Dr. Kurt Rohloff, rohloff@njit.edu
Programmers:
Dr. Yuriy Polyakov, polyakov@njit.edu
Gyana Sahu, grs22@njit.edu
Description:
This code exercises the Proxy Re-Encryption capabilities of the NJIT Lattice crypto library.
In this code we:
- Generate a key pair.
- Encrypt a string of data.
- Decrypt the data.
- Generate a new key pair.
- Generate a proxy re-encryption key.
- Re-Encrypt the encrypted data.
- Decrypt the re-encrypted data.
We configured parameters (namely the ring dimension and ciphertext modulus) to provide a level of security roughly equivalent to a root hermite factor of 1.007 which is generally considered secure and conservatively comparable to AES-128 in terms of computational work factor and may be closer to AES-256.

Additionally we excercise the gnu benchmark library

License Information:

Copyright (c) 2015, New Jersey Institute of Technology (NJIT)
All rights reserved.
Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:
1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

*/

#define _USE_MATH_DEFINES 
#include <iostream>
#include <fstream>
#include "lib/crypto/cryptocontext.h"
#include "lib/utils/cryptocontexthelper.h"
#include "lib/crypto/cryptocontext.cpp"
#include "lib/utils/cryptocontexthelper.cpp"

#include "lib/math/nbtheory.h"

#include "lib/math/distrgen.h"

#include "lib/lattice/ilvector2n.h"
#include "lib/lattice/ilvectorarray2n.h"

#include "lib/utils/debug.h"
#include <vector>


using namespace std;
using namespace lbcrypto;

//double currentDateTime();

const usint NUMBER_OF_RUNS = 100;

//defination of input parameters for 
struct SecureParams {
	usint m;
	BigBinaryInteger modulus;
	BigBinaryInteger rootOfUnity;
	usint relinWindow;
	usint depth;
	usint bitLength;
};

//routine to check decryption correctness for 5,000 runs of the LTV scheme w/o re-encryption; computes the number of errors
void EncryptionSchemeSimulation(usint count);

//performance evaluation for single-reencryption case; computes encryption, decryption, and re-encryption times averaged for 100 runs
void PRESimulation(usint count, usint dataset);

int main() {
        cout<<"Note we have not yet implemented the benchmark for this code."
	    << endl;
	//EncryptionSchemeSimulation(100);
	PRESimulation(100,0);

	cout << "Press any key to continue..." << endl;
	cin.get();

	return 0;
}

void EncryptionSchemeSimulation(usint count){

	ifstream ptextFile("n_sample.txt");

	if (ptextFile.bad()){
		std::cout << "failed to open file with plaintext" << std::endl;
		std::cin.get();
	}

	string x;
	ptextFile >> x;

	//file with input parameters
	ifstream dataFile("inp_data.txt");

	if (dataFile.bad()){
		std::cout << "failed to open file with parameters" << std::endl;
		std::cin.get();
	}

	//string modulus
	string mod;
	string rUnity;

	//Load sets of params for different ring dimensions
	SecureParams data[10];
	usint i = 0;

	while (!dataFile.eof()){

		dataFile >> data[i].m;
		//cout << "m = " <<data[i].m << endl;
		dataFile >> mod;
		data[i].modulus.SetValue(mod);
		//cout<<"modulus = "<<data[i].modulus<<endl;
		dataFile >> rUnity;
		data[i].rootOfUnity.SetValue(rUnity);
		//cout <<"root of unity = "<<data[i].rootOfUnity << endl;

		i++;
	}

	i = 0;

	ofstream fout;
	fout.open("decryptioncheck_" + std::to_string(data[i].m) + ".txt");

	//for each dataset we run NTRUPRE for j iterations and check if there is any error or not
	//for (usint i = 0; i<7; i++){

	//prepare the parameters
	usint n = data[i].m / 2;
	usint m = data[i].m;
	BigBinaryInteger modulus(data[i].modulus);
	BigBinaryInteger rootOfUnity(data[i].rootOfUnity);
	usint relWindow = 1;

	ILParams ilParams(m, modulus, rootOfUnity);

	int stdDev = 4;

	//Set crypto parametes
	LPCryptoParametersLTV<ILVector2n> cryptoParams;
	cryptoParams.SetPlaintextModulus(BigBinaryInteger::TWO);  	// Set plaintext modulus.
	cryptoParams.SetDistributionParameter(stdDev);			// Set the noise parameters.
	cryptoParams.SetRelinWindow(relWindow);				// Set the relinearization window
	cryptoParams.SetElementParams(ilParams);			// Set the initialization parameters.

	DiscreteGaussianGenerator dgg(stdDev);				// Create the noise generator
	cryptoParams.SetDiscreteGaussianGenerator(dgg);

	//Precomputations for FTT
	ChineseRemainderTransformFTT::GetInstance().PreCompute(rootOfUnity, m, modulus);

	//Precomputations for DGG
	ILVector2n::PreComputeDggSamples(dgg, ilParams);

	//prepare the plaintext
	ByteArray plaintext;
	ifstream txt("n_sample.txt");
	std::string all;
	txt >> all;
	txt.close();

	while ((all.length() < n)){
		all = all + all;
	}

	plaintext = all.substr(0, n / 8);

	usint errorCount = 0;

	double diff, start, finish;

	start = currentDateTime();

	for (usint j = 0; j<count; j++){

		// Initialize the public key containers.
		LPPublicKeyLTV<ILVector2n> pk(cryptoParams);
		LPPrivateKeyLTV<ILVector2n> sk(cryptoParams);

		//Regular LWE-NTRU encryption algorithm
		LPAlgorithmLTV<ILVector2n> algorithm;

		bool successKeyGen = false;
		successKeyGen = algorithm.KeyGen(&pk, &sk);	// This is the core function call that generates the keys.

		if (!successKeyGen) {
			std::cout << "Key generation failed!" << std::endl;
			exit(1);
		}

		Ciphertext<ILVector2n> ciphertext;
		ByteArrayPlaintextEncoding ptxt(plaintext);

		algorithm.Encrypt(pk, ptxt, &ciphertext);	// This is the core encryption operation.

		ByteArrayPlaintextEncoding plaintextNew;

		DecryptResult result = algorithm.Decrypt(sk, ciphertext, &plaintextNew);  // This is the core decryption operation.

		if (!result.isValid) {
			std::cout << "Decryption failed!" << std::endl;
			exit(1);
		}

		if (plaintext != plaintextNew.GetData())
			errorCount++;

		//cout << plaintextNew.GetData() << endl;

	}

	finish = currentDateTime();
	diff = finish - start;

	fout << "Total computation time: " << "\t" << diff << " ms" << endl;

	fout << "m = " << data[i].m << "; modulus = " << data[i].modulus << endl;
	fout << "error count = " << errorCount << endl;

	fout.close();

	//cleans up precomputed samples
	ILVector2n::DestroyPreComputedSamples();

	//}
	ptextFile.close();

	ChineseRemainderTransformFTT::GetInstance().Destroy();
	NumberTheoreticTransform::GetInstance().Destroy();

}


void PRESimulation(usint count, usint dataset){

	//PLAINTEXT FILE HANDLING
	//open the file with plaintext
	ifstream ptextFile("n_sample.txt");

	if (!ptextFile){
		std::cout << "failed to open file with plaintext (n_sample.txt)" << std::endl;
		std::cin.get();
		return;
	}

	string ptext;
	ptextFile >> ptext;

	//PARAMETER FILE HANDLING
	//file with input parameters
	ifstream dataFile("inp_data_1pre.txt");

	if (!dataFile){
		std::cout << "failed to open file with parameters (inp_data_1pre.txt)" << std::endl;
		std::cin.get();
		return;
	}

	//string modulus
	string mod;
	string rUnity;

	//Load sets of params for different ring dimensions
	SecureParams data[50];
	usint i = 0;

	while (!dataFile.eof()){

		dataFile >> data[i].m;
		dataFile >> mod;
		data[i].modulus.SetValue(mod);
		dataFile >> rUnity;
		data[i].rootOfUnity.SetValue(rUnity);
		dataFile >> data[i].relinWindow;
		dataFile >> data[i].depth;
		dataFile >> data[i].bitLength;

		i++;

	}

	//which parameters dataset
	i = dataset;

	ofstream fout;

	#if MATHBACKEND == 1
		fout.open("singlepreperformance_m_" + std::to_string(data[i].m) + "_d_" + std::to_string(data[i].depth) + 
			"_r_" + std::to_string(data[i].relinWindow) + "_len_" + std::to_string(data[i].bitLength) + 
			"_BBIBITLENGTH_" + std::to_string(cpu8bit::BIT_LENGTH) +  ".txt");
	#endif
	#if MATHBACKEND == 2
		fout.open("singlepreperformance_m_" + std::to_string(data[i].m) + "_d_" + std::to_string(data[i].depth) + 
			"_r_" + std::to_string(data[i].relinWindow) + "_len_" + std::to_string(data[i].bitLength) + 
			 ".txt");
	#endif

	//POPULATE THE PARAMETERS AND PERFORM PRE-COMPUTATIONS
	//prepare the parameters
	usint n = data[i].m / 2;
	usint m = data[i].m;
	BigBinaryInteger modulus(data[i].modulus);
	BigBinaryInteger rootOfUnity(data[i].rootOfUnity);
	usint relWindow = data[i].relinWindow;
	usint depth = data[i].depth;

	ILParams ilParams(m, modulus, rootOfUnity);

	int stdDev = 4;

	// Set crypto parametes
	LPCryptoParametersLTV<ILVector2n> cryptoParams;
	cryptoParams.SetPlaintextModulus(BigBinaryInteger::TWO); // Set plaintext modulus.
	cryptoParams.SetDistributionParameter(stdDev);			 // Set the noise parameters.
	cryptoParams.SetRelinWindow(relWindow);				     // Set the relinearization window
	cryptoParams.SetElementParams(ilParams);			     // Set the initialization parameters.

	DiscreteGaussianGenerator dgg(stdDev);				 // Create the noise generator
	cryptoParams.SetDiscreteGaussianGenerator(dgg);

	// Precomputations for FTT
	ChineseRemainderTransformFTT::GetInstance().PreCompute(rootOfUnity, m, modulus);

	// Precomputations for DGG
	ILVector2n::PreComputeDggSamples(dgg, ilParams);

	// prepare the plaintext
	ByteArray plaintext;
	ifstream txt("n_sample.txt");
	std::string all;
	txt >> all;
	txt.close();

	while ((all.length() < n)){
		all = all + all;
	}

	//GENERATE THE KEYS

	//LWE-NTRU encryption/pre-encryption algorithm instance
	std::bitset<FEATURESETSIZE> mask (std::string("000011"));
	LPPublicKeyEncryptionSchemeLTV<ILVector2n> algorithm(mask);

	std::vector<LPPublicKeyLTV<ILVector2n>*> publicKeys;
	std::vector<LPPrivateKeyLTV<ILVector2n>*> privateKeys;
	std::vector<LPEvalKeyLTV<ILVector2n>*> evalKeys;

	// Initialize the public key containers.
	LPPublicKeyLTV<ILVector2n> pk(cryptoParams);
	LPPrivateKeyLTV<ILVector2n> sk(cryptoParams);

	bool successKeyGen = false;
	successKeyGen = algorithm.KeyGen(&pk, &sk);	// This is the core function call that generates the keys.

	if (!successKeyGen) {
		std::cout << "Key generation failed!" << std::endl;
		exit(1);
	}

	publicKeys.push_back(&pk);
	privateKeys.push_back(&sk);

	for (usint d = 0; d < depth; d++){

		LPPublicKeyLTV<ILVector2n> *newPK;
		LPPrivateKeyLTV<ILVector2n> *newSK;
		LPEvalKeyLTV<ILVector2n> *evalKey;

		newPK = new LPPublicKeyLTV<ILVector2n>(cryptoParams);
		newSK = new LPPrivateKeyLTV<ILVector2n>(cryptoParams);
		evalKey = new LPEvalKeyLTV<ILVector2n>(cryptoParams);

		successKeyGen = algorithm.KeyGen(newPK, newSK);	// This is the same core key generation operation.

		algorithm.EvalKeyGen(*newPK, *privateKeys[d], evalKey);  // This is the core re-encryption operation.

		publicKeys.push_back(newPK);
		privateKeys.push_back(newSK);
		evalKeys.push_back(evalKey);

	}

	double diff, start, finish;

	//all expensive operations are moved outside the loop

	ByteArray arrPlaintext[NUMBER_OF_RUNS];
	Ciphertext<ILVector2n> arrCiphertext[NUMBER_OF_RUNS];

	for (usint j = 0; j < count; j++){
		arrPlaintext[j] = all.substr(j*(n / 8), n / 8);
	}

	start = currentDateTime();

	for (usint j = 0; j < count; j++){

		ByteArrayPlaintextEncoding ptxt(arrPlaintext[j]);

		algorithm.Encrypt(pk, ptxt, &arrCiphertext[j]);	// This is the core encryption operation.

	}

	finish = currentDateTime();
	diff = finish - start;

	cout << "Average encryption time: " << "\t" << diff/100 << " ms" << endl;
	fout << "Average encryption time: " << "\t" << diff/100 << " ms" << endl;

	usint errorcounter = 0;

	ByteArrayPlaintextEncoding plaintextNew[NUMBER_OF_RUNS];

	//decryption loop

	start = currentDateTime();

	for (usint j = 0; j < count; j++){

		DecryptResult result = algorithm.Decrypt(sk,arrCiphertext[j],&plaintextNew[j]);  // This is the core decryption operation.

	}

	finish = currentDateTime();
	diff = finish - start;

	cout << "Average decryption time: " << "\t" << diff/100 << " ms" << endl;
	fout << "Average decryption time: " << "\t" << diff/100 << " ms" << endl;

	//decryption checking loop

	for (usint j = 0; j < count; j++){

		if (plaintextNew[j].GetData() != arrPlaintext[j])
			errorcounter++;
	}

	cout << "Number of decryption errors: " << "\t" << errorcounter << endl;
	fout << "Number of decryption errors: " << "\t" << errorcounter << endl;

	Ciphertext<ILVector2n> arrCiphertextNew[NUMBER_OF_RUNS];

	//computing re-encryption time

	for (usint d = 0; d < depth; d++){

		start = currentDateTime();

		for (usint j = 0; j < count; j++){

			algorithm.ReEncrypt(*evalKeys[d], arrCiphertext[j],&arrCiphertextNew[j]); 

		}

		finish = currentDateTime();
		diff = finish - start;

		cout << "Average re-encryption time for step " + std::to_string(d+1) + ": " << "\t" << diff/100 << " ms" << endl;
		fout << "Average re-encryption time for step " + std::to_string(d+1) + ": " << "\t" << diff/100 << " ms" << endl;

		for (usint j = 0; j < count; j++){

			arrCiphertext[j] = arrCiphertextNew[j];

		}

	}

	//decryption loop

	start = currentDateTime();

	for (usint j = 0; j < count; j++){

		DecryptResult result = algorithm.Decrypt(*privateKeys.back(),arrCiphertextNew[j],&plaintextNew[j]);  // This is the core decryption operation.

	}

	finish = currentDateTime();
	diff = finish - start;

	cout << "Average decryption time (after re-encryption): " << "\t" << diff/100 << " ms" << endl;
	fout << "Average decryption time (after re-encryption): " << "\t" << diff/100 << " ms" << endl;

	//decryption checking loop

	errorcounter = 0;

	for (usint j = 0; j < count; j++){

		if (plaintextNew[j].GetData() != arrPlaintext[j])
			errorcounter++;
	}

	cout << "Number of decryption errors: " << "\t" << errorcounter << endl;
	fout << "Number of decryption errors: " << "\t" << errorcounter << endl;

	//Extra round of encryption/decryption for troubleshooting purposes
	//STARTS HERE

	//Ciphertext<ILVector2n> arrCiphertext1[NUMBER_OF_RUNS];

	//start = currentDateTime();

	//for (usint j = 0; j < count; j++){

	//	ByteArrayPlaintextEncoding ptxt(arrPlaintext[j]);

	//	algorithm.Encrypt(pk, dgg, ptxt, &arrCiphertext1[j]);	// This is the core encryption operation.

	//}

	//finish = currentDateTime();
	//diff = finish - start;

	//cout << "Average encryption time: " << "\t" << diff/100 << " ms" << endl;
	//fout << "Average encryption time: " << "\t" << diff/100 << " ms" << endl;

	////decryption loop

	//start = currentDateTime();

	//for (usint j = 0; j < count; j++){

	//	DecryptResult result = algorithm.Decrypt(sk,arrCiphertext1[j],&plaintextNew[j]);  // This is the core decryption operation.

	//}

	//finish = currentDateTime();
	//diff = finish - start;

	//cout << "Average decryption time: " << "\t" << diff/100 << " ms" << endl;
	//fout << "Average decryption time: " << "\t" << diff/100 << " ms" << endl;

	////decryption checking loop

	//for (usint j = 0; j < count; j++){

	//	ByteArrayPlaintextEncoding ptxt(arrPlaintext[j]);

	//	if (plaintextNew[j].GetData().substr(0,n/8) != ptxt.GetData().substr(0,n/8))
	//		errorcounter++;
	//}

	//cout << "Number of decryption errors: " << "\t" << errorcounter << endl;
	//fout << "Number of decryption errors: " << "\t" << errorcounter << endl;

	// ENDS HERE

	fout.close();

	//cleans up precomputed samples
	ILVector2n::DestroyPreComputedSamples();

	ptextFile.close();

	ChineseRemainderTransformFTT::GetInstance().Destroy();
	NumberTheoreticTransform::GetInstance().Destroy();

}

// double currentDateTime()
// {

// 	std::chrono::time_point<std::chrono::system_clock> now = std::chrono::system_clock::now();

// 	time_t tnow = std::chrono::system_clock::to_time_t(now);
// 	tm *date = localtime(&tnow);
// 	date->tm_hour = 0;
// 	date->tm_min = 0;
// 	date->tm_sec = 0;

// 	auto midnight = std::chrono::system_clock::from_time_t(mktime(date));

// 	return std::chrono::duration <double, std::milli>(now - midnight).count();
// }
