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

License Information:

Copyright (c) 2015, New Jersey Institute of Technology (NJIT)
All rights reserved.
Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:
1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

*/

#include <iostream>
#include <fstream>

#include "../lib/palisade.h"
#include "../lib/palisadespace.h"

#include "../../lib/crypto/cryptocontext.cpp"
#include "../../lib/utils/cryptocontexthelper.h"
#include "../../lib/utils/cryptocontexthelper.cpp"

#include "../../lib/encoding/byteplaintextencoding.h"
#include "../../lib/utils/cryptoutility.h"
#include "../../lib/utils/debug.h"
#include <vector>


using namespace std;
using namespace lbcrypto;

//double currentDateTime();

const usint NUMBER_OF_RUNS = 100;

//defination of input parameters for 
struct SecureParams {
	usint m;
	string modulus;
	string rootOfUnity;
	usint relinWindow;
	usint depth;
	usint bitLength;
};

//routine to check decryption correctness for 5,000 runs of the LTV scheme w/o re-encryption; computes the number of errors
void EncryptionSchemeSimulation(usint count);

//performance evaluation for single-reencryption case; computes encryption, decryption, and re-encryption times averaged for 100 runs
void PRESimulation(usint count, usint dataset);

int main() {

	//EncryptionSchemeSimulation(100);
	PRESimulation(100,0);

	std::cout<<"Press any key to continue..."<<std::endl;
	std::cin.get();

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

	//Load sets of params for different ring dimensions
	SecureParams data[10];
	usint i = 0;

	while (!dataFile.eof()){

		dataFile >> data[i].m;
		dataFile >> data[i].modulus;
		dataFile >> data[i].rootOfUnity;

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

	// Create crypto context
	CryptoContext<ILVector2n> cc = CryptoContextFactory<ILVector2n>::genCryptoContextLTV(2,m,data[i].modulus,data[i].rootOfUnity,relWindow,stdDev);

	//Precomputations for FTT
	ChineseRemainderTransformFTT::GetInstance().PreCompute(rootOfUnity, m, modulus);

	//Precomputations for DGG
	ILVector2n::PreComputeDggSamples(cc.GetGenerator(), ilParams);

	//prepare the plaintext
	BytePlaintextEncoding plaintext;
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

		bool successKeyGen = false;
		LPKeyPair<ILVector2n> kp = cc.KeyGen();

		if (!successKeyGen) {
			std::cout << "Key generation failed!" << std::endl;
			exit(1);
		}

		vector<shared_ptr<Ciphertext<ILVector2n>>> ciphertext =
				cc.Encrypt(kp.publicKey, plaintext);

		BytePlaintextEncoding plaintextNew;

		DecryptResult result = CryptoUtility<ILVector2n>::Decrypt(cc.GetEncryptionAlgorithm(), *kp.secretKey, ciphertext, &plaintextNew);  // This is the core decryption operation.

		if (!result.isValid) {
			std::cout << "Decryption failed!" << std::endl;
			exit(1);
		}

		if (plaintext != plaintextNew)
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
		dataFile >> data[i].modulus;
		dataFile >> data[i].rootOfUnity;
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

	CryptoContext<ILVector2n> cc = CryptoContextFactory<ILVector2n>::genCryptoContextLTV(2,m,data[i].modulus,data[i].rootOfUnity,relWindow,stdDev);

	// Precomputations for FTT
	ChineseRemainderTransformFTT::GetInstance().PreCompute(rootOfUnity, m, modulus);

	// Precomputations for DGG
	ILVector2n::PreComputeDggSamples(dgg, ilParams);

	// prepare the plaintext
	BytePlaintextEncoding plaintext;
	ifstream txt("n_sample.txt");
	std::string all;
	txt >> all;
	txt.close();

	while ((all.length() < n)){
		all = all + all;
	}

	//GENERATE THE KEYS

	//LWE-NTRU encryption/pre-encryption algorithm instance
	//LPAlgorithmPRELTV<ILVector2n> algorithm;
	std::bitset<FEATURESETSIZE> mask (std::string("000011"));
	LPPublicKeyEncryptionSchemeLTV<ILVector2n> algorithm(mask);

	std::vector<shared_ptr<LPPublicKey<ILVector2n>>> publicKeys;
	std::vector<shared_ptr<LPPrivateKey<ILVector2n>>> privateKeys;
	std::vector<shared_ptr<LPEvalKey<ILVector2n>>> evalKeys;

	// Initialize the public key containers.

	bool successKeyGen = false;
	LPKeyPair<ILVector2n> kp = cc.KeyGen();	// This is the core function call that generates the keys.

	if (!successKeyGen) {
		std::cout << "Key generation failed!" << std::endl;
		exit(1);
	}

	publicKeys.push_back(kp.publicKey);
	privateKeys.push_back(kp.secretKey);

	for (usint d = 0; d < depth; d++){

		LPKeyPair<ILVector2n> newKp = cc.KeyGen();

		shared_ptr<LPEvalKey<ILVector2n>> evalKey = cc.ReKeyGen(newKp.publicKey, privateKeys[d]);

		publicKeys.push_back(newKp.publicKey);
		privateKeys.push_back(newKp.secretKey);
		evalKeys.push_back(evalKey);

	}

	double diff, start, finish;

	//all expensive operations are moved outside the loop

	BytePlaintextEncoding arrPlaintext[NUMBER_OF_RUNS];
	shared_ptr<Ciphertext<ILVector2n>> arrCiphertext[NUMBER_OF_RUNS];

	for (usint j = 0; j < count; j++){
		arrPlaintext[j] = all.substr(j*(n / 8), n / 8);
	}

	start = currentDateTime();

	for (usint j = 0; j < count; j++) {

		vector<shared_ptr<Ciphertext<ILVector2n>>> ciphertext = cc.Encrypt(kp.publicKey, arrPlaintext[j]);
		arrCiphertext[j] = ciphertext[0];

	}

	finish = currentDateTime();
	diff = finish - start;

	cout << "Average encryption time: " << "\t" << diff/100 << " ms" << endl;
	fout << "Average encryption time: " << "\t" << diff/100 << " ms" << endl;

	usint errorcounter = 0;

	BytePlaintextEncoding plaintextNew[NUMBER_OF_RUNS];

	//decryption loop

	start = currentDateTime();

	for (usint j = 0; j < count; j++){

		vector<shared_ptr<Ciphertext<ILVector2n>>> ct;
		ct.push_back(arrCiphertext[j]);
		DecryptResult result = CryptoUtility<ILVector2n>::Decrypt(algorithm, *kp.secretKey, ct, &plaintextNew[j]);
		ct.clear();

	}

	finish = currentDateTime();
	diff = finish - start;

	cout << "Average decryption time: " << "\t" << diff/100 << " ms" << endl;
	fout << "Average decryption time: " << "\t" << diff/100 << " ms" << endl;

	//decryption checking loop

	for (usint j = 0; j < count; j++){

		if (plaintextNew[j] != arrPlaintext[j])
			errorcounter++;
	}

	cout << "Number of decryption errors: " << "\t" << errorcounter << endl;
	fout << "Number of decryption errors: " << "\t" << errorcounter << endl;

	shared_ptr<Ciphertext<ILVector2n>> arrCiphertextNew[NUMBER_OF_RUNS];

	//computing re-encryption time

	for (usint d = 0; d < depth; d++){

		start = currentDateTime();

		for (usint j = 0; j < count; j++){
			vector<shared_ptr<Ciphertext<ILVector2n>>> ct;
			ct.push_back(arrCiphertext[j]);
			vector<shared_ptr<Ciphertext<ILVector2n>>> ctR;

			CryptoUtility<ILVector2n>::ReEncrypt(cc.GetEncryptionAlgorithm(), *evalKeys[d], ct, &ctR);
			arrCiphertextNew[j] = ctR[0];
			ct.clear();
			ctR.clear();

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

		vector<shared_ptr<Ciphertext<ILVector2n>>> ct;
		ct.push_back(arrCiphertextNew[j]);
		DecryptResult result = CryptoUtility<ILVector2n>::Decrypt(algorithm, *privateKeys.back(), ct, &plaintextNew[j]);
		ct.clear();
	}

	finish = currentDateTime();
	diff = finish - start;

	cout << "Average decryption time (after re-encryption): " << "\t" << diff/100 << " ms" << endl;
	fout << "Average decryption time (after re-encryption): " << "\t" << diff/100 << " ms" << endl;

	//decryption checking loop

	errorcounter = 0;

	for (usint j = 0; j < count; j++){

		if (plaintextNew[j] != arrPlaintext[j])
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
