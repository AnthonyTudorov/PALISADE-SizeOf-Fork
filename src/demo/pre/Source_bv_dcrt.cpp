//Hi Level Execution/Demonstration
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

#include "../../lib/crypto/cryptocontext.h"
#include "../../lib/utils/cryptocontexthelper.h"
#include "../../lib/crypto/cryptocontext.cpp"
#include "../../lib/utils/cryptocontexthelper.cpp"

#include "../../lib/encoding/byteplaintextencoding.h"
#include "../../lib/encoding/intplaintextencoding.h"
#include "../../lib/utils/cryptoutility.h"

#include "../../lib/utils/debug.h"

using namespace std;
using namespace lbcrypto;
void EncryptionTest();
//double currentDateTime();

/**
 * @brief Input parameters for PRE example.
 */
struct SecureParams {
	usint m;			///< The ring parameter.
	BigBinaryInteger modulus;	///< The modulus
	BigBinaryInteger rootOfUnity;	///< The rootOfUnity
	usint relinWindow;		///< The relinearization window parameter.
};

#include <iterator>

int main() {

	////NTRUPRE is where the core functionality is provided.
	EncryptionTest();
	//NTRUPRE(3);
	
	std::cin.get();
	ChineseRemainderTransformFTT::GetInstance().Destroy();
	NumberTheoreticTransform::GetInstance().Destroy();

	return 0;
}




void EncryptionTest() {
	
	usint m = 8;
	

	//BytePlaintextEncoding plaintext("NJIT_CRYPTOGRAPHY_LABORATORY_IS_DEVELOPING_NEW-NTRU_LIKE_PROXY_REENCRYPTION_SCHEME_USING_LATTICE_BASED_CRYPTOGRAPHY_ABCDEFGHIJKL");
	//BytePlaintextEncoding plaintext("NJIT_CRYPTOGRAPHY_LABORATORY_IS_DEVELOPING_NEW-NTRU_LIKE_PROXY_REENCRYPTION_SCHEME_USING_LATTICE_BASED_CRYPTOGRAPHY_ABCDEFGHIJKLNJIT_CRYPTOGRAPHY_LABORATORY_IS_DEVELOPING_NEW-NTRU_LIKE_PROXY_REENCRYPTION_SCHEME_USING_LATTICE_BASED_CRYPTOGRAPHY_ABCDEFGHIJKL");

	usint numOfTower = 20;

	float stdDev = 4;

	std::vector<BigBinaryInteger> moduli(numOfTower);

	std::vector<BigBinaryInteger> rootsOfUnity(numOfTower);

	BigBinaryInteger q("50000");
	BigBinaryInteger temp;
	BigBinaryInteger modulus("1");

	for (int j = 0; j < numOfTower; j++) {
		lbcrypto::NextQ(q, BigBinaryInteger::TWO, m, BigBinaryInteger("4"), BigBinaryInteger("4"));
		moduli[j] = q;
		rootsOfUnity[j] = RootOfUnity(m, moduli[j]);
		modulus = modulus* moduli[j];
		std::cout << "modulus is: " << moduli[j] << std::endl;
		std::cout << "rootsOfUnity is: " << rootsOfUnity[j] << std::endl;
	}


	std::cout << " \nCryptosystem initialization: Performing precomputations..." << std::endl;

	DiscreteGaussianGenerator dgg(stdDev);

	//Prepare for parameters.
	ILDCRTParams params(m, moduli, rootsOfUnity);

	//Set crypto parametes
	LPCryptoParametersBV<ILVectorArray2n> cryptoParams;
	cryptoParams.SetPlaintextModulus(BigBinaryInteger("5"));  	// Set plaintext modulus.
	//cryptoParams.SetPlaintextModulus(BigBinaryInteger("4"));  	// Set plaintext modulus.
	cryptoParams.SetDistributionParameter(stdDev);			// Set the noise parameters.
	cryptoParams.SetRelinWindow(8);				// Set the relinearization window
	cryptoParams.SetElementParams(params);			// Set the initialization parameters.
	cryptoParams.SetDiscreteGaussianGenerator(dgg);

	//This code is run only when performing execution time measurements

	//Precomputations for FTT
	ChineseRemainderTransformFTT::GetInstance().PreCompute(rootsOfUnity, m, moduli);

	//Precomputations for DGG
	//ILVector2n::PreComputeDggSamples(dgg, params);


	// Initialize the public key containers.
	LPPublicKey<ILVectorArray2n> pk(cryptoParams);
	LPPrivateKey<ILVectorArray2n> sk(cryptoParams);

	//Regular LWE-NTRU encryption algorithm

	////////////////////////////////////////////////////////////
	//Perform the key generation operation.
	////////////////////////////////////////////////////////////

	//LPAlgorithmLTV<ILVector2n> algorithm;

	std::vector<usint> vectorOfInts1 = { 4,0,0,0 };

	IntPlaintextEncoding intArray1(vectorOfInts1);


	LPPublicKeyEncryptionSchemeBV<ILVectorArray2n> algorithm;
	algorithm.Enable(ENCRYPTION);
	algorithm.Enable(PRE);

	bool successKeyGen = false;

	std::cout <<"\n" <<  "Running key generation..." << std::endl;


	successKeyGen = algorithm.KeyGen(&pk,&sk);	// This is the core function call that generates the keys.


	//fout<< currentDateTime()  << " pk = "<<pk.GetPublicElement().GetValues()<<endl;
	//fout<< currentDateTime()  << " sk = "<<sk.GetPrivateElement().GetValues()<<endl;

	if (!successKeyGen) {
		std::cout<<"Key generation failed!"<<std::endl;
		exit(1);
	}

	////////////////////////////////////////////////////////////
	//Encryption
	////////////////////////////////////////////////////////////

	// Begin the initial encryption operation.
	//cout<<"\n"<<"original plaintext: "<< intArray1 <<"\n"<<endl;

	vector<Ciphertext<ILVectorArray2n>> ciphertext;

	std::cout << "Running encryption..." << std::endl;

	CryptoUtility<ILVectorArray2n>::Encrypt(algorithm,pk, intArray1,&ciphertext,false);	// This is the core encryption operation.


	IntPlaintextEncoding intArrayNew;

	

	DecryptResult result = CryptoUtility<ILVectorArray2n>::Decrypt(algorithm, sk, ciphertext, &intArrayNew, false);  // This is the core decryption operation.

	

	if (!result.isValid) {
		std::cout << "Decryption failed!" << std::endl;
		exit(1);
	}



	//PRE SCHEME

	////////////////////////////////////////////////////////////
	//Perform the second key generation operation.
	// This generates the keys which should be able to decrypt the ciphertext after the re-encryption operation.
	////////////////////////////////////////////////////////////

	LPPublicKey<ILVectorArray2n> newPK(cryptoParams);
	LPPrivateKey<ILVectorArray2n> newSK(cryptoParams);

	std::cout << "Running second key generation (used for re-encryption)..." << std::endl;


	successKeyGen = CryptoUtility<ILVectorArray2n>::KeyGen(algorithm, &newPK, &newSK);	// This is the same core key generation operation.

	////////////////////////////////////////////////////////////
	//Perform the proxy re-encryption key generation operation.
	// This generates the keys which are used to perform the key switching.
	////////////////////////////////////////////////////////////

	std::cout << "\n" << "Generating proxy re-encryption key..." << std::endl;

	LPEvalKeyRelin<ILVectorArray2n> evalKey(cryptoParams);

	algorithm.ReKeyGen(newSK, sk, &evalKey);  // FIXME this can't use CryptoUtility because the calling sequence is wrong (2 private keys)


	////////////////////////////////////////////////////////////
	//Perform the proxy re-encryption operation.
	// This switches the keys which are used to perform the key switching.
	////////////////////////////////////////////////////////////


	vector<Ciphertext<ILVectorArray2n>> newCiphertext;

	std::cout << "\n" << "Running re-encryption..." << std::endl;

	CryptoUtility<ILVectorArray2n>::ReEncrypt(algorithm, evalKey, ciphertext, &newCiphertext);  // This is the core re-encryption operation.



	//cout<<"new CipherText - PRE = "<<newCiphertext.GetValues()<<endl;

	////////////////////////////////////////////////////////////
	//Decryption
	////////////////////////////////////////////////////////////

	IntPlaintextEncoding intArrayNew2;

	std::cout << "\n" << "Running decryption of re-encrypted cipher..." << std::endl;

	DecryptResult result1 = CryptoUtility<ILVectorArray2n>::Decrypt(algorithm, newSK, newCiphertext, &intArrayNew2, false);  // This is the core decryption operation.

	std::cout << "Secret Keys" << std::endl;
	newSK.GetPrivateElement().PrintValues();

	const auto &el = newCiphertext.at(0).GetElements();

	for (usint i = 0; i < el.size(); i++) {
		std::cout << "Printing " << i << "  th ciphertext" << std::endl;
		el.at(i).PrintValues();
	}


	if (!result1.isValid) {
		std::cout << "Decryption failed!" << std::endl;
		exit(1);
	}

	std::cout << "Execution completed." << std::endl;


}
