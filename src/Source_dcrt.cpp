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
#include <sys/types.h>
#include "time.h"
#include <chrono>

#include "math/backend.h"
#include "utils/inttypes.h"
#include "math/nbtheory.h"
#include "lattice/elemparams.h"
#include "lattice/ilparams.h"
#include "lattice/ildcrtparams.h"
#include "lattice/ilelement.h"
#include "math/distrgen.h"
#include "crypto/lwecrypt.h"
#include "crypto/lwecrypt.cpp"
#include "crypto/lweautomorph.cpp"
#include "crypto/lwepre.h"
#include "crypto/lwepre.cpp"
#include "crypto/lweahe.cpp"
#include "crypto/lweshe.cpp"
#include "crypto/lwefhe.cpp"
#include "lattice/ilvector2n.h"
#include "lattice/ilvectorarray2n.h"
#include "crypto/ciphertext.cpp"

using namespace std;
using namespace lbcrypto;

void NTRU_DCRT();
double currentDateTime();
void SparseKeyGenTest();
void SparseKeyGenTestDoubleCRT();

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

	NTRU_DCRT();

	std::cin.get();
	ChineseRemainderTransformFTT::GetInstance().Destroy();
	NumberTheoreticTransform::GetInstance().Destroy();

	return 0;
}


double currentDateTime()
{

	std::chrono::time_point<std::chrono::system_clock> now = std::chrono::system_clock::now();

    time_t tnow = std::chrono::system_clock::to_time_t(now);
    tm *date = localtime(&tnow);
    date->tm_hour = 0;
    date->tm_min = 0;
    date->tm_sec = 0;

    auto midnight = std::chrono::system_clock::from_time_t(mktime(date));

	return std::chrono::duration <double, std::milli>(now - midnight).count();
}

void NTRU_DCRT() {

	double diff, start, finish;

	start = currentDateTime();

	usint m = 1024;

	const ByteArray plaintext = "I am a good boy!";
	ByteArrayPlaintextEncoding ptxt(plaintext);
	ptxt.Pad<ZeroPad>(m/16);
//	ptxt.Pad<ZeroPad>(m/8);

	float stdDev = 4;

	usint size = 5;

	std::cout << "tower size: " << size << std::endl;

	ByteArrayPlaintextEncoding ctxtd;

	vector<BigBinaryInteger> moduli(size);

	vector<BigBinaryInteger> rootsOfUnity(size);

	BigBinaryInteger q("1");
	BigBinaryInteger temp;
	BigBinaryInteger modulus("1");

	for(int i=0; i < size;i++){
        lbcrypto::NextQ(q, BigBinaryInteger::TWO,m,BigBinaryInteger("4"), BigBinaryInteger("4"));
		moduli[i] = q;
	//	cout << q << endl;
		rootsOfUnity[i] = RootOfUnity(m,moduli[i]);
	//	cout << rootsOfUnity[i] << endl;
		modulus = modulus* moduli[i];
	
	}

	cout << "big modulus: " << modulus << endl;
	DiscreteGaussianGenerator dgg(modulus,stdDev);

	ILDCRTParams params(rootsOfUnity, m, moduli);

//	ILDCRTParams params(rootsOfUnity, m, moduli,modulus1*modulus2);

	LPCryptoParametersLTV<ILVectorArray2n> cryptoParams;
//	BigBinaryInteger plaintextm("8");
	cryptoParams.SetPlaintextModulus(BigBinaryInteger::TWO);
//	cryptoParams.SetPlaintextModulus(plaintextm);
	cryptoParams.SetDistributionParameter(stdDev);
	cryptoParams.SetRelinWindow(1);
	cryptoParams.SetElementParams(params);
	cryptoParams.SetDiscreteGaussianGenerator(dgg);

	Ciphertext<ILVectorArray2n> cipherText;
	cipherText.SetCryptoParameters(cryptoParams);


	LPPublicKeyLTV<ILVectorArray2n> pk(cryptoParams);
	LPPrivateKeyLTV<ILVectorArray2n> sk(cryptoParams);

	std::bitset<FEATURESETSIZE> mask (std::string("000011"));
	LPPublicKeyEncryptionSchemeLTV<ILVectorArray2n> algorithm(mask);

	//LPAlgorithmLTV<ILVectorArray2n> algorithm;

	algorithm.KeyGen(&pk, &sk);

	algorithm.Encrypt(pk, ptxt, &cipherText);

	algorithm.Decrypt(sk, cipherText, &ctxtd);

	finish = currentDateTime();

	diff = finish - start;
	ctxtd.Unpad<ZeroPad>();

	cout << "Decrypted value ILVectorArray2n: \n" << endl;
	cout << ctxtd<< "\n" << endl;

	cout<< "Decryption execution time: "<<"\t"<<diff<<" ms"<<endl;

	//LPAlgorithmPRELTV<ILVectorArray2n> algorithmPRE;

	////////////////////////////////////////////////////////////////
	//////Perform the second key generation operation.
	////// This generates the keys which should be able to decrypt the ciphertext after the re-encryption operation.
	////////////////////////////////////////////////////////////////

	//LPPublicKeyLTV<ILVectorArray2n> newPK(cryptoParams);
	//LPPrivateKeyLTV<ILVectorArray2n> newSK(cryptoParams);

	//std::cout << "Running second key generation (used for re-encryption)..." << std::endl;

	//algorithmPRE.KeyGen(newPK,newSK,dgg);	// This is the same core key generation operation.

	//LPEvalKeyLTV<ILVectorArray2n> evalKey(cryptoParams);

	//algorithmPRE.EvalKeyGen(newPK, sk, dgg , &evalKey);  // This is the core re-encryption operation.

	//Ciphertext<ILVectorArray2n> newCiphertext;

	//
	//algorithmPRE.ReEncrypt(evalKey, cipherText,&newCiphertext);  // This is the core re-encryption operation.

	//
	//ByteArrayPlaintextEncoding plaintextNew2;

	//std::cout <<"\n"<< "Running decryption of re-encrypted cipher..." << std::endl;

	//
	//DecodingResult result1 = algorithmPRE.Decrypt(newSK,newCiphertext,&plaintextNew2);  // This is the core decryption operation.
 //   plaintextNew2.Unpad<ZeroPad>();

	//
	//cout<<"\n"<<"decrypted plaintext (PRE Re-Encrypt): "<<plaintextNew2<<"\n"<<endl;


}

void SparseKeyGenTest(){
	
	/*SHEOperations<ILVector2n> she_test;

	usint m = 16;
	float stdDev = 4;

	ByteArrayPlaintextEncoding ctxtd;

	const ByteArray plaintext = "M";
	
	BigBinaryInteger q("1");
	lbcrypto::NextQ(q, BigBinaryInteger::TWO,m,BigBinaryInteger("4"), BigBinaryInteger("4"));	
	BigBinaryInteger rootOfUnity;

	rootOfUnity = RootOfUnity(m,q);

	cout << "Modulus is" << q << endl;
	cout << "RootOfUnity is" << rootOfUnity << endl;

	DiscreteGaussianGenerator dgg(q,stdDev);

	ILParams ilParams(m,q,rootOfUnity);

	ByteArrayPlaintextEncoding ptxt(plaintext);
	
	ptxt.Pad<ZeroPad>(m/16);

	ILVector2n ilVector2n(ilParams);

	LPCryptoParametersLTV<ILVector2n> cryptoParams;
	cryptoParams.SetPlaintextModulus(BigBinaryInteger::TWO);
	cryptoParams.SetDistributionParameter(stdDev);
	cryptoParams.SetRelinWindow(1);
	cryptoParams.SetElementParams(ilParams);

	Ciphertext<ILVector2n> cipherText;

	cipherText.SetCryptoParameters(cryptoParams);

	LPPublicKeyLTV<ILVector2n> pk(cryptoParams);
	LPPrivateKeyLTV<ILVector2n> sk(cryptoParams);

	LPAlgorithmLTV<ILVector2n> algorithm;

	algorithm.SparseKeyGen(pk, sk, dgg);
	algorithm.Encrypt(pk, ptxt, &cipherText);

	algorithm.Decrypt(sk, cipherText, &ctxtd);

	cout << "Decrypted value ILVector2n: \n" << endl;
	cout << ctxtd<< "\n" << endl;*/

//	sk.GetPrivateElement().PrintValues();
}

void SparseKeyGenTestDoubleCRT(){
	
//	SHEOperations<ILVectorArray2n> she_test;
//
//	double diff, start, finish;
//
//	start = currentDateTime();
//
//	usint m = 256;
//
//	const ByteArray plaintext = "Ma test is";
//	ByteArrayPlaintextEncoding ptxt(plaintext);
//	ptxt.Pad<ZeroPad>(m/16);
////	ptxt.Pad<ZeroPad>(m/8);
//
//	float stdDev = 5;
//
//	usint size = 5;
//
//	ByteArrayPlaintextEncoding ctxtd;
//
//	vector<BigBinaryInteger> moduli(size);
//
//	vector<BigBinaryInteger> rootsOfUnity(size);
//
//	BigBinaryInteger q("1");
//	BigBinaryInteger temp;
//	BigBinaryInteger modulus("1");
//
//	for(int i=0; i < size;i++){
//        lbcrypto::NextQ(q, BigBinaryInteger::TWO,m,BigBinaryInteger("4"), BigBinaryInteger("4"));
//		moduli[i] = q;
//		rootsOfUnity[i] = RootOfUnity(m,moduli[i]);
//		modulus = modulus* moduli[i];
//		
//	}
//
//	DiscreteGaussianGenerator dgg(modulus,stdDev);
//
//	ILDCRTParams params(rootsOfUnity, m, moduli,modulus);
//
//	LPCryptoParametersLTV<ILVectorArray2n> cryptoParams;
//	cryptoParams.SetPlaintextModulus(BigBinaryInteger::TWO);
//	cryptoParams.SetDistributionParameter(stdDev);
//	cryptoParams.SetRelinWindow(1);
//	cryptoParams.SetElementParams(params);
//
//	Ciphertext<ILVectorArray2n> cipherText;
//	cipherText.SetCryptoParameters(cryptoParams);
//
//	LPPublicKeyLTV<ILVectorArray2n> pk(cryptoParams);
//	LPPrivateKeyLTV<ILVectorArray2n> sk(cryptoParams);
//
//	LPAlgorithmLTV<ILVectorArray2n> algorithm;
//
//	algorithm.SparseKeyGen(pk, sk, dgg);
//
//	algorithm.Encrypt(pk, ptxt, &cipherText);
//
//	algorithm.Decrypt(sk, cipherText, &ctxtd);
//
//	cout << "Decrypted value ILVectorArray2n: \n" << endl;
//	cout << ctxtd<< "\n" << endl;

}