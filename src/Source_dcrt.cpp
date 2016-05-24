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
#include  <sys/types.h>


#include "math/backend.h"
//#include "math/cpu8bit/backend.h"
#include "utils/inttypes.h"
#include "math/nbtheory.h"
//#include <thread>
#include "lattice/elemparams.h"
#include "lattice/ilparams.h"
#include "lattice/ildcrtparams.h"
#include "lattice/ilelement.h"
//#include "ilvector2n.h"
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
#include "time.h"
#include "crypto/ciphertext.cpp"
//#include "SHE/sheoperations.cpp"
//#include "vld.h"
#include <chrono>
//#include "gtest/gtest.h"
//#include "math/cpu8bit/binint.h"
//#include "math/cpu8bit/binvect.h"
//#include "math/cpu8bit/binmat.h"

using namespace std;
using namespace lbcrypto;
double currentDateTime();
void NTRU_DCRT();
// void NextQ(BigBinaryInteger &q, const BigBinaryInteger &plainTextModulus, const usint &ringDimension, const BigBinaryInteger &sigma, const BigBinaryInteger &alpha);
void KeySwitchTest();
void KeySwitchTestSingleCRT();
void SparseKeyGenTest();
void SparseKeyGenTestDoubleCRT();
void KeySwitchTestSingleCRTNew();
void KeySwitchTestNew();
void RingReduceTest();
void ModReduceTest();
void RingReduceDoubleCRTTest();
void RingReduceSingleCRTTest();
void ModReduceNew();
void ModReduceGyana();
void KeySwitchTestNewAPI();
void RingReduceDCRTTest();
void RingReduceSingleCRTTest();
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

//	KeySwitchTest();

//	SparseKeyGenTest();

//	KeySwitchTestSingleCRTNew();

//	SparseKeyGenTestDoubleCRT();

	// KeySwitchTestNew();

//	DecomposeTest();

//	DecomposeTestDoubleCRT();

	//RingReduceSingleCRTTest();

	//RingReduceDoubleCRTTest();

	//ModReduceTest();

//	ModReduceNew();

//	ModReduceGyana();
	
	//KeySwitchTestNewAPI(); 

//	RingReduceDCRTTest();
//	RingReduceSingleCRTTest();
//	RingReduceDCRTTest();

//	NextQTest();

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

	LPCryptoParametersLTV<ILVectorArray2n> cryptoParams2;
//	BigBinaryInteger plaintextm("8");
	cryptoParams2.SetPlaintextModulus(BigBinaryInteger::TWO);
//	cryptoParams2.SetPlaintextModulus(plaintextm);
	cryptoParams2.SetDistributionParameter(stdDev);
	cryptoParams2.SetRelinWindow(1);
	cryptoParams2.SetElementParams(params);
	cryptoParams2.SetDiscreteGaussianGenerator(dgg);

	Ciphertext<ILVectorArray2n> cipherText2;
	cipherText2.SetCryptoParameters(cryptoParams2);


	LPPublicKeyLTV<ILVectorArray2n> pk2(cryptoParams2);
	LPPrivateKeyLTV<ILVectorArray2n> sk2(cryptoParams2);

	std::bitset<FEATURESETSIZE> mask (std::string("000011"));
	LPPublicKeyEncryptionSchemeLTV<ILVectorArray2n> algorithm2(mask);

	//LPAlgorithmLTV<ILVectorArray2n> algorithm2;

	algorithm2.KeyGen(&pk2, &sk2);

	algorithm2.Encrypt(pk2, ptxt, &cipherText2);

	algorithm2.Decrypt(sk2, cipherText2, &ctxtd);

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

	//LPPublicKeyLTV<ILVectorArray2n> newPK(cryptoParams2);
	//LPPrivateKeyLTV<ILVectorArray2n> newSK(cryptoParams2);

	//std::cout << "Running second key generation (used for re-encryption)..." << std::endl;

	//algorithmPRE.KeyGen(newPK,newSK,dgg);	// This is the same core key generation operation.

	//LPEvalKeyLTV<ILVectorArray2n> evalKey(cryptoParams2);

	//algorithmPRE.EvalKeyGen(newPK, sk2, dgg , &evalKey);  // This is the core re-encryption operation.

	//Ciphertext<ILVectorArray2n> newCiphertext;

	//
	//algorithmPRE.ReEncrypt(evalKey, cipherText2,&newCiphertext);  // This is the core re-encryption operation.

	//
	//ByteArrayPlaintextEncoding plaintextNew2;

	//std::cout <<"\n"<< "Running decryption of re-encrypted cipher..." << std::endl;

	//
	//DecodingResult result1 = algorithmPRE.Decrypt(newSK,newCiphertext,&plaintextNew2);  // This is the core decryption operation.
 //   plaintextNew2.Unpad<ZeroPad>();

	//
	//cout<<"\n"<<"decrypted plaintext (PRE Re-Encrypt): "<<plaintextNew2<<"\n"<<endl;


}

void KeySwitchTestSingleCRT(){

	//SHEOperations<ILVector2n> she_test;

	//usint m = 4096;
	//float stdDev = 4;

	//ByteArrayPlaintextEncoding ctxtd;

	//const ByteArray plaintext = "Mary had a little lamb, Its fleece was white as snow; And everywhere that Mary went The lamb was sure to go.";
	//
	//BigBinaryInteger q("1");
	//lbcrypto::NextQ(q, BigBinaryInteger::TWO,m,BigBinaryInteger("4"), BigBinaryInteger("4"));	
	//BigBinaryInteger rootOfUnity;

	//rootOfUnity = lbcrypto::RootOfUnity(m,q);

	//cout << "Modulus is" << q << endl;
	//cout << "RootOfUnity is" << rootOfUnity << endl;

	//DiscreteGaussianGenerator dgg(q,stdDev);


	//ILParams ilParams(m,q,rootOfUnity);


	//ByteArrayPlaintextEncoding ptxt(plaintext);
	//
	//ptxt.Pad<ZeroPad>(m/16);

	//ILVector2n ilVector2n(ilParams);

	//LPCryptoParametersLTV<ILVector2n> cryptoParams2;
	//cryptoParams2.SetPlaintextModulus(BigBinaryInteger::TWO);
	//cryptoParams2.SetDistributionParameter(stdDev);
	//cryptoParams2.SetRelinWindow(1);
	//cryptoParams2.SetElementParams(ilParams);

	//Ciphertext<ILVector2n> cipherText2;

	//cipherText2.SetCryptoParameters(cryptoParams2);

	//LPPublicKeyLTV<ILVector2n> pk2(cryptoParams2);
	//LPPrivateKeyLTV<ILVector2n> sk2(cryptoParams2);

	//LPAlgorithmLTV<ILVector2n> algorithm2;

	//algorithm2.KeyGen(&pk2, &sk2);
	//algorithm2.Encrypt(pk2, ptxt, &cipherText2);

	//algorithm2.Decrypt(sk2, cipherText2, &ctxtd);

	//cout << "Decrypted value ILVector2n: \n" << endl;
	//cout << ctxtd<< "\n" << endl;

	//LPPublicKeyLTV<ILVector2n> pk3(cryptoParams2);
	//LPPrivateKeyLTV<ILVector2n> sk3(cryptoParams2);
	//algorithm2.KeyGen(&pk3, &sk3);

	//ILVector2n keySwitchHint(ilParams);

	//keySwitchHint = she_test.KeySwitchHintGen(sk3,sk2,dgg);

	//ILVector2n c(ilParams);
	//
	//c = cipherText2.GetElement(); //EVAL

	//c = c* keySwitchHint;  //EVAL

	//cipherText2.SetElement(c);

	//algorithm2.Decrypt(sk3, cipherText2, &ctxtd);

	//cout << "Decrypted value ILVector2n: \n" << endl;
	//cout << ctxtd<< "\n" << endl;
}


void KeySwitchTest(){

//	SHEOperations<ILVectorArray2n> she_test;
//
//	double diff, start, finish;
//
//	start = currentDateTime();
//
//	usint m = 512;
//
//	const ByteArray plaintext = "Mary had a litte lamb.";
//	ByteArrayPlaintextEncoding ptxt(plaintext);
//	ptxt.Pad<ZeroPad>(m/16);
////	ptxt.Pad<ZeroPad>(m/8);
//
//	float stdDev = 2;
//
//	usint size = 8;
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
//		rootsOfUnity[i] = lbcrypto::RootOfUnity(m,moduli[i]);
//		modulus = modulus* moduli[i];
//		
//	}
//
////	cout << "big modulus: " << modulus << endl;
//	DiscreteGaussianGenerator dgg(modulus,stdDev);
//
//	ILDCRTParams params(rootsOfUnity, m, moduli,modulus);
//
//	LPCryptoParametersLTV<ILVectorArray2n> cryptoParams2;
//	cryptoParams2.SetPlaintextModulus(BigBinaryInteger::TWO);
//	cryptoParams2.SetDistributionParameter(stdDev);
//	cryptoParams2.SetRelinWindow(1);
//	cryptoParams2.SetElementParams(params);
//
//	Ciphertext<ILVectorArray2n> cipherText2;
//	cipherText2.SetCryptoParameters(cryptoParams2);
//
//	LPPublicKeyLTV<ILVectorArray2n> pk2(cryptoParams2);
//	LPPrivateKeyLTV<ILVectorArray2n> sk2(cryptoParams2);
//
//	LPAlgorithmLTV<ILVectorArray2n> algorithm2;
//
//	algorithm2.KeyGen(&pk2, &sk2);
//
//	LPPublicKeyLTV<ILVectorArray2n> pk3(cryptoParams2);
//	LPPrivateKeyLTV<ILVectorArray2n> sk3(cryptoParams2);
//
//	algorithm2.KeyGen(&pk3, &sk3);
//
//	algorithm2.Encrypt(pk2, ptxt, &cipherText2);
//
//	ILVectorArray2n d(params);
//
//	d = cipherText2.GetElement();
//
////	d.PrintValues();
//
//	for(int i = 0; i < d.GetParams().GetModuli().size();i++){
//		cout << "Moduli " << i << " : " << d.GetParams().GetModuli()[i] << endl;
//	}
//	
//	for(int i = 0; i < d.GetParams().GetRootsOfUnity().size();i++){
//		cout << "Roots of Unity " << i << " : " << d.GetParams().GetRootsOfUnity()[i] << endl;
//	}
//
//
//	//algorithm2.Decrypt(sk2, cipherText2, &ctxtd);
//
//	//cout << "Decrypted value ILVectorArray2n: \n" << endl;
//
//	//cout << ctxtd<< "\n" << endl;
//
//	ILVectorArray2n keySwitchHint(params);
//
//	keySwitchHint = she_test.KeySwitchHintGen(sk3,sk2,dgg);
//
//	cout << "Key switch hint being printed " << endl;
//
//	cout << keySwitchHint.GetParams().GetModulus() << endl;
//
////	keySwitchHint = keySwitchHint.Mod(keySwitchHint.GetParams().GetModulus()); 
//
////	keySwitchHint.PrintValues();
//
//	algorithm2.Decrypt(sk2, cipherText2, &ctxtd);
//
//	cout << "Decrypted value ILVectorArray2n: \n" << endl;
//	cout << ctxtd<< "\n" << endl;
//
//	ILVectorArray2n c(params);
//	
//	
//	c = cipherText2.GetElement(); 
//
////	c.PrintValues();
//
////	c.SwitchFormat(); //EVAL
//	
////	c.PrintValues();
//
//	c = c* keySwitchHint;  
//
////	c.PrintValues();
//
////	c.SwitchFormat(); 
//
////	c.PrintValues();
//
//	cipherText2.SetElement(c);
//
//	algorithm2.Decrypt(sk3, cipherText2, &ctxtd);
//
//	cout << "Decrypted value ILVectorArray2n: \n" << endl;
//
//	cout << ctxtd<< "\n" << endl;

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

	LPCryptoParametersLTV<ILVector2n> cryptoParams2;
	cryptoParams2.SetPlaintextModulus(BigBinaryInteger::TWO);
	cryptoParams2.SetDistributionParameter(stdDev);
	cryptoParams2.SetRelinWindow(1);
	cryptoParams2.SetElementParams(ilParams);

	Ciphertext<ILVector2n> cipherText2;

	cipherText2.SetCryptoParameters(cryptoParams2);

	LPPublicKeyLTV<ILVector2n> pk2(cryptoParams2);
	LPPrivateKeyLTV<ILVector2n> sk2(cryptoParams2);

	LPAlgorithmLTV<ILVector2n> algorithm2;

	algorithm2.SparseKeyGen(pk2, sk2, dgg);
	algorithm2.Encrypt(pk2, ptxt, &cipherText2);

	algorithm2.Decrypt(sk2, cipherText2, &ctxtd);

	cout << "Decrypted value ILVector2n: \n" << endl;
	cout << ctxtd<< "\n" << endl;*/

//	sk2.GetPrivateElement().PrintValues();
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
//	LPCryptoParametersLTV<ILVectorArray2n> cryptoParams2;
//	cryptoParams2.SetPlaintextModulus(BigBinaryInteger::TWO);
//	cryptoParams2.SetDistributionParameter(stdDev);
//	cryptoParams2.SetRelinWindow(1);
//	cryptoParams2.SetElementParams(params);
//
//	Ciphertext<ILVectorArray2n> cipherText2;
//	cipherText2.SetCryptoParameters(cryptoParams2);
//
//	LPPublicKeyLTV<ILVectorArray2n> pk2(cryptoParams2);
//	LPPrivateKeyLTV<ILVectorArray2n> sk2(cryptoParams2);
//
//	LPAlgorithmLTV<ILVectorArray2n> algorithm2;
//
//	algorithm2.SparseKeyGen(pk2, sk2, dgg);
//
//	algorithm2.Encrypt(pk2, ptxt, &cipherText2);
//
//	algorithm2.Decrypt(sk2, cipherText2, &ctxtd);
//
//	cout << "Decrypted value ILVectorArray2n: \n" << endl;
//	cout << ctxtd<< "\n" << endl;

}

void ringReduce(int n, int a, Ciphertext<ILVector2n> cipherText2)
{

}

void KeySwitchTestSingleCRTNew(){

	/*SHEOperations<ILVector2n> she_test;

	usint m = 2048;
	float stdDev = 4;

	ByteArrayPlaintextEncoding ctxtd;

	const ByteArray plaintext = "Mary had";
	
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

	LPCryptoParametersLTV<ILVector2n> cryptoParams2;
	cryptoParams2.SetPlaintextModulus(BigBinaryInteger::TWO);
	cryptoParams2.SetDistributionParameter(stdDev);
	cryptoParams2.SetRelinWindow(1);
	cryptoParams2.SetElementParams(ilParams);

	Ciphertext<ILVector2n> cipherText2;

	cipherText2.SetCryptoParameters(cryptoParams2);

	LPPublicKeyLTV<ILVector2n> pk2(cryptoParams2);
	LPPrivateKeyLTV<ILVector2n> sk2(cryptoParams2);

	LPAlgorithmLTV<ILVector2n> algorithm2;

	algorithm2.KeyGen(&pk2, &sk2);
	algorithm2.Encrypt(pk2, ptxt, &cipherText2);

	algorithm2.Decrypt(sk2, cipherText2, &ctxtd);

	cout << "Decrypted value ILVector2n: \n" << endl;
	cout << ctxtd<< "\n" << endl;

	LPPublicKeyLTV<ILVector2n> pk3(cryptoParams2);
	LPPrivateKeyLTV<ILVector2n> sk3(cryptoParams2);
	algorithm2.KeyGen(&pk3, &sk3);

	cipherText2 = she_test.KeySwitch(sk3,sk2,dgg,cipherText2);

	algorithm2.Decrypt(sk3, cipherText2, &ctxtd);

	cout << "Decrypted value ILVector2n: \n" << endl;
	cout << ctxtd<< "\n" << endl;*/
}

void KeySwitchTestNew(){

//	SHEOperations<ILVectorArray2n> she_test;
//
//	double diff, start, finish;
//
//	start = currentDateTime();
//
//	usint m = 512;
//
//	const ByteArray plaintext = "Mary had a litte lamb.";
//	ByteArrayPlaintextEncoding ptxt(plaintext);
//	ptxt.Pad<ZeroPad>(m/16);
////	ptxt.Pad<ZeroPad>(m/8);
//
//	float stdDev = 2;
//
//	usint size = 8;
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
////	cout << "big modulus: " << modulus << endl;
//	DiscreteGaussianGenerator dgg(modulus,stdDev);
//
//	ILDCRTParams params(rootsOfUnity, m, moduli,modulus);
//
//	LPCryptoParametersLTV<ILVectorArray2n> cryptoParams2;
//	cryptoParams2.SetPlaintextModulus(BigBinaryInteger::TWO);
//	cryptoParams2.SetDistributionParameter(stdDev);
//	cryptoParams2.SetRelinWindow(1);
//	cryptoParams2.SetElementParams(params);
//
//	Ciphertext<ILVectorArray2n> cipherText2;
//	cipherText2.SetCryptoParameters(cryptoParams2);
//
//	LPPublicKeyLTV<ILVectorArray2n> pk2(cryptoParams2);
//	LPPrivateKeyLTV<ILVectorArray2n> sk2(cryptoParams2);
//
//	LPAlgorithmLTV<ILVectorArray2n> algorithm2;
//
//	algorithm2.KeyGen(&pk2, &sk2);
//
//	LPPublicKeyLTV<ILVectorArray2n> pk3(cryptoParams2);
//	LPPrivateKeyLTV<ILVectorArray2n> sk3(cryptoParams2);
//
//	algorithm2.KeyGen(&pk3, &sk3);
//
//	algorithm2.Encrypt(pk2, ptxt, &cipherText2);
//
//	
//
//	ILVectorArray2n keySwitchHint(params);
//
//	keySwitchHint = she_test.KeySwitchHintGen(sk3,sk2,dgg);
//
//	cout << "Key switch hint being printed " << endl;
//
//	cout << keySwitchHint.GetParams().GetModulus() << endl;
//
////	keySwitchHint = keySwitchHint.Mod(keySwitchHint.GetParams().GetModulus()); 
//
////	keySwitchHint.PrintValues();
//
//	algorithm2.Decrypt(sk2, cipherText2, &ctxtd);
//
//	cout << "Decrypted value ILVectorArray2n: \n" << endl;
//	cout << ctxtd<< "\n" << endl;
//
//	
//	Ciphertext<ILVectorArray2n> cipherText3;
//
//	cipherText3 = she_test.KeySwitch(sk3,sk2,dgg,cipherText2);
//
//	
//
//	cout << "Decrypted value ILVectorArray2n: \n" << endl;
//
//	cout << ctxtd<< "\n" << endl;

}

void RingReduceDCRTTest(){

	usint m = 32;

	const ByteArray plaintext = "M";
	ByteArrayPlaintextEncoding ptxt(plaintext);
	ptxt.Pad<ZeroPad>(m/16);

	float stdDev = 4;

	usint size = 2;

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
		cout << moduli[i] << endl;
		rootsOfUnity[i] = RootOfUnity(m,moduli[i]);
		cout << rootsOfUnity[i] << endl;
		modulus = modulus* moduli[i];
	
	}

	cout << "big modulus: " << modulus << endl;
	DiscreteGaussianGenerator dgg(modulus,stdDev);

	ILDCRTParams params(rootsOfUnity, m, moduli);

	LPCryptoParametersLTV<ILVectorArray2n> cryptoParams2;
	cryptoParams2.SetPlaintextModulus(BigBinaryInteger::TWO);
	cryptoParams2.SetDistributionParameter(stdDev);
	cryptoParams2.SetRelinWindow(1);
	cryptoParams2.SetElementParams(params);
	cryptoParams2.SetDiscreteGaussianGenerator(dgg);

	Ciphertext<ILVectorArray2n> cipherText2;
	cipherText2.SetCryptoParameters(cryptoParams2);

	LPPublicKeyLTV<ILVectorArray2n> pk2(cryptoParams2);
	LPPrivateKeyLTV<ILVectorArray2n> sk2(cryptoParams2);

	std::bitset<FEATURESETSIZE> mask (std::string("1000011"));
	LPPublicKeyEncryptionSchemeLTV<ILVectorArray2n> algorithm2(mask);

	algorithm2.KeyGen(&pk2, &sk2);

	/*sk2.GetPrivateElement().PrintValues();
	pk2.GetPublicElement().PrintValues();*/

	algorithm2.Encrypt(pk2, ptxt, &cipherText2);
	algorithm2.Decrypt(sk2, cipherText2, &ctxtd);

	ctxtd.Unpad<ZeroPad>();

	cout << "Decrypted value ILVectorArray2n: \n" << endl;
	cout << ctxtd<< "\n" << endl;

	algorithm2.m_algorithmLeveledSHE->RingReduce(&cipherText2, &sk2);
	
	algorithm2.Decrypt(sk2, cipherText2, &ctxtd);

	cout << "Decrypted after MOD Reduce ILVectorArray2n: \n" << endl;
	
	cout << ctxtd<< "\n" << endl;

}

void RingReduceSingleCRTTest(){

	usint m = 32;

	const ByteArray plaintext = "M";
	ByteArrayPlaintextEncoding ptxt(plaintext);
	ptxt.Pad<ZeroPad>(m/16);

	float stdDev = 4;

	ByteArrayPlaintextEncoding ctxtd;
	BigBinaryInteger q("1");
	BigBinaryInteger temp;
	BigBinaryInteger modulus("17729");
	BigBinaryInteger rootOfUnity = lbcrypto::RootOfUnity(m,modulus);

	cout << "big modulus: " << modulus << endl;
	DiscreteGaussianGenerator dgg(modulus,stdDev);

	ILParams params(m, modulus, rootOfUnity);

	LPCryptoParametersLTV<ILVector2n> cryptoParams2;
	cryptoParams2.SetPlaintextModulus(BigBinaryInteger::TWO);
	cryptoParams2.SetDistributionParameter(stdDev);
	cryptoParams2.SetRelinWindow(1);
	cryptoParams2.SetElementParams(params);
	cryptoParams2.SetDiscreteGaussianGenerator(dgg);

	Ciphertext<ILVector2n> cipherText2;
	cipherText2.SetCryptoParameters(cryptoParams2);

	LPPublicKeyLTV<ILVector2n> pk2(cryptoParams2);
	LPPrivateKeyLTV<ILVector2n> sk2(cryptoParams2);

	std::bitset<FEATURESETSIZE> mask (std::string("1000011"));
	LPPublicKeyEncryptionSchemeLTV<ILVector2n> algorithm2(mask);

	algorithm2.KeyGen(&pk2, &sk2);

	/*sk2.GetPrivateElement().PrintValues();
	pk2.GetPublicElement().PrintValues();*/

	algorithm2.Encrypt(pk2, ptxt, &cipherText2);
	algorithm2.Decrypt(sk2, cipherText2, &ctxtd);

	ctxtd.Unpad<ZeroPad>();

	cout << "Decrypted value ILVectorArray2n: \n" << endl;
	cout << ctxtd<< "\n" << endl;

	algorithm2.m_algorithmLeveledSHE->RingReduce(&cipherText2, &sk2);
	
	algorithm2.Decrypt(sk2, cipherText2, &ctxtd);

	cout << "Decrypted after MOD Reduce ILVectorArray2n: \n" << endl;
	
	cout << ctxtd<< "\n" << endl;

}

void RingReduceDoubleCRTTest(){

	//SHEOperations<ILVectorArray2n> she_test;
	//usint m = 32; //4096
	//float stdDev = 3;
	//usint size = 3;

	//ByteArrayPlaintextEncoding ctxtd;
	//vector<BigBinaryInteger> moduli(size);
	//vector<BigBinaryInteger> rootsOfUnity(size);

	//BigBinaryInteger q("1");
	//BigBinaryInteger temp;
	//BigBinaryInteger modulus("1");

	//for(int i=0; i < size;i++){
 //       lbcrypto::NextQ(q, BigBinaryInteger::TWO,m,BigBinaryInteger("4"), BigBinaryInteger("4"));
	//	moduli[i] = q;
	//	rootsOfUnity[i] = RootOfUnity(m,moduli[i]);
	//	modulus = modulus* moduli[i];
	//	
	//}

	//ILDCRTParams params(rootsOfUnity, m, moduli, modulus);

	//const ByteArray plaintext = "M";
	////Mary had a little lamb, Its fleece was white as snow; And everywhere that Mary went The lamb was sure to go.
	//cout << "Actual plaintext: " << endl;
	//cout << plaintext << endl;
	//DiscreteGaussianGenerator dgg(q,stdDev);
	//
	//ByteArrayPlaintextEncoding ptxt(plaintext);
	//ptxt.Pad<ZeroPad>(m/16);

	//LPCryptoParametersLTV<ILVectorArray2n> cryptoParams;
	//cryptoParams.SetPlaintextModulus(BigBinaryInteger::TWO);
	//cryptoParams.SetDistributionParameter(stdDev);
	//cryptoParams.SetRelinWindow(1);
	//cryptoParams.SetElementParams(params);

	//Ciphertext<ILVectorArray2n> cipherText, cipherText2;
	//cipherText.SetCryptoParameters(cryptoParams);

	//LPAlgorithmLTV<ILVectorArray2n> algorithm;
	//
	//LPPublicKeyLTV<ILVectorArray2n> pk(cryptoParams);
	//LPPrivateKeyLTV<ILVectorArray2n> sk(cryptoParams);

	//algorithm.KeyGen(&pk, &sk);
	//algorithm.Encrypt(pk, ptxt, &cipherText);
	//algorithm.Decrypt(sk, cipherText, &ctxtd);
	//ctxtd.Unpad<ZeroPad>();
	//cout << "Decrypting ringreduce values" << endl;
	//cout << ctxtd << endl;
	//
	//ILVectorArray2n c(params);
	//
	//lbcrypto::CipherTextSparseKey<ILVectorArray2n> ringReduceValues(she_test.RingReduce(cipherText, sk, dgg));

}


void ModReduceTest()
{
	//SHEOperations<ILVectorArray2n> she_test;
	//
	//usint m = 64;
	//const ByteArray plaintext = "MEIS"; //€
	//ByteArrayPlaintextEncoding ptxt(plaintext);
	//ptxt.Pad<ZeroPad>(m/16);
	//float stdDev = 4;
	//usint size = 3;

	//ByteArrayPlaintextEncoding ctxtd;
	//vector<BigBinaryInteger> moduli(size);
	//vector<BigBinaryInteger> rootsOfUnity(size);
	//BigBinaryInteger q("1");
	//BigBinaryInteger temp;
	//BigBinaryInteger modulus("1");

	//for(int i=0; i < size;i++){
 //       lbcrypto::NextQ(q, BigBinaryInteger::TWO,m,BigBinaryInteger("4"), BigBinaryInteger("4"));
	//	moduli[i] = q;
	//	rootsOfUnity[i] = lbcrypto::RootOfUnity(m,moduli[i]);
	//	modulus = modulus* moduli[i];
	//}

	//DiscreteGaussianGenerator dgg(modulus,stdDev);
	//ILDCRTParams params(rootsOfUnity, m, moduli, modulus);

	//LPCryptoParametersLTV<ILVectorArray2n> cryptoParams;
	//cryptoParams.SetPlaintextModulus(BigBinaryInteger::TWO);
	//cryptoParams.SetDistributionParameter(stdDev);
	//cryptoParams.SetRelinWindow(1);
	//cryptoParams.SetElementParams(params);

	//Ciphertext<ILVectorArray2n> cipherText;
	//cipherText.SetCryptoParameters(cryptoParams);

	//LPPublicKeyLTV<ILVectorArray2n> pk(cryptoParams);
	//LPPrivateKeyLTV<ILVectorArray2n> sk(cryptoParams);

	//LPAlgorithmLTV<ILVectorArray2n> algorithm;
	//algorithm.KeyGen(&pk, &sk);
	//algorithm.Encrypt(pk, ptxt, &cipherText);

	//algorithm.Decrypt(sk, cipherText, &ctxtd);
	//cout << "Decryption before Mod Reduce: " << endl;
	//cout << ctxtd << endl;

	//she_test.ModReduce(cipherText,sk);
	//algorithm.Decrypt(sk, cipherText, &ctxtd);
	//cout << "Decryption after Mod Reduce: " << endl;
	//cout << ctxtd << endl;
}

void ModReduceNew() {

	double diff, start, finish;

	start = currentDateTime();

	usint m = 16;

	const ByteArray plaintext = "M";
	ByteArrayPlaintextEncoding ptxt(plaintext);
	ptxt.Pad<ZeroPad>(m/16);
//	ptxt.Pad<ZeroPad>(m/8);

	float stdDev = 4;

	usint size = 3;

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
		//cout << moduli[i] << endl;
		rootsOfUnity[i] = RootOfUnity(m,moduli[i]);
		//cout << rootsOfUnity[i] << endl;
		modulus = modulus* moduli[i];
		//cout << moduli[i] << endl;
		//cout << rootsOfUnity[i] << endl;
	}

	/*rootsOfUnity[0] = BigBinaryInteger("10878");
	rootsOfUnity[1] = BigBinaryInteger("12967");*/

	cout << "big modulus: " << modulus << endl;
	DiscreteGaussianGenerator dgg(modulus,stdDev);

	ILDCRTParams params(rootsOfUnity, m, moduli);

//	ILDCRTParams params(rootsOfUnity, m, moduli,modulus1*modulus2);

	LPCryptoParametersLTV<ILVectorArray2n> cryptoParams2;
//	BigBinaryInteger plaintextm("8");
	cryptoParams2.SetPlaintextModulus(BigBinaryInteger::TWO);
//	cryptoParams2.SetPlaintextModulus(plaintextm);
	cryptoParams2.SetDistributionParameter(stdDev);
	cryptoParams2.SetRelinWindow(1);
	cryptoParams2.SetElementParams(params);
	cryptoParams2.SetDiscreteGaussianGenerator(dgg);

	Ciphertext<ILVectorArray2n> cipherText2;
	cipherText2.SetCryptoParameters(cryptoParams2);


	LPPublicKeyLTV<ILVectorArray2n> pk2(cryptoParams2);
	LPPrivateKeyLTV<ILVectorArray2n> sk2(cryptoParams2);

	std::bitset<FEATURESETSIZE> mask (std::string("1000011"));
	LPPublicKeyEncryptionSchemeLTV<ILVectorArray2n> algorithm2(mask);

	//LPAlgorithmLTV<ILVectorArray2n> algorithm2;

	algorithm2.KeyGen(&pk2, &sk2);

	/*sk2.GetPrivateElement().PrintValues();

	pk2.GetPublicElement().PrintValues();*/


	algorithm2.Encrypt(pk2, ptxt, &cipherText2);

	algorithm2.Decrypt(sk2, cipherText2, &ctxtd);

	finish = currentDateTime();

	diff = finish - start;
	ctxtd.Unpad<ZeroPad>();

	cout << "Decrypted value ILVectorArray2n: \n" << endl;
	cout << ctxtd<< "\n" << endl;

	cout<< "Decryption execution time: "<<"\t"<<diff<<" ms"<<endl;

	
	//algorithm2.Enable(LEVELEDSHE);

	algorithm2.m_algorithmLeveledSHE->ModReduce(&cipherText2, &sk2);
	
	algorithm2.Decrypt(sk2, cipherText2, &ctxtd);

	cout << "Decrypted after MOD Reduce ILVectorArray2n: \n" << endl;
	
	cout << ctxtd<< "\n" << endl;
	
}



void KeySwitchTestNewAPI() {

	usint m = 16;

	const ByteArray plaintext = "M";
	ByteArrayPlaintextEncoding ptxt(plaintext);
	ptxt.Pad<ZeroPad>(m/16);
//	ptxt.Pad<ZeroPad>(m/8);

	float stdDev = 4;

	usint size = 3;

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
		cout << moduli[i] << endl;
		rootsOfUnity[i] = RootOfUnity(m,moduli[i]);
		cout << rootsOfUnity[i] << endl;
		modulus = modulus* moduli[i];
	
	}

	/*rootsOfUnity[0] = BigBinaryInteger("10878");
	rootsOfUnity[1] = BigBinaryInteger("12967");*/
	
	cout << "big modulus: " << modulus << endl;
	DiscreteGaussianGenerator dgg(modulus,stdDev);

	ILDCRTParams params(rootsOfUnity, m, moduli);

//	ILDCRTParams params(rootsOfUnity, m, moduli,modulus1*modulus2);

	LPCryptoParametersLTV<ILVectorArray2n> cryptoParams2;
//	BigBinaryInteger plaintextm("8");
	cryptoParams2.SetPlaintextModulus(BigBinaryInteger::TWO);
//	cryptoParams2.SetPlaintextModulus(plaintextm);
	cryptoParams2.SetDistributionParameter(stdDev);
	cryptoParams2.SetRelinWindow(1);
	cryptoParams2.SetElementParams(params);
	cryptoParams2.SetDiscreteGaussianGenerator(dgg);

	Ciphertext<ILVectorArray2n> cipherText2;
	cipherText2.SetCryptoParameters(cryptoParams2);


	LPPublicKeyLTV<ILVectorArray2n> pk2(cryptoParams2);
	LPPrivateKeyLTV<ILVectorArray2n> sk2(cryptoParams2);

	LPPublicKeyLTV<ILVectorArray2n> pk3(cryptoParams2);
	LPPrivateKeyLTV<ILVectorArray2n> sk3(cryptoParams2);

	std::bitset<FEATURESETSIZE> mask (std::string("1000011"));
	LPPublicKeyEncryptionSchemeLTV<ILVectorArray2n> algorithm2(mask);

	//LPAlgorithmLTV<ILVectorArray2n> algorithm2;

	algorithm2.KeyGen(&pk2, &sk2);
	algorithm2.KeyGen(&pk3, &sk3);

	algorithm2.Encrypt(pk2, ptxt, &cipherText2);

	algorithm2.Decrypt(sk2, cipherText2, &ctxtd);

	
	cout << "Decrypted value ILVectorArray2n: \n" << endl;
	cout << ctxtd<< "\n" << endl;

	LPKeySwitchHintLTV<ILVectorArray2n> keySwitchHint;

	algorithm2.m_algorithmLeveledSHE->KeySwitchHintGen(sk2,sk3, &keySwitchHint);
	Ciphertext<ILVectorArray2n> cipherText3(algorithm2.m_algorithmLeveledSHE->KeySwitch(keySwitchHint, cipherText2));

	algorithm2.Decrypt(sk3, cipherText3, &ctxtd);

	cout << "Decrypted after MOD Reduce ILVectorArray2n: \n" << endl;
	
	cout << ctxtd<< "\n" << endl;
	
}