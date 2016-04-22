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
void DecomposeTest();
void DecomposeTestDoubleCRT();
void RingReduceTest();
void ModReduceTest();
void RingReduceDoubleCRTTest();
void RingReduceSingleCRTTest();
void ModReduceNew();
void ModReduceGyana();
void KeySwitchTestNewAPI();
void RingReduceDCRTTest();
void RingReduceSingleCRTTest();
void NextQTest();
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


//	NTRU_DCRT();

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

	ModReduceNew();

//	ModReduceGyana();
	
	//KeySwitchTestNewAPI(); 

//	RingReduceDCRTTest();
//	RingReduceSingleCRTTest();
	//RingReduceDCRTTest();

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

	usint m = 16;

	const ByteArray plaintext = "I";
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
	//	cout << q << endl;
		rootsOfUnity[i] = RootOfUnity(m,moduli[i]);
	//	cout << rootsOfUnity[i] << endl;
		modulus = modulus* moduli[i];
	
	}

	cout << "big modulus: " << modulus << endl;
	DiscreteGaussianGenerator dgg(modulus,stdDev);

	ILDCRTParams params(rootsOfUnity, m, moduli,modulus);

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

void DecomposeTest(){

	usint m = 16;
	float stdDev = 4;

	BigBinaryInteger q("1");
	DiscreteGaussianGenerator dgg(q,stdDev);

	lbcrypto::NextQ(q, BigBinaryInteger::TWO,m,BigBinaryInteger("4"), BigBinaryInteger("4"));	
	BigBinaryInteger rootOfUnity;

	rootOfUnity = RootOfUnity(m,q);

	cout << "Modulus is" << q << endl;
	cout << "RootOfUnity is" << rootOfUnity << endl;

//	DiscreteGaussianGenerator dgg(q,stdDev);

	ILParams ilParams(m,q,rootOfUnity);

	ILVector2n ilVector2n(dgg,ilParams,Format::COEFFICIENT);

	ilVector2n.PrintValues();

	ILVector2n ilVectorDecomposed;

	// ilVectorDecomposed = ilVector2n.Decompose();

	ilVectorDecomposed.PrintValues();

}

void DecomposeTestDoubleCRT(){

	usint m = 16;

	float stdDev = 2;

	usint size = 2;

	ByteArrayPlaintextEncoding ctxtd;

	vector<BigBinaryInteger> moduli(size);

	vector<BigBinaryInteger> rootsOfUnity(size);

	BigBinaryInteger q("1");
	BigBinaryInteger temp;
	BigBinaryInteger modulus("1");

	for(int i=0; i < size;i++){
        lbcrypto::NextQ(q, BigBinaryInteger::TWO,m,BigBinaryInteger("4"), BigBinaryInteger("4"));
		moduli[i] = q;
		rootsOfUnity[i] = RootOfUnity(m,moduli[i]);
		modulus = modulus* moduli[i];
		
	}

	DiscreteGaussianGenerator dgg(modulus,stdDev);

	ILDCRTParams params(rootsOfUnity, m, moduli,modulus);
	
	ILVectorArray2n ilVectorArray2n(dgg, params, Format::COEFFICIENT);
	ilVectorArray2n.PrintValues();

	//ILVectorArray2n ilVectorArray2nDecompose;

	//ilVectorArray2nDecompose = ilVectorArray2n.Decompose();
	//ilVectorArray2nDecompose.PrintValues();

	//cout << ilVectorArray2nDecompose.GetParams().GetCyclotomicOrder() << endl;

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

	ILDCRTParams params(rootsOfUnity, m, moduli,modulus);

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

	ILDCRTParams params(rootsOfUnity, m, moduli,modulus);

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

void ModReduceGyana() {
	usint m = 8;
	float stdDev = 8;

	const BigBinaryInteger plainTextMod("2");

	const BigBinaryInteger q1("17729");
	const BigBinaryInteger q2("17761");

	DiscreteGaussianGenerator dgg1(q1, 4);
	DiscreteGaussianGenerator dgg2(q2, 4);

	auto root1 = RootOfUnity(m, q1);
	auto root2 = RootOfUnity(m, q2);

	cout<< "root1: "<<root1<<endl;
	cout<< "root2: "<<root2<<endl;


	BigBinaryVector f1(m / 2);
	BigBinaryVector f2(m / 2);

	f1.SetValAtIndex(0, BigBinaryInteger("17726"));
	//f1.SetValAtIndex(1, BigBinaryInteger("2"));
	f1.SetValAtIndex(1, BigBinaryInteger("2"));
	f1.SetValAtIndex(2, BigBinaryInteger("0"));
	f1.SetValAtIndex(3, BigBinaryInteger("0"));
	f1.SetModulus(q1);

	f2.SetValAtIndex(0, BigBinaryInteger("17758"));
	f2.SetValAtIndex(1, BigBinaryInteger("2"));
	//f2.SetValAtIndex(2, BigBinaryInteger("17757"));
	//f2.SetValAtIndex(2, BigBinaryInteger("17757"));
	f2.SetValAtIndex(2, BigBinaryInteger("0"));
	f2.SetValAtIndex(3, BigBinaryInteger("0"));
	f2.SetModulus(q2);

	//f1 = dgg1.GenerateIdentity(m/2,q1);
	//f2 = dgg2.GenerateIdentity(m/2,q2);
	//f1.SetValAtIndex(0, BigBinaryInteger("3")); //2115
	//f2.SetValAtIndex(0, BigBinaryInteger("3"));

	std::cout << "f1:" << f1 << std::endl;
	std::cout << "f2:" << f2 << std::endl;

	auto F1 = ChineseRemainderTransformFTT::GetInstance().ForwardTransform(f1, root1, m);
	std::cout << "F1:" << F1 << std::endl;
	auto F1InverseEval = F1.ModInverse();
	std::cout << "F1InverseEval:" << F1InverseEval << std::endl;

	//std::cout << F1*F1InverseEval << std::endl;
	auto F2 = ChineseRemainderTransformFTT::GetInstance().ForwardTransform(f2, root2, m);
	std::cout << "F2:" << F2 << std::endl;
	auto F2InverseEval = F2.ModInverse();
	std::cout << "F2InverseEval:" << F2InverseEval << std::endl;

	auto f1InverseCoeff = ChineseRemainderTransformFTT::GetInstance().InverseTransform(F1InverseEval, root1, m);
	auto f2InverseCoeff = ChineseRemainderTransformFTT::GetInstance().InverseTransform(F2InverseEval, root2, m);

	std::cout << "f1InverseCoeff:" << f1InverseCoeff << endl;
	std::cout << "f2InverseCoeff:" << f2InverseCoeff << endl;

	auto m1 = dgg1.GenerateIdentity(m / 2, q1);
	m1.SetValAtIndex(2, BigBinaryInteger::ONE);
	std::cout << "m1:" << m1 << endl;
	auto m2 = dgg2.GenerateIdentity(m / 2, q2);
	m2.SetValAtIndex(2, BigBinaryInteger::ONE);
	std::cout << "m2:" << m2 << endl;

	auto M1 = ChineseRemainderTransformFTT::GetInstance().ForwardTransform(m1, root1, m);
	std::cout << "M1:" << M1 << std::endl;
	auto M2 = ChineseRemainderTransformFTT::GetInstance().ForwardTransform(m2, root2, m);
	std::cout << "M2:" << M2 << std::endl;


	BigBinaryVector e1(m / 2);
	BigBinaryVector e2(m / 2);

	e1.SetValAtIndex(0, BigBinaryInteger("2"));
	//e1.SetValAtIndex(1, BigBinaryInteger("2"));
	e1.SetValAtIndex(1, BigBinaryInteger("4"));
	e1.SetValAtIndex(2, BigBinaryInteger("17725"));
	e1.SetValAtIndex(3, BigBinaryInteger("3"));
	e1.SetModulus(q1);

	e2.SetValAtIndex(0, BigBinaryInteger("2"));
	e2.SetValAtIndex(1, BigBinaryInteger("4"));
	//e2.SetValAtIndex(2, BigBinaryInteger("17757"));
	//e2.SetValAtIndex(2, BigBinaryInteger("17757"));
	e2.SetValAtIndex(2, BigBinaryInteger("17757"));
	e2.SetValAtIndex(3, BigBinaryInteger("3"));
	e2.SetModulus(q2);

	auto E1 = ChineseRemainderTransformFTT::GetInstance().ForwardTransform(e1, root1, m);
	auto E2 = ChineseRemainderTransformFTT::GetInstance().ForwardTransform(e2, root2, m);

	BigBinaryVector s1(m / 2);
	BigBinaryVector s2(m / 2);

	s1.SetValAtIndex(0, BigBinaryInteger("3"));
	//g1.SetValAtIndex(1, BigBinaryInteger("2"));
	s1.SetValAtIndex(1, BigBinaryInteger("3"));
	s1.SetValAtIndex(2, BigBinaryInteger("17725"));
	s1.SetValAtIndex(3, BigBinaryInteger("2"));
	s1.SetModulus(q1);

	s2.SetValAtIndex(0, BigBinaryInteger("3"));
	s2.SetValAtIndex(1, BigBinaryInteger("3"));
	//g2.SetValAtIndex(2, BigBinaryInteger("17757"));
	//g2.SetValAtIndex(2, BigBinaryInteger("17757"));
	s2.SetValAtIndex(2, BigBinaryInteger("17757"));
	s2.SetValAtIndex(3, BigBinaryInteger("2"));
	s2.SetModulus(q2);

	auto S1 = ChineseRemainderTransformFTT::GetInstance().ForwardTransform(s1, root1, m);
	auto S2 = ChineseRemainderTransformFTT::GetInstance().ForwardTransform(s2, root2, m);

	BigBinaryVector g1(m / 2);
	BigBinaryVector g2(m / 2);

	g1.SetValAtIndex(0, BigBinaryInteger("3"));
	//g1.SetValAtIndex(1, BigBinaryInteger("2"));
	g1.SetValAtIndex(1, BigBinaryInteger("3"));
	g1.SetValAtIndex(2, BigBinaryInteger("17725"));
	g1.SetValAtIndex(3, BigBinaryInteger("2"));
	g1.SetModulus(q1);

	g2.SetValAtIndex(0, BigBinaryInteger("3"));
	g2.SetValAtIndex(1, BigBinaryInteger("3"));
	//g2.SetValAtIndex(2, BigBinaryInteger("17757"));
	//g2.SetValAtIndex(2, BigBinaryInteger("17757"));
	g2.SetValAtIndex(2, BigBinaryInteger("17757"));
	g2.SetValAtIndex(3, BigBinaryInteger("2"));
	g2.SetModulus(q2);

	auto G1 = ChineseRemainderTransformFTT::GetInstance().ForwardTransform(g1, root1, m);
	auto G2 = ChineseRemainderTransformFTT::GetInstance().ForwardTransform(g2, root2, m);
	std::cout << "G1:" << G1 << std::endl;
	std::cout << "G2:" << G2 << std::endl;

	auto publicKey1 = G1*F1InverseEval*plainTextMod;
	auto publicKey2 = G2*F2InverseEval*plainTextMod;
	std::cout << "publicKey1:" << publicKey1 << std::endl;
	std::cout << "publicKey2:" << publicKey2 << std::endl;

	E1 = E1*plainTextMod;
	E2 = E2*plainTextMod;

	auto C1 = S1*G1*F1InverseEval*plainTextMod + M1 + E1;
	std::cout << "C1:" << C1 << std::endl;
	auto C2 = S2*G2*F2InverseEval*plainTextMod + M2 + E2;
	std::cout << "C2:" << C2 << std::endl;

	auto c1 = ChineseRemainderTransformFTT::GetInstance().InverseTransform(C1, root1, m);
	auto c2 = ChineseRemainderTransformFTT::GetInstance().InverseTransform(C2, root2, m);

	std::cout << "cipherText, c1: " << c1 << std::endl;
	std::cout << "cipherText, c2: " << c2 << std::endl;

	auto cf1 = ChineseRemainderTransformFTT::GetInstance().InverseTransform(C1*F1, root1, m);
	auto cf2 = ChineseRemainderTransformFTT::GetInstance().InverseTransform(C2*F2, root2, m);

	std::cout << "cipherText, cf1: " << cf1 << std::endl;
	std::cout << "cipherText, cf2: " << cf2 << std::endl;

	auto mr1 = cf1.ModByTwo();
	auto mr2 = cf2.ModByTwo();

	std::cout << "cipherText, mr1: " << mr1 << std::endl;
	std::cout << "cipherText, mr2: " << mr2 << std::endl;

	auto d(c2);

	d.SwitchModulus(plainTextMod*q2);
	cout << "d after switch modulus to 2*q2:" << endl;
	cout << d << endl;

	d = d*(q2 - BigBinaryInteger::ONE);

	cout << "d after multiplying with vqt-1:" << endl;
	cout << d << endl;

	auto Delta1(d);
	auto Delta2(d);

	//cout << Delta1 << endl;
	//cout << Delta2 << endl;

	Delta1.SwitchModulus(q1);
	Delta2.SwitchModulus(q2);

	cout << "delta DCRT:" << endl;
	cout << Delta1 << endl;
	cout << Delta2 << endl;


	auto DeltaPrime1 = Delta1 + c1;
	auto DeltaPrime2 = Delta2 + c2;

	cout << "delta DCRT + ciphertext:" << endl;
	std::cout << DeltaPrime1 << std::endl;
	std::cout << DeltaPrime2 << std::endl;


	auto qtInverse = q2.Mod(q1).ModInverse(q1);
	cout << "q2 inverse mod q1:" << qtInverse << std::endl;

	DeltaPrime1 = DeltaPrime1*qtInverse;
	cout << "DeltaPrime1: " << DeltaPrime1 << std::endl;
	cout<< DeltaPrime1 <<endl;
	//DeltaPrime2 = DeltaPrime2*qtInverse;

	auto DeltaPrime1Eval = ChineseRemainderTransformFTT::GetInstance().ForwardTransform(DeltaPrime1, root1, m);

	auto DeltaPrimeCFEval = DeltaPrime1Eval*F1;

	auto DeltaPrimeCFCoeff = ChineseRemainderTransformFTT::GetInstance().InverseTransform(DeltaPrimeCFEval, root1, m);

	cout << DeltaPrimeCFCoeff << endl;

	auto DeltaPrime1Mess = DeltaPrimeCFCoeff.ModByTwo();

	cout << DeltaPrime1Mess << endl;
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

	ILDCRTParams params(rootsOfUnity, m, moduli,modulus);

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

void NextQTest(){
	BigBinaryInteger q("1");
	BigBinaryInteger temp;
	BigBinaryInteger modulus("1");

		vector<BigBinaryInteger> moduli(10);


	for(int i=0; i < 10;i++){
        lbcrypto::NextQ(q, BigBinaryInteger::TWO,2048,BigBinaryInteger("4"), BigBinaryInteger("4"));
		moduli[i] = q;
		cout << moduli[i] << endl;
	//	rootsOfUnity[i] = RootOfUnity(m,moduli[i]);
	//	cout << rootsOfUnity[i] << endl;
		modulus = modulus* moduli[i];
	
	}

	cout << modulus;


}