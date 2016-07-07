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

#include "../../lib/math/nbtheory.h"
#include "../../lib/math/distrgen.h"

#include "../../lib/lattice/ilvector2n.h"
#include "../../lib/lattice/ilvectorarray2n.h"
#include "../../lib/crypto/cryptocontext.h"
#include "time.h"

#include <chrono>
#include "../../lib/utils/debug.h"

using namespace std;
using namespace lbcrypto;

//double currentDateTime();
void NTRU_DCRT();
double currentDateTime();
void SparseKeyGenTest();
void SparseKeyGenTestDoubleCRT();
void LevelCircuitEvaluation();
void LevelCircuitEvaluation1();
void LevelCircuitEvaluation2();
void MultTest();
void RingReduceTest();
void RingReduceDCRTTest();
void TestParameterSelection();

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


	//MultTest();
//	RingReduceDCRTTest();

//	NTRU_DCRT();
	//LevelCircuitEvaluation();
	//LevelCircuitEvaluation1();
//	LevelCircuitEvaluation2();

	TestParameterSelection();

	std::cin.get();
	ChineseRemainderTransformFTT::GetInstance().Destroy();
	NumberTheoreticTransform::GetInstance().Destroy();

	return 0;
}


// double currentDateTime()
// {

// 	std::chrono::time_point<std::chrono::system_clock> now = std::chrono::system_clock::now();

//     time_t tnow = std::chrono::system_clock::to_time_t(now);
//     tm *date = localtime(&tnow);
//     date->tm_hour = 0;
//     date->tm_min = 0;
//     date->tm_sec = 0;

//     auto midnight = std::chrono::system_clock::from_time_t(mktime(date));

// 	return std::chrono::duration <double, std::milli>(now - midnight).count();
// }

void NTRU_DCRT() {

	double diff, start, finish;

	start = currentDateTime();

	usint m = 1024;

	const ByteArray plaintext = "I am a good boy!";
	//const ByteArray plaintext = "I";
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
	DiscreteGaussianGenerator dgg(stdDev);

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

/*<<<<<<< HEAD:src/Source_dcrt.cpp
	Ciphertext<ILVectorArray2n> cipherText;
	cipherText.SetCryptoParameters(cryptoParams);
=======*/
	Ciphertext<ILVectorArray2n> cipherText;
	cipherText.SetCryptoParameters(&cryptoParams);
// >>>>>>> master:src/demo/pre/Source_dcrt.cpp


	LPPublicKeyLTV<ILVectorArray2n> pk(cryptoParams);
	LPPrivateKeyLTV<ILVectorArray2n> sk(cryptoParams);

	//std::bitset<FEATURESETSIZE> mask (std::string("000011"));
	LPPublicKeyEncryptionSchemeLTV<ILVectorArray2n> algorithm2;
	algorithm2.Enable(ENCRYPTION);

	//LPAlgorithmLTV<ILVectorArray2n> algorithm;

	algorithm2.KeyGen(&pk, &sk);

	algorithm2.Encrypt(pk, ptxt, &cipherText);

	algorithm2.Decrypt(sk, cipherText, &ctxtd);

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

void MultTest(){

	BigBinaryInteger a("8589988480");
	const BigBinaryInteger modulus("42949942405");

	BigBinaryVector bbv(4);
	bbv.SetModulus(modulus);
	bbv.SetValAtIndex(0,"295979831");
	bbv.SetValAtIndex(1,"1430148772");
	bbv.SetValAtIndex(2,"39566279604");
	bbv.SetValAtIndex(3,"824376828");

	auto result = bbv*a;

	std::cout<< result << std::endl ;

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

void LevelCircuitEvaluation(){
	usint m = 8;
	float stdDev = 4;
	usint size = 2;
	BigBinaryInteger plainTextModulus(BigBinaryInteger::FIVE);
	ByteArrayPlaintextEncoding ctxtd;
	vector<BigBinaryInteger> moduli(size);
	vector<BigBinaryInteger> rootsOfUnity(size);

	BigBinaryInteger q("1");
	BigBinaryInteger temp;
	BigBinaryInteger modulus("1");
	moduli[1] = BigBinaryInteger("2199023288321");
	moduli[0] = BigBinaryInteger("8589987841");

	for(int i=0; i < size; i++){
        // lbcrypto::NextQ(q, plainTextModulus,m,BigBinaryInteger("4"), BigBinaryInteger("4"));
		// moduli[i] = q;
		rootsOfUnity[i] = RootOfUnity(m,moduli[i]);
		cout << moduli[i] << endl;
		cout << rootsOfUnity[i] << endl;
	}

	DiscreteGaussianGenerator dgg(stdDev);
	ILDCRTParams ildcrtParams(rootsOfUnity, m, moduli);

	ILParams ilParams0(m, moduli[0], rootsOfUnity[0]);
	ILParams ilParams1(m, moduli[1], rootsOfUnity[1]);

	LPCryptoParametersLTV<ILVectorArray2n> cryptoParams;
	cryptoParams.SetPlaintextModulus(plainTextModulus);
	cryptoParams.SetDistributionParameter(stdDev);
	cryptoParams.SetRelinWindow(1);
	cryptoParams.SetElementParams(ildcrtParams);
	cryptoParams.SetDiscreteGaussianGenerator(dgg);

	/*vector<ILVector2n> levelsSk(size);

	ILVector2n level0Sk(ilParams0, Format::COEFFICIENT);
	BigBinaryVector bbv0Sk(m/2, moduli[0]);
	bbv0Sk.SetValAtIndex(0, BigBinaryInteger("1"));
	bbv0Sk.SetValAtIndex(1, BigBinaryInteger("2"));
	bbv0Sk.SetValAtIndex(2, BigBinaryInteger("3"));
	bbv0Sk.SetValAtIndex(3, BigBinaryInteger("4"));
	level0Sk.SetValues(bbv0Sk, Format::COEFFICIENT);

	ILVector2n level1Sk(ilParams1, Format::COEFFICIENT);
	BigBinaryVector bbv1Sk(m/2, moduli[1]);
	bbv1Sk.SetValAtIndex(0, BigBinaryInteger("1"));
	bbv1Sk.SetValAtIndex(1, BigBinaryInteger("2"));
	bbv1Sk.SetValAtIndex(2, BigBinaryInteger("3"));
	bbv1Sk.SetValAtIndex(3, BigBinaryInteger("4"));
	level1Sk.SetValues(bbv1Sk, Format::COEFFICIENT);

	levelsSk[0] = level0Sk;
	levelsSk[1] = level1Sk;

	ILVectorArray2n skElement(levelsSk);


	// ------------------ Set pk ----------------------//

	vector<ILVector2n> levelsPk(size);

	ILVector2n level0Pk(ilParams0, Format::COEFFICIENT);
	BigBinaryVector bbv0Pk(m/2, moduli[0]);
	bbv0Pk.SetValAtIndex(0, BigBinaryInteger("1"));
	bbv0Pk.SetValAtIndex(1, BigBinaryInteger("0"));
	bbv0Pk.SetValAtIndex(2, BigBinaryInteger("0"));
	bbv0Pk.SetValAtIndex(3, BigBinaryInteger("0"));
	level0Pk.SetValues(bbv0Pk, Format::COEFFICIENT);

	ILVector2n level1Pk(ilParams1, Format::COEFFICIENT);
	BigBinaryVector bbv1Pk(m/2, moduli[1]);
	bbv1Pk.SetValAtIndex(0, BigBinaryInteger("1"));
	bbv1Pk.SetValAtIndex(1, BigBinaryInteger("0"));
	bbv1Pk.SetValAtIndex(2, BigBinaryInteger("0"));
	bbv1Pk.SetValAtIndex(3, BigBinaryInteger("0"));
	level1Pk.SetValues(bbv1Pk, Format::COEFFICIENT);

	levelsPk[0] = level0Pk;
	levelsPk[1] = level1Pk;

	ILVectorArray2n pkElement(levelsPk);*/

	// -------------------------- end Set pk ----------------------//

	// ------------------ Set cipherText Element ----------------------//

	vector<ILVector2n> levelsCipherTextElement(size);

	ILVector2n level0CipherTextElement(ilParams0, Format::COEFFICIENT);
	BigBinaryVector bbv0CipherTextElement(m/2, moduli[0]);
	bbv0CipherTextElement.SetValAtIndex(0, BigBinaryInteger("2"));
	bbv0CipherTextElement.SetValAtIndex(1, BigBinaryInteger("0"));
	bbv0CipherTextElement.SetValAtIndex(2, BigBinaryInteger("0"));
	bbv0CipherTextElement.SetValAtIndex(3, BigBinaryInteger("0"));
	level0CipherTextElement.SetValues(bbv0CipherTextElement, Format::COEFFICIENT);

	ILVector2n level1CipherTextElement(ilParams1, Format::COEFFICIENT);
	BigBinaryVector bbv1CipherTextElement(m/2, moduli[1]);
	bbv1CipherTextElement.SetValAtIndex(0, BigBinaryInteger("2"));
	bbv1CipherTextElement.SetValAtIndex(1, BigBinaryInteger("0"));
	bbv1CipherTextElement.SetValAtIndex(2, BigBinaryInteger("0"));
	bbv1CipherTextElement.SetValAtIndex(3, BigBinaryInteger("0"));
	level1CipherTextElement.SetValues(bbv1CipherTextElement, Format::COEFFICIENT);

	levelsCipherTextElement[0] = level0CipherTextElement;
	levelsCipherTextElement[1] = level1CipherTextElement;

	ILVectorArray2n cipherTextElement(levelsCipherTextElement);

	cipherTextElement.PrintValues();

	// -------------------------- end Set cipherText Element ----------------------//

	// ------------------ Set cipherText1 Element ----------------------//

	vector<ILVector2n> levelsCipherText1Element(size);

	ILVector2n level0CipherText1Element(ilParams0, Format::COEFFICIENT);
	BigBinaryVector bbv0CipherText1Element(m/2, moduli[0]);
	bbv0CipherText1Element.SetValAtIndex(0, BigBinaryInteger("0"));
	bbv0CipherText1Element.SetValAtIndex(1, BigBinaryInteger("0"));
	bbv0CipherText1Element.SetValAtIndex(2, BigBinaryInteger("4"));
	bbv0CipherText1Element.SetValAtIndex(3, BigBinaryInteger("0"));
	level0CipherText1Element.SetValues(bbv0CipherText1Element, Format::COEFFICIENT);

	ILVector2n level1CipherText1Element(ilParams1, Format::COEFFICIENT);
	BigBinaryVector bbv1CipherText1Element(m/2, moduli[1]);
	bbv1CipherText1Element.SetValAtIndex(0, BigBinaryInteger("0"));
	bbv1CipherText1Element.SetValAtIndex(1, BigBinaryInteger("0"));
	bbv1CipherText1Element.SetValAtIndex(2, BigBinaryInteger("4"));
	bbv1CipherText1Element.SetValAtIndex(3, BigBinaryInteger("0"));
	level1CipherText1Element.SetValues(bbv1CipherText1Element, Format::COEFFICIENT);

	levelsCipherText1Element[0] = level0CipherText1Element;
	levelsCipherText1Element[1] = level1CipherText1Element;

	ILVectorArray2n cipherText1Element(levelsCipherText1Element);
	cipherText1Element.PrintValues();

	// -------------------------- end Set cipherText1 Element ----------------------//

	LPPublicKeyLTV<ILVectorArray2n> pk(cryptoParams);
	LPPrivateKeyLTV<ILVectorArray2n> sk(cryptoParams);

	std::bitset<FEATURESETSIZE> mask (std::string("1000011"));
	LPPublicKeyEncryptionSchemeLTV<ILVectorArray2n> algorithm(mask);

	/*sk.SetPrivateElement(skElement);
	pk.SetPublicElement(pkElement);*/

	algorithm.KeyGen(&pk, &sk);

	/*cout << "Printing sk values in COEFFICIENT: " << endl;
	auto skElementInCoeff(sk.GetPrivateElement());
	skElementInCoeff.SwitchFormat();
	skElementInCoeff.PrintValues();
	cout << "End Printing sk values in COEFFICIENT. " << endl;


	cout << "Printing pk values in COEFFICIENT: " << endl;
	auto pkElementInCoeff(pk.GetPublicElement());
	pkElementInCoeff.SwitchFormat();
	pkElementInCoeff.PrintValues();
	cout << "End Printing pk values in COEFFICIENT. " << endl;*/

	Ciphertext<ILVectorArray2n> cipherText;
	cipherText.SetCryptoParameters(&cryptoParams);
	cipherText.SetElement(cipherTextElement);

	Ciphertext<ILVectorArray2n> cipherText1;
	cipherText1.SetCryptoParameters(&cryptoParams);
	cipherText1.SetElement(cipherText1Element);

	algorithm.Encrypt(pk, &cipherText);
	algorithm.Encrypt(pk, &cipherText1);

	//Print
	/*cout << "Printing ciphertext values: " << endl;
	ILVectorArray2n c(cipherText.GetElement());
	c.SwitchFormat();
	c.PrintValues();*/

	cipherText.SetElement(cipherText.GetElement() * cipherText1.GetElement());

	/*cout << "Printing cipherText multiplied values in COEFFICIENT: " << endl;
	auto cipherTextElementInCoeff(cipherText.GetElement());
	cipherTextElementInCoeff.SwitchFormat();
	cipherTextElementInCoeff.PrintValues();
	cout << "End Printing cipherText multiplied values in COEFFICIENT. " << endl;*/

	sk.SetPrivateElement(sk.GetPrivateElement() * sk.GetPrivateElement());

	/*cout << "Printing skSquared values in COEFFICIENT: " << endl;
	auto skSquaredElementInCoeff(sk.GetPrivateElement());
	skSquaredElementInCoeff.SwitchFormat();
	skSquaredElementInCoeff.PrintValues();
	cout << "End Printing skSquared values in COEFFICIENT. " << endl;*/

	algorithm.Decrypt(sk, cipherText, &ctxtd);
}

void LevelCircuitEvaluation1(){

	usint m = 8;
	float stdDev = 4;
	usint size = 2;
	BigBinaryInteger plainTextModulus(BigBinaryInteger::FIVE);
	ByteArrayPlaintextEncoding ctxtd;
	vector<BigBinaryInteger> moduli(size);
	vector<BigBinaryInteger> rootsOfUnity(size);

	BigBinaryInteger q("1");
	BigBinaryInteger temp;
	BigBinaryInteger modulus("1");
	//moduli[0] = BigBinaryInteger("2199023288321");
	 moduli[0] = BigBinaryInteger("8589987841");
	// moduli[1] = BigBinaryInteger("2199023288321");
	q = moduli[0];
	lbcrypto::NextQ(q, plainTextModulus, m, BigBinaryInteger("4"), BigBinaryInteger("4"));
	moduli[1] = q;

	for(int i=0; i < size; i++){
        // lbcrypto::NextQ(q, plainTextModulus,m,BigBinaryInteger("4"));
        modulus = modulus * moduli[i];
		rootsOfUnity[i] = RootOfUnity(m,moduli[i]);
		cout << moduli[i] << endl;
		cout << rootsOfUnity[i] << endl;
	}

	vector<BigBinaryInteger> moduli1(moduli);
	vector<BigBinaryInteger> rootsOfUnity1(rootsOfUnity);
	moduli1.pop_back();
	rootsOfUnity1.pop_back();
	
	DiscreteGaussianGenerator dgg(stdDev);
	ILDCRTParams ildcrtParams(rootsOfUnity, m, moduli);
	ILDCRTParams ildcrtParams1(rootsOfUnity1, m, moduli1);

	LPCryptoParametersLTV<ILVectorArray2n> cryptoParams;
	cryptoParams.SetPlaintextModulus(plainTextModulus);
	cryptoParams.SetDistributionParameter(stdDev);
	cryptoParams.SetRelinWindow(1);
	cryptoParams.SetElementParams(ildcrtParams);
	cryptoParams.SetDiscreteGaussianGenerator(dgg);

	LPCryptoParametersLTV<ILVectorArray2n> cryptoParams1;
	cryptoParams1.SetPlaintextModulus(plainTextModulus);
	cryptoParams1.SetDistributionParameter(stdDev);
	cryptoParams1.SetRelinWindow(1);
	cryptoParams1.SetElementParams(ildcrtParams1);
	cryptoParams1.SetDiscreteGaussianGenerator(dgg);


	LPPublicKeyLTV<ILVectorArray2n> pk(cryptoParams);
	LPPrivateKeyLTV<ILVectorArray2n> sk(cryptoParams);

	LPPublicKeyLTV<ILVectorArray2n> pk1(cryptoParams);
	LPPrivateKeyLTV<ILVectorArray2n> sk1(cryptoParams);

	std::bitset<FEATURESETSIZE> mask (std::string("1000011"));
	LPPublicKeyEncryptionSchemeLTV<ILVectorArray2n> algorithm(mask);
	
	algorithm.KeyGen(&pk, &sk);
	algorithm.KeyGen(&pk1, &sk1);

	Ciphertext<ILVectorArray2n> cipherText1;
	cipherText1.SetCryptoParameters(&cryptoParams);
	ILVectorArray2n element1(ildcrtParams);
	element1.SwitchFormat();
	element1 = {2};
	element1.PrintValues();
	cipherText1.SetElement(element1);

	Ciphertext<ILVectorArray2n> cipherText2;
	cipherText2.SetCryptoParameters(&cryptoParams);
	ILVectorArray2n element2(ildcrtParams);
	element2.SwitchFormat();
	element2 = {2};
	element2.PrintValues();
	cipherText2.SetElement(element2);

	algorithm.Encrypt(pk, &cipherText1);
	algorithm.Encrypt(pk, &cipherText2);

	algorithm.Decrypt(sk, cipherText1, &ctxtd);
	algorithm.Decrypt(sk, cipherText2, &ctxtd);

	LPKeySwitchHintLTV<ILVectorArray2n> linearKeySwitchHint1, linearKeySwitchHint2, quadraticKeySwitchHint1, quadraticKeySwitchHint2;

	algorithm.m_algorithmLeveledSHE->KeySwitchHintGen(sk,sk1, &linearKeySwitchHint1);
	algorithm.m_algorithmLeveledSHE->QuadraticKeySwitchHintGen(sk,sk1, &quadraticKeySwitchHint1);

	///////////////////----------- Start LEVEL 1 Computation ---------------------/////////////////
	Ciphertext<ILVectorArray2n> cipherText3(cipherText1);
	cipherText3.SetElement(cipherText1.GetElement() * cipherText2.GetElement());

	cipherText3 = algorithm.m_algorithmLeveledSHE->KeySwitch(quadraticKeySwitchHint1, cipherText3);

	algorithm.Decrypt(sk1, cipherText3, &ctxtd);

	ILVectorArray2n pvElement1 = sk1.GetPrivateElement();
	sk1.SetCryptoParameters(&cryptoParams1);
	pvElement1.DropTower(pvElement1.GetTowerLength() - 1);
	sk1.SetPrivateElement(pvElement1);

	algorithm.m_algorithmLeveledSHE->ModReduce(&cipherText3);

	///////////////////----------- End LEVEL 1 Computation ---------------------/////////////////

	algorithm.Decrypt(sk1, cipherText3, &ctxtd);

	cout << "Final Decrypted value :\n" << endl;
	
	cout << ctxtd << "\n" << endl;


}

void LevelCircuitEvaluation2(){

	usint m = 8;
	float stdDev = 4;
	usint size = 3;
	BigBinaryInteger plainTextModulus(BigBinaryInteger::FIVE);
	vector<BigBinaryInteger> moduli(size);
	vector<BigBinaryInteger> rootsOfUnity(size);

	BigBinaryInteger q("1");
	BigBinaryInteger temp;
	BigBinaryInteger modulus("1");
	moduli[0] = BigBinaryInteger("2199023288321");
	q = moduli[0];
	lbcrypto::NextQ(q, plainTextModulus, m, BigBinaryInteger("4"), BigBinaryInteger("4"));
	moduli[1] = q;
	lbcrypto::NextQ(q, plainTextModulus, m, BigBinaryInteger("4"), BigBinaryInteger("4"));
	moduli[2] = q;
	
	for(int i=0; i < size; i++){
        // lbcrypto::NextQ(q, plainTextModulus,m,BigBinaryInteger("4"));
		modulus = modulus * moduli[i];
		rootsOfUnity[i] = RootOfUnity(m,moduli[i]);
		cout << moduli[i] << endl;
	}
	
	vector<BigBinaryInteger> moduli1(moduli);
	vector<BigBinaryInteger> rootsOfUnity1(rootsOfUnity);
	moduli1.pop_back();
	rootsOfUnity1.pop_back();
	
	DiscreteGaussianGenerator dgg(stdDev);
	ILDCRTParams params(rootsOfUnity, m, moduli);
	ILDCRTParams params1(rootsOfUnity1, m, moduli1);

	LPCryptoParametersLTV<ILVectorArray2n> cryptoParams;
	cryptoParams.SetPlaintextModulus(plainTextModulus);
	cryptoParams.SetDistributionParameter(stdDev);
	cryptoParams.SetRelinWindow(1);
	cryptoParams.SetElementParams(params);
	cryptoParams.SetDiscreteGaussianGenerator(dgg);

	LPCryptoParametersLTV<ILVectorArray2n> cryptoParams1;
	cryptoParams1.SetPlaintextModulus(plainTextModulus);
	cryptoParams1.SetDistributionParameter(stdDev);
	cryptoParams1.SetRelinWindow(1);
	cryptoParams1.SetElementParams(params1);
	cryptoParams1.SetDiscreteGaussianGenerator(dgg);

	Ciphertext<ILVectorArray2n> cipherText1;
	cipherText1.SetCryptoParameters(&cryptoParams);
	ILVectorArray2n element1(params);
	element1.SwitchFormat();
	element1 = {2};
	// element1.PrintValues();
	cipherText1.SetElement(element1);

	Ciphertext<ILVectorArray2n> cipherText2;
	cipherText2.SetCryptoParameters(&cryptoParams);
	ILVectorArray2n element2(params);
	element2.SwitchFormat();
	element2 = {3};
	cipherText2.SetElement(element2);

	Ciphertext<ILVectorArray2n> cipherText3;
	cipherText3.SetCryptoParameters(&cryptoParams);
	ILVectorArray2n element3(params);
	element3.SwitchFormat();
	element3 = {1};
	cipherText3.SetElement(element3);

	LPPublicKeyLTV<ILVectorArray2n> pk(cryptoParams);
	LPPrivateKeyLTV<ILVectorArray2n> sk(cryptoParams);

	LPPublicKeyLTV<ILVectorArray2n> pk1(cryptoParams);
	LPPrivateKeyLTV<ILVectorArray2n> sk1(cryptoParams);

	LPPublicKeyLTV<ILVectorArray2n> pk2(cryptoParams1);
	LPPrivateKeyLTV<ILVectorArray2n> sk2(cryptoParams1);

	std::bitset<FEATURESETSIZE> mask (std::string("1000011"));
	LPPublicKeyEncryptionSchemeLTV<ILVectorArray2n> algorithm(mask);
	
	algorithm.KeyGen(&pk, &sk);
	algorithm.KeyGen(&pk1, &sk1);
	algorithm.KeyGen(&pk2, &sk2);
	cout << "KeyGen Finished" << endl;
	/*cout << "Printing sk values: " << endl;
	sk.GetPrivateElement().PrintValues();

	cout << "Printing sk1 values: " << endl;
	sk1.GetPrivateElement().PrintValues();

	cout << "Printing sk2 values: " << endl;
	sk2.GetPrivateElement().PrintValues();*/

	algorithm.Encrypt(pk, &cipherText1);
	algorithm.Encrypt(pk, &cipherText2);
	algorithm.Encrypt(pk, &cipherText3);
	cout << "Encrypt Finished" << endl;
	//Print
	// cout << "Printing ciphertext1 values: " << endl;
	// cipherText1.GetElement().PrintValues();

	LPKeySwitchHintLTV<ILVectorArray2n> linearKeySwitchHint1, linearKeySwitchHint2, quadraticKeySwitchHint1, quadraticKeySwitchHint2;

	algorithm.m_algorithmLeveledSHE->KeySwitchHintGen(sk,sk1, &linearKeySwitchHint1);
	algorithm.m_algorithmLeveledSHE->QuadraticKeySwitchHintGen(sk,sk1, &quadraticKeySwitchHint1);

	ILVectorArray2n pvElement1 = sk1.GetPrivateElement();
	sk1.SetCryptoParameters(&cryptoParams1);
	pvElement1.DropTower(pvElement1.GetTowerLength() - 1);
	sk1.SetPrivateElement(pvElement1);

	algorithm.m_algorithmLeveledSHE->KeySwitchHintGen(sk1,sk2, &linearKeySwitchHint2);
	algorithm.m_algorithmLeveledSHE->QuadraticKeySwitchHintGen(sk1,sk2, &quadraticKeySwitchHint2);

	cout << "HintGen Finished" << endl;
	///////////////////----------- Start LEVEL 1 Computation ---------------------/////////////////
	Ciphertext<ILVectorArray2n> cipherText4(cipherText1);
	cipherText4.SetElement(cipherText1.GetElement() * cipherText2.GetElement());
	cipherText4 = algorithm.m_algorithmLeveledSHE->KeySwitch(quadraticKeySwitchHint1, cipherText4);
	// cipherText4.GetElement().PrintValues();

	Ciphertext<ILVectorArray2n> cipherText5(cipherText3);
	cipherText5 = algorithm.m_algorithmLeveledSHE->KeySwitch(linearKeySwitchHint1, cipherText5);
	// cipherText5.GetElement().PrintValues();

	Ciphertext<ILVectorArray2n> cipherText6(cipherText2);
	cipherText6.SetElement(cipherText2.GetElement() * cipherText3.GetElement());
	cipherText6 = algorithm.m_algorithmLeveledSHE->KeySwitch(quadraticKeySwitchHint1, cipherText6);
	// cipherText6.GetElement().PrintValues();
	cout << "STEP 1" << endl;
	algorithm.m_algorithmLeveledSHE->ModReduce(&cipherText4);
	cout << "STEP 2" << endl;
	algorithm.m_algorithmLeveledSHE->ModReduce(&cipherText5);
	cout << "STEP 3" << endl;
	algorithm.m_algorithmLeveledSHE->ModReduce(&cipherText6);

	cout << "Level1 Finished" << endl;
	///////////////////----------- End LEVEL 1 Computation ---------------------/////////////////

	///////////////////----------- Start LEVEL 2 Computation ---------------------/////////////////
	Ciphertext<ILVectorArray2n> cipherText7(cipherText4);
	cipherText7.SetElement(cipherText4.GetElement() * cipherText5.GetElement());
	cipherText7 = algorithm.m_algorithmLeveledSHE->KeySwitch(quadraticKeySwitchHint2, cipherText7);

	Ciphertext<ILVectorArray2n> cipherText8(cipherText6);
	cipherText8 = algorithm.m_algorithmLeveledSHE->KeySwitch(linearKeySwitchHint2, cipherText8);

	algorithm.m_algorithmLeveledSHE->ModReduce(&cipherText7);
	algorithm.m_algorithmLeveledSHE->ModReduce(&cipherText8);

	cout << "Level2 Finished" << endl;
	///////////////////----------- End LEVEL 2 Computation ---------------------/////////////////

	cipherText8.SetElement(cipherText7.GetElement() + cipherText8.GetElement());

	ILVectorArray2n pvElement2 = sk2.GetPrivateElement();
	pvElement2.DropTower(pvElement2.GetTowerLength() - 1);
	sk2.SetPrivateElement(pvElement2);
	
	ByteArrayPlaintextEncoding ctxtd;
	algorithm.Decrypt(sk2, cipherText8, &ctxtd);

	cout << "Final Decrypted value :\n" << endl;
	
	cout << ctxtd << "\n" << endl;

}

void RingReduceDCRTTest(){

	usint m = 16;

	const ByteArray plaintext = "M";
	ByteArrayPlaintextEncoding ptxt(plaintext);
	ptxt.Pad<ZeroPad>(m/16);

	float stdDev = 4;

	usint size = 2;

	std::cout << "tower size: " << size << std::endl;

	ByteArrayPlaintextEncoding ctxtd;

	vector<BigBinaryInteger> moduli(size);

	vector<BigBinaryInteger> rootsOfUnity(size);

	vector<BigBinaryInteger> sparseRootsOfUnity(size);

	BigBinaryInteger q("1");
	BigBinaryInteger temp;
	BigBinaryInteger modulus("1");

	for(int i=0; i < size;i++){
        lbcrypto::NextQ(q, BigBinaryInteger::TWO,m,BigBinaryInteger("4"), BigBinaryInteger("4"));
		moduli[i] = q;
		cout << "moduli:	"<< i << moduli[i] << endl;
		rootsOfUnity[i] = RootOfUnity(m,moduli[i]);
		sparseRootsOfUnity[i] = RootOfUnity(m/2,moduli[i]);
		cout << "rootsOfUnity:	"<< i << rootsOfUnity[i] << endl;
		cout << "sparseRootsOfUnity:	"<<sparseRootsOfUnity[i] << endl;
		modulus = modulus* moduli[i];	
	}

	cout << "big modulus: " << modulus << endl;

	DiscreteGaussianGenerator dgg(stdDev);
	ILDCRTParams params(rootsOfUnity, m, moduli);
	ILDCRTParams sparseParams(sparseRootsOfUnity, m/2, moduli);


	LPCryptoParametersLTV<ILVectorArray2n> cryptoParams;
	cryptoParams.SetPlaintextModulus(BigBinaryInteger::TWO);
	cryptoParams.SetDistributionParameter(stdDev);
	cryptoParams.SetRelinWindow(1);
	cryptoParams.SetElementParams(params);
	cryptoParams.SetDiscreteGaussianGenerator(dgg);

	LPCryptoParametersLTV<ILVectorArray2n> sparseCryptoParams;
	sparseCryptoParams.SetPlaintextModulus(BigBinaryInteger::TWO);
	sparseCryptoParams.SetDistributionParameter(stdDev);
	sparseCryptoParams.SetRelinWindow(1);
	sparseCryptoParams.SetElementParams(sparseParams);
	sparseCryptoParams.SetDiscreteGaussianGenerator(dgg);

	Ciphertext<ILVectorArray2n> cipherText;
	cipherText.SetCryptoParameters(&cryptoParams);

	LPPublicKeyLTV<ILVectorArray2n> pk(cryptoParams);
	LPPrivateKeyLTV<ILVectorArray2n> sk(cryptoParams);

	LPPublicKeyLTV<ILVectorArray2n> sparsePk(cryptoParams);
	LPPrivateKeyLTV<ILVectorArray2n> sparseSk(cryptoParams);

	LPPublicKeyLTV<ILVectorArray2n> sparsePkDecomposed(sparseCryptoParams);
	LPPrivateKeyLTV<ILVectorArray2n> sparseSkDecomposed(sparseCryptoParams);

	std::bitset<FEATURESETSIZE> mask ( std::string("1000011") );
	LPPublicKeyEncryptionSchemeLTV<ILVectorArray2n> algorithm2(mask);

	//KeyGens
	algorithm2.KeyGen(&pk, &sk);

	algorithm2.SparseKeyGen(sparsePk,sparseSk,dgg);


	/*sk2.GetPrivateElement().PrintValues();
	pk2.GetPublicElement().PrintValues();*/

	algorithm2.Encrypt(pk, ptxt, &cipherText);

	LPKeySwitchHintLTV<ILVectorArray2n> linearKeySwitchHint;

	algorithm2.m_algorithmLeveledSHE->KeySwitchHintGen(sk,sparseSk, &linearKeySwitchHint);

	//below 2 lines are to check whether sparse key switch works, sanity check
	//cipherText = algorithm2.m_algorithmLeveledSHE->KeySwitch(linearKeySwitchHint,cipherText);

	//algorithm2.Decrypt(sparseSk, cipherText, &ctxtd);

	algorithm2.m_algorithmLeveledSHE->RingReduce(&cipherText,linearKeySwitchHint);

	//decompose the sparseSK
	auto sparseSKElement = sparseSk.GetPrivateElement();

	sparseSKElement.Decompose();

	//sparseSKElement.SetRootOfUnity(cipherText.GetElement().GetRootsOfUnity());


	algorithm2.Decrypt(sparseSk, cipherText, &ctxtd);

	/*ctxtd.Unpad<ZeroPad>();

	cout << "Decrypted value ILVectorArray2n: \n" << endl;
	cout << ctxtd<< "\n" << endl;*/



	//algorithm2.m_algorithmLeveledSHE->RingReduce(&cipherText, &sk);
	
	algorithm2.Decrypt(sk, cipherText, &ctxtd);

	cout << "Decrypted after MOD Reduce ILVectorArray2n: \n" << endl;
	
	cout << ctxtd<< "\n" << endl;

}

//void RingReduceSingleCRTTest(){
//
//	usint m = 32;
//
//	const ByteArray plaintext = "M";
//	ByteArrayPlaintextEncoding ptxt(plaintext);
//	ptxt.Pad<ZeroPad>(m/16);
//
//	float stdDev = 4;
//
//	ByteArrayPlaintextEncoding ctxtd;
//	BigBinaryInteger q("1");
//	BigBinaryInteger temp;
//	BigBinaryInteger modulus("17729");
//	BigBinaryInteger rootOfUnity = lbcrypto::RootOfUnity(m,modulus);
//
//	cout << "big modulus: " << modulus << endl;
//	DiscreteGaussianGenerator dgg(modulus,stdDev);
//
//	ILParams params(m, modulus, rootOfUnity);
//
//	LPCryptoParametersLTV<ILVector2n> cryptoParams2;
//	cryptoParams2.SetPlaintextModulus(BigBinaryInteger::TWO);
//	cryptoParams2.SetDistributionParameter(stdDev);
//	cryptoParams2.SetRelinWindow(1);
//	cryptoParams2.SetElementParams(params);
//	cryptoParams2.SetDiscreteGaussianGenerator(dgg);
//
//	Ciphertext<ILVector2n> cipherText2;
//	cipherText2.SetCryptoParameters(cryptoParams2);
//
//	LPPublicKeyLTV<ILVector2n> pk2(cryptoParams2);
//	LPPrivateKeyLTV<ILVector2n> sk2(cryptoParams2);
//
//	std::bitset<FEATURESETSIZE> mask (std::string("1000011"));
//	LPPublicKeyEncryptionSchemeLTV<ILVector2n> algorithm2(mask);
//
//	algorithm2.KeyGen(&pk2, &sk2);
//
//	/*sk2.GetPrivateElement().PrintValues();
//	pk2.GetPublicElement().PrintValues();*/
//
//	algorithm2.Encrypt(pk2, ptxt, &cipherText2);
//	algorithm2.Decrypt(sk2, cipherText2, &ctxtd);
//
//	ctxtd.Unpad<ZeroPad>();
//
//	cout << "Decrypted value ILVectorArray2n: \n" << endl;
//	cout << ctxtd<< "\n" << endl;
//
//	algorithm2.m_algorithmLeveledSHE->RingReduce(&cipherText2, &sk2);
//	
//	algorithm2.Decrypt(sk2, cipherText2, &ctxtd);
//
//	cout << "Decrypted after MOD Reduce ILVectorArray2n: \n" << endl;
//	
//	cout << ctxtd<< "\n" << endl;
//
//}

void TestParameterSelection(){

double diff, start, finish;

	start = currentDateTime();

	usint m = 16;

	float stdDev = 4;

	usint size = 11;

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
		rootsOfUnity[i] = RootOfUnity(m,moduli[i]);
		modulus = modulus* moduli[i];
	
	}

	cout << "big modulus: " << modulus << endl;
	DiscreteGaussianGenerator dgg(stdDev);

	ILDCRTParams params(rootsOfUnity, m, moduli);

	LPCryptoParametersLTV<ILVectorArray2n> cryptoParams;
	cryptoParams.SetPlaintextModulus(BigBinaryInteger::TWO);
	cryptoParams.SetDistributionParameter(stdDev);
	cryptoParams.SetRelinWindow(1);
	cryptoParams.SetElementParams(params);
	cryptoParams.SetDiscreteGaussianGenerator(dgg);
	cryptoParams.SetAssuranceMeasure(6);
	cryptoParams.SetDepth(size-1);
	cryptoParams.SetSecurityLevel(1.006);

	usint n = 16;

	std::vector<BigBinaryInteger> moduliV(size);
	LPCryptoParametersLTV<ILVectorArray2n> cryptoParams2;

	cryptoParams.ParameterSelection(&cryptoParams2);
	//cryptoParams.ParameterSelection(n, moduliV);

	cout << "parameter selection test" << endl;
	cout << cryptoParams2.GetAssuranceMeasure() << endl;

	const ILDCRTParams &dcrtParams = static_cast< const ILDCRTParams& >(cryptoParams2.GetElementParams());
	std::vector<BigBinaryInteger> moduli2 = dcrtParams.GetModuli();

	for(usint i =0; i < moduliV.size();i++){
		 cout<< moduli2[i] << endl; 
	}

 }