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
void NextQ(BigBinaryInteger &q, const BigBinaryInteger &plainTextModulus, const usint &ringDimension, const BigBinaryInteger &sigma, const BigBinaryInteger &alpha);

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

	usint m = 2048;

	const ByteArray plaintext = "I am a good boy, who are you?";
	ByteArrayPlaintextEncoding ptxt(plaintext);
	ptxt.Pad<ZeroPad>(m/16);
//	ptxt.Pad<ZeroPad>(m/8);

	float stdDev = 4;

	usint size = 3;

	std::cout << "tower size: " << size << std::endl;

	ByteArrayPlaintextEncoding ctxtd;

	vector<BigBinaryInteger> moduli(size);

	vector<BigBinaryInteger> rootsOfUnity(size);

	BigBinaryInteger q("12313321");
	BigBinaryInteger temp;
	BigBinaryInteger modulus("1");

	for(int i=0; i < size;i++){
        NextQ(q, BigBinaryInteger::TWO,m,BigBinaryInteger("4"), BigBinaryInteger("4"));
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

	algorithm2.KeyGen(pk2, sk2);

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

void NextQ(BigBinaryInteger &q, const BigBinaryInteger &plainTextModulus, const usint &ringDimension, const BigBinaryInteger &sigma, const BigBinaryInteger &alpha) {
	BigBinaryInteger bigOne("1");
	BigBinaryInteger bigTwo("2");
	BigBinaryInteger bigSixteen("16");
	BigBinaryInteger lowerBound;
	BigBinaryInteger ringDimensions(ringDimension);

	lowerBound = bigSixteen * ringDimensions * sigma  * sigma * alpha;
	if (!(q >= lowerBound)) {
		q = lowerBound;
	}
	else {
		q = q + bigOne;
	}

	while (q.Mod(plainTextModulus) != bigOne) {
		q = q + bigOne;
	}

	BigBinaryInteger cyclotomicOrder = ringDimensions * bigTwo;

	while (q.Mod(cyclotomicOrder) != bigOne) {
		q = q + plainTextModulus;
	}

	BigBinaryInteger productValue = cyclotomicOrder * plainTextModulus;

	while (!MillerRabinPrimalityTest(q)) {
		q = q + productValue;
	}

	BigBinaryInteger gcd;
	gcd = GreatestCommonDivisor(q - BigBinaryInteger::ONE, ringDimensions);

	if(!(ringDimensions == gcd)){
		q = q + BigBinaryInteger::ONE;
	  	NextQ(q, plainTextModulus, ringDimension, sigma, alpha);
	}

}
