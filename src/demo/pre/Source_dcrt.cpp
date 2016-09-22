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

#include "../lib/palisade.h"
#include "../lib/palisadespace.h"

#include "../../lib/utils/cryptocontexthelper.h"
#include "../../lib/crypto/cryptocontext.cpp"
#include "../../lib/utils/cryptocontexthelper.cpp"

#include "../../lib/utils/cryptoutility.h"
#include "time.h"

#include <chrono>
#include "../../lib/utils/debug.h"
#include "../../lib/encoding/byteplaintextencoding.h"
#include "../../lib/encoding/intplaintextencoding.h"

//#include "testJson.h"
//#include "testJson.cpp"

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
void RingReduceTest();
void RingReduceDCRTTest();
void TestParameterSelection();
void FinalLeveledComputation();
void NTRUPRE(usint input);
void LevelCircuitEvaluation2WithCEM();
void ComposedEvalMultTest();
bool canRingReduce(usint ringDimension, std::vector<BigBinaryInteger> moduli, double rootHermiteFactor);
void RootsOfUnitTest();
void BenchMarking();
void FFTTest();
/**
 * @brief Input parameters for PRE example.
 */
struct SecureParams {
	usint m;			///< The ring parameter.
	string modulus;	///< The modulus
	string rootOfUnity;	///< The rootOfUnity
	usint relinWindow;		///< The relinearization window parameter.
};

#include <iterator>
int main() {
	FFTTest();
//	BenchMarking();
//	RootsOfUnitTest();
//	RingReduceTest();
//	RingReduceDCRTTest();
//	NTRUPRE(0);
	NTRU_DCRT();

	//LevelCircuitEvaluation();
	//LevelCircuitEvaluation1();
	//LevelCircuitEvaluation2();
	//	ComposedEvalMultTest();
	//	 FinalLeveledComputation();

//	TestParameterSelection();
	//LevelCircuitEvaluation2WithCEM();

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

void BenchMarking() {
	double diff, start, finish;
	std::unordered_map<usint, std::vector<double>> encryptTimer;
	std::unordered_map<usint, std::vector<double>> decryptTimer;

	usint m = 16;
	usint numberOfIterations = 100;
	usint numberOfTowers = 20;
	std::vector<double> encryptTimeTower(20);
//	encryptTimeTower.reserve(20);
	std::fill(encryptTimeTower.begin(), encryptTimeTower.end(), 0);
	encryptTimer.insert(std::make_pair(m, encryptTimeTower));

	std::vector<double> decryptTimeTower(20);
//	decryptTimeTower.reserve(19);
	std::fill(decryptTimeTower.begin(), decryptTimeTower.end(), 0);
	decryptTimer.insert(std::make_pair(m, decryptTimeTower));

	for (usint k = 0; k < numberOfIterations; k++) {
		for (usint i = 1; i <= 3; i++) {
			float stdDev = 4;

			BytePlaintextEncoding plaintext("N");

			BytePlaintextEncoding ctxtd;

			vector<BigBinaryInteger> moduli(i);

			vector<BigBinaryInteger> rootsOfUnity(i);

			BigBinaryInteger q("1");
			BigBinaryInteger temp;
			BigBinaryInteger modulus("1");

			for (int j = 0; j < i; j++) {
				lbcrypto::NextQ(q, BigBinaryInteger::TWO, m, BigBinaryInteger("4"), BigBinaryInteger("4"));
				moduli[j] = q;
				rootsOfUnity[j] = RootOfUnity(m, moduli[j]);
				modulus = modulus* moduli[j];
			}

			DiscreteGaussianGenerator dgg(stdDev);

			ILDCRTParams params(m, moduli, rootsOfUnity);

			LPCryptoParametersLTV<ILVectorArray2n> cryptoParams;
			cryptoParams.SetPlaintextModulus(BigBinaryInteger::TWO);
			cryptoParams.SetDistributionParameter(stdDev);
			cryptoParams.SetRelinWindow(1);
			cryptoParams.SetElementParams(params);
			cryptoParams.SetDiscreteGaussianGenerator(dgg);

			CryptoContext<ILVectorArray2n> cc = CryptoContextFactory<ILVectorArray2n>::getCryptoContextDCRT(&cryptoParams);
			cc.Enable(ENCRYPTION);
			cc.Enable(PRE);

			LPKeyPair<ILVectorArray2n> kp = cc.KeyGen();

			vector<shared_ptr<Ciphertext<ILVectorArray2n>>> ciphertext;

			start = currentDateTime();

			CryptoUtility<ILVectorArray2n>::Encrypt(cc.GetEncryptionAlgorithm(), *kp.publicKey, plaintext, &ciphertext);
			finish = currentDateTime();
			diff = finish - start;
			encryptTimer.at(m).at(i) += diff;

			BytePlaintextEncoding plaintextNew;

			start = currentDateTime();

			CryptoUtility<ILVectorArray2n>::Decrypt(cc.GetEncryptionAlgorithm(), *kp.secretKey, ciphertext, &plaintextNew);
			finish = currentDateTime();
			diff = finish - start;
            decryptTimer.at(m).at(i) += diff;
		}
	}
	for (int i = 1; i < 4; i++) {
		cout << encryptTimer.at(m).at(i)/100 << endl;
		cout << decryptTimer.at(m).at(i)/100 << endl;
		cout << endl;
	}

}

void NTRU_DCRT() {
	cout << "NTRU_DCRT" << endl;

	double diff, start, finish;

	start = currentDateTime();

	usint m = 16;
	m = 4096;

	const BytePlaintextEncoding plaintext = "I";

	float stdDev = 4;

	usint size = 2;

	std::cout << "tower size: " << size << std::endl;

	BytePlaintextEncoding ctxtd;

	vector<BigBinaryInteger> moduli(size);

	vector<BigBinaryInteger> rootsOfUnity(size);

	BigBinaryInteger q("1");
	BigBinaryInteger temp;
	BigBinaryInteger modulus("1");

	for(int i=0; i < size;i++){
		lbcrypto::NextQ(q, BigBinaryInteger::TWO,m,BigBinaryInteger("4"), BigBinaryInteger("4"));
		moduli[i] = q;
		cout << q << endl;
		rootsOfUnity[i] = RootOfUnity(m,moduli[i]);
	//	cout << rootsOfUnity[i] << endl;
		modulus = modulus* moduli[i];

	}

	cout << "big modulus: " << modulus << endl;
	DiscreteGaussianGenerator dgg(stdDev);

	ILDCRTParams params(m, moduli, rootsOfUnity);

	LPCryptoParametersLTV<ILVectorArray2n> cryptoParams;
	cryptoParams.SetPlaintextModulus(BigBinaryInteger::TWO);
	cryptoParams.SetDistributionParameter(stdDev);
	cryptoParams.SetRelinWindow(1);
	cryptoParams.SetElementParams(params);
	cryptoParams.SetDiscreteGaussianGenerator(dgg);

	CryptoContext<ILVectorArray2n> cc = CryptoContextFactory<ILVectorArray2n>::getCryptoContextDCRT(&cryptoParams);
	cc.Enable(ENCRYPTION);
	cc.Enable(PRE);

	bool successKeyGen=false;

	std::cout <<"\n" <<  "Running key generation..." << std::endl;

	start = currentDateTime();

	LPKeyPair<ILVectorArray2n> kp = cc.KeyGen();	// This is the core function call that generates the keys.

	finish = currentDateTime();
	diff = finish - start;

	cout<< "Key generation execution time: "<<"\t"<<diff<<" ms"<<endl;
	//fout<< "Key generation execution time: "<<"\t"<<diff<<" ms"<<endl;

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
	cout<<"\n"<<"original plaintext: "<<plaintext<<"\n"<<endl;
	//fout<<"\n"<<"original plaintext: "<<plaintext<<"\n"<<endl;

	vector<shared_ptr<Ciphertext<ILVectorArray2n>>> ciphertext;

	std::cout << "Running encryption..." << std::endl;

	start = currentDateTime();

	CryptoUtility<ILVectorArray2n>::Encrypt(cc.GetEncryptionAlgorithm(),*kp.publicKey,plaintext,&ciphertext);	// This is the core encryption operation.

	finish = currentDateTime();
	diff = finish - start;

	cout<< "Encryption execution time: "<<"\t"<<diff<<" ms"<<endl;
	//fout<< "Encryption execution time: "<<"\t"<<diff<<" ms"<<endl;

	////////////////////////////////////////////////////////////
	//Decryption
	////////////////////////////////////////////////////////////

	BytePlaintextEncoding plaintextNew;

	std::cout <<"\n"<< "Running decryption..." << std::endl;

	start = currentDateTime();

	DecryptResult result = CryptoUtility<ILVectorArray2n>::Decrypt(cc.GetEncryptionAlgorithm(),*kp.secretKey,ciphertext,&plaintextNew);  // This is the core decryption operation.

	finish = currentDateTime();
	diff = finish - start;

	cout<< "Decryption execution time: "<<"\t"<<diff<<" ms"<<endl;
	//fout<< "Decryption execution time: "<<"\t"<<diff<<" ms"<<endl;

	cout<<"\n"<<"decrypted plaintext (NTRU encryption): "<<plaintextNew<<"\n"<<endl;
	//fout<<"\n"<<"decrypted plaintext (NTRU encryption): "<<plaintextNew<<"\n"<<endl;

	if (!result.isValid) {
		std::cout<<"Decryption failed!"<<std::endl;
		exit(1);
	}

//	IntPlaintextEncoding intIn = { 2,4,6,8,10 };
//	IntPlaintextEncoding intOut;
//	vector<Ciphertext<ILVectorArray2n>> intCiphertext;
//	CryptoUtility<ILVectorArray2n>::Encrypt(algorithm,pk,intIn,&intCiphertext);
//	result = CryptoUtility<ILVectorArray2n>::Decrypt(algorithm,sk,intCiphertext,&intOut);
//
//	for( int i = 0; i < intIn.GetLength() ; i++ ) {
//		cout << intIn.at(i) << " ";
//	}
//	cout << endl << "::::::::::::" << endl;
//
//	for( int i = 0; i < intOut.GetLength() ; i++ ) {
//		cout << intOut.at(i) << " ";
//	}
//	cout << endl;
//
//	if(true) return;

	LPKeyPair<ILVectorArray2n> newKp = cc.GetEncryptionAlgorithm().KeyGen(cc);

	////////////////////////////////////////////////////////////
	//Perform the proxy re-encryption key generation operation.
	// This generates the keys which are used to perform the key switching.
	////////////////////////////////////////////////////////////

	LPEvalKeyNTRURelin<ILVectorArray2n> evalKey(cc);

	cout << "Running eval key gen" << endl;

	bool rval = CryptoUtility<ILVectorArray2n>::ReKeyGen(cc.GetEncryptionAlgorithm(), *newKp.publicKey, *newKp.secretKey, &evalKey);  // This is the core re-encryption operation.

	if( rval == false ) {
		cout << "EvalKeyGen failed!!!" << endl;
	}
	else {
		vector<ILVectorArray2n> av = evalKey.GetAVector();
		cout << "The eval key A vect size is " << av.size() << endl;

		vector<shared_ptr<Ciphertext<ILVectorArray2n>>> newCiphertext;

		cout << "Running re encryption" << endl;
		CryptoUtility<ILVectorArray2n>::ReEncrypt(cc.GetEncryptionAlgorithm(), evalKey, ciphertext, &newCiphertext);

		//cout<<"new CipherText - PRE = "<<newCiphertext.GetValues()<<endl;

		////////////////////////////////////////////////////////////
		//Decryption
		////////////////////////////////////////////////////////////

		BytePlaintextEncoding plaintextNew2;

		DecryptResult result1 = CryptoUtility<ILVectorArray2n>::Decrypt(cc.GetEncryptionAlgorithm(), *newKp.secretKey, newCiphertext, &plaintextNew2);

		if (!result1.isValid) {
			std::cout<<"Decryption failed!"<<std::endl;
			exit(1);
		}
	}

	std::cout << "Execution completed." << std::endl;


//	cout << "Running serialization testing:" << endl;
//
//	TestJsonParms<ILVectorArray2n> tjp;
//	BytePlaintextEncoding newPlaintext("1) SERIALIZE CRYPTO-OBJS TO FILE AS NESTED JSON STRUCTURES\n2) DESERIALIZE JSON FILES INTO CRYPTO-OBJS USED FOR CRYPTO-APIS\n3) Profit!!!!!");
//
//	tjp.ctx = ctx;
//	tjp.pk = &pk;
//	tjp.sk = &sk;
//	tjp.evalKey = &evalKey;
//	tjp.newSK = &newSK;
//
//	testJson<ILVectorArray2n>("DCRT", newPlaintext, &tjp, true);
}

void LevelCircuitEvaluation(){
	/*usint m = 8;
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
	ILDCRTParams ildcrtParams(m, moduli, rootsOfUnity);

	ILParams ilParams0(m, moduli[0], rootsOfUnity[0]);
	ILParams ilParams1(m, moduli[1], rootsOfUnity[1]);

	LPCryptoParametersLTV<ILVectorArray2n> cryptoParams;
	cryptoParams.SetPlaintextModulus(plainTextModulus);
	cryptoParams.SetDistributionParameter(stdDev);
	cryptoParams.SetRelinWindow(1);
	cryptoParams.SetElementParams(ildcrtParams);
	cryptoParams.SetDiscreteGaussianGenerator(dgg);

	// vector<ILVector2n> levelsSk(size);

	// ILVector2n level0Sk(ilParams0, Format::COEFFICIENT);
	// BigBinaryVector bbv0Sk(m/2, moduli[0]);
	// bbv0Sk.SetValAtIndex(0, BigBinaryInteger("1"));
	// bbv0Sk.SetValAtIndex(1, BigBinaryInteger("2"));
	// bbv0Sk.SetValAtIndex(2, BigBinaryInteger("3"));
	// bbv0Sk.SetValAtIndex(3, BigBinaryInteger("4"));
	// level0Sk.SetValues(bbv0Sk, Format::COEFFICIENT);

	// ILVector2n level1Sk(ilParams1, Format::COEFFICIENT);
	// BigBinaryVector bbv1Sk(m/2, moduli[1]);
	// bbv1Sk.SetValAtIndex(0, BigBinaryInteger("1"));
	// bbv1Sk.SetValAtIndex(1, BigBinaryInteger("2"));
	// bbv1Sk.SetValAtIndex(2, BigBinaryInteger("3"));
	// bbv1Sk.SetValAtIndex(3, BigBinaryInteger("4"));
	// level1Sk.SetValues(bbv1Sk, Format::COEFFICIENT);

	// levelsSk[0] = level0Sk;
	// levelsSk[1] = level1Sk;

	// ILVectorArray2n skElement(levelsSk);


	// // ------------------ Set pk ----------------------//

	// vector<ILVector2n> levelsPk(size);

	// ILVector2n level0Pk(ilParams0, Format::COEFFICIENT);
	// BigBinaryVector bbv0Pk(m/2, moduli[0]);
	// bbv0Pk.SetValAtIndex(0, BigBinaryInteger("1"));
	// bbv0Pk.SetValAtIndex(1, BigBinaryInteger("0"));
	// bbv0Pk.SetValAtIndex(2, BigBinaryInteger("0"));
	// bbv0Pk.SetValAtIndex(3, BigBinaryInteger("0"));
	// level0Pk.SetValues(bbv0Pk, Format::COEFFICIENT);

	// ILVector2n level1Pk(ilParams1, Format::COEFFICIENT);
	// BigBinaryVector bbv1Pk(m/2, moduli[1]);
	// bbv1Pk.SetValAtIndex(0, BigBinaryInteger("1"));
	// bbv1Pk.SetValAtIndex(1, BigBinaryInteger("0"));
	// bbv1Pk.SetValAtIndex(2, BigBinaryInteger("0"));
	// bbv1Pk.SetValAtIndex(3, BigBinaryInteger("0"));
	// level1Pk.SetValues(bbv1Pk, Format::COEFFICIENT);

	// levelsPk[0] = level0Pk;
	// levelsPk[1] = level1Pk;

	// ILVectorArray2n pkElement(levelsPk);

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

	LPPublicKey<ILVectorArray2n> pk(cryptoParams);
	LPPrivateKey<ILVectorArray2n> sk(cryptoParams);

	std::bitset<FEATURESETSIZE> mask (std::string("1000011"));
	LPPublicKeyEncryptionSchemeLTV<ILVectorArray2n> algorithm(mask);

	//sk.SetPrivateElement(skElement);
	//pk.SetPublicElement(pkElement);

	algorithm.KeyGen(&pk, &sk);

	// cout << "Printing sk values in COEFFICIENT: " << endl;
	// auto skElementInCoeff(sk.GetPrivateElement());
	// skElementInCoeff.SwitchFormat();
	// skElementInCoeff.PrintValues();
	// cout << "End Printing sk values in COEFFICIENT. " << endl;


	// cout << "Printing pk values in COEFFICIENT: " << endl;
	// auto pkElementInCoeff(pk.GetPublicElement());
	// pkElementInCoeff.SwitchFormat();
	// pkElementInCoeff.PrintValues();
	// cout << "End Printing pk values in COEFFICIENT. " << endl;

	Ciphertext<ILVectorArray2n> cipherText(&cryptoParams);
	cipherText.SetElement(cipherTextElement);

	Ciphertext<ILVectorArray2n> cipherText1(&cryptoParams);
	cipherText1.SetElement(cipherText1Element);

	algorithm.Encrypt(pk, &cipherText);
	algorithm.Encrypt(pk, &cipherText1);

	//Print
	// cout << "Printing ciphertext values: " << endl;
	// ILVectorArray2n c(cipherText.GetElement());
	// c.SwitchFormat();
	// c.PrintValues();

	cipherText.SetElement(cipherText.GetElement() * cipherText1.GetElement());

	// cout << "Printing cipherText multiplied values in COEFFICIENT: " << endl;
	// auto cipherTextElementInCoeff(cipherText.GetElement());
	// cipherTextElementInCoeff.SwitchFormat();
	// cipherTextElementInCoeff.PrintValues();
	// cout << "End Printing cipherText multiplied values in COEFFICIENT. " << endl;

	sk.SetPrivateElement(sk.GetPrivateElement() * sk.GetPrivateElement());

	// cout << "Printing skSquared values in COEFFICIENT: " << endl;
	// auto skSquaredElementInCoeff(sk.GetPrivateElement());
	// skSquaredElementInCoeff.SwitchFormat();
	// skSquaredElementInCoeff.PrintValues();
	// cout << "End Printing skSquared values in COEFFICIENT. " << endl;

	algorithm.Decrypt(sk, cipherText, &ctxtd);*/
}

void LevelCircuitEvaluation1(){
	/*
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
	ILDCRTParams ildcrtParams(m, moduli, rootsOfUnity);
	ILDCRTParams ildcrtParams1(m, moduli1, rootsOfUnity1);

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


	LPPublicKey<ILVectorArray2n> pk(cryptoParams);
	LPPrivateKey<ILVectorArray2n> sk(cryptoParams);

	LPPublicKey<ILVectorArray2n> pk1(cryptoParams);
	LPPrivateKey<ILVectorArray2n> sk1(cryptoParams);

	std::bitset<FEATURESETSIZE> mask (std::string("1000011"));
	LPPublicKeyEncryptionSchemeLTV<ILVectorArray2n> algorithm(mask);

	algorithm.KeyGen(&pk, &sk);
	algorithm.KeyGen(&pk1, &sk1);

	Ciphertext<ILVectorArray2n> cipherText1(&cryptoParams);
	ILVectorArray2n element1(ildcrtParams);
	element1.SwitchFormat();
	element1 = {2};
	element1.PrintValues();
	cipherText1.SetElement(element1);

	Ciphertext<ILVectorArray2n> cipherText2(&cryptoParams);
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

	algorithm.m_algorithmLeveledSHE->EvalMultKeyGen(sk,sk1, &linearKeySwitchHint1);
	algorithm.m_algorithmLeveledSHE->QuadraticEvalMultKeyGen(sk,sk1, &quadraticKeySwitchHint1);

	///////////////////----------- Start LEVEL 1 Computation ---------------------/////////////////
	Ciphertext<ILVectorArray2n> cipherText3(cipherText1);
	cipherText3.SetElement(cipherText1.GetElement() * cipherText2.GetElement());

	cipherText3 = algorithm.m_algorithmLeveledSHE->KeySwitch(quadraticKeySwitchHint1, cipherText3);

	algorithm.Decrypt(sk1, cipherText3, &ctxtd);

	ILVectorArray2n pvElement1 = sk1.GetPrivateElement();
	pvElement1.DropTower(pvElement1.GetTowerLength() - 1);
	sk1.SetPrivateElement(pvElement1);

	algorithm.m_algorithmLeveledSHE->ModReduce(&cipherText3);

	///////////////////----------- End LEVEL 1 Computation ---------------------/////////////////

	algorithm.Decrypt(sk1, cipherText3, &ctxtd);

	cout << "Final Decrypted value :\n" << endl;

	cout << ctxtd << "\n" << endl;
	 */

}

void LevelCircuitEvaluation2WithCEM(){
	/*
	usint m = 8192;
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
	ILDCRTParams params(m, moduli, rootsOfUnity);
	ILDCRTParams params1(m, moduli1, rootsOfUnity1);

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

	Ciphertext<ILVectorArray2n> cipherText1(&cryptoParams);
	ILVectorArray2n element1(params);
	element1.SwitchFormat();
	element1 = {2};
	// element1.PrintValues();
	cipherText1.SetElement(element1);

	Ciphertext<ILVectorArray2n> cipherText2(&cryptoParams);
	ILVectorArray2n element2(params);
	element2.SwitchFormat();
	element2 = {3};
	cipherText2.SetElement(element2);

	Ciphertext<ILVectorArray2n> cipherText3(&cryptoParams);
	ILVectorArray2n element3(params);
	element3.SwitchFormat();
	element3 = {1};
	cipherText3.SetElement(element3);

	LPPublicKey<ILVectorArray2n> pk(cryptoParams);
	LPPrivateKey<ILVectorArray2n> sk(cryptoParams);

	LPPublicKey<ILVectorArray2n> pk1(cryptoParams);
	LPPrivateKey<ILVectorArray2n> sk1(cryptoParams);

	LPPublicKey<ILVectorArray2n> pk2(cryptoParams1);
	LPPrivateKey<ILVectorArray2n> sk2(cryptoParams1);

	std::bitset<FEATURESETSIZE> mask (std::string("1000011"));
	LPPublicKeyEncryptionSchemeLTV<ILVectorArray2n> algorithm(mask);
	algorithm.Enable(SHE);
	algorithm.Enable(LEVELEDSHE);

	algorithm.KeyGen(&pk, &sk);
	algorithm.KeyGen(&pk1, &sk1);
	algorithm.KeyGen(&pk2, &sk2);
	cout << "KeyGen Finished" << endl;

	// cout << "Printing sk values: " << endl;
	// sk.GetPrivateElement().PrintValues();

	// cout << "Printing sk1 values: " << endl;
	// sk1.GetPrivateElement().PrintValues();

	// cout << "Printing sk2 values: " << endl;
	// sk2.GetPrivateElement().PrintValues();

	algorithm.Encrypt(pk, &cipherText1);
	algorithm.Encrypt(pk, &cipherText2);
	algorithm.Encrypt(pk, &cipherText3);
	cout << "Encrypt Finished" << endl;
	//Print
	// cout << "Printing ciphertext1 values: " << endl;
	// cipherText1.GetElement().PrintValues();

	LPKeySwitchHintLTV<ILVectorArray2n> linearKeySwitchHint1, linearKeySwitchHint2, quadraticKeySwitchHint1, quadraticKeySwitchHint2;

	algorithm.m_algorithmLeveledSHE->EvalMultKeyGen(sk,sk1, &linearKeySwitchHint1);
	algorithm.m_algorithmLeveledSHE->QuadraticEvalMultKeyGen(sk,sk1, &quadraticKeySwitchHint1);

	ILVectorArray2n pvElement1 = sk1.GetPrivateElement();
	pvElement1.DropTower(pvElement1.GetTowerLength() - 1);
	sk1.SetPrivateElement(pvElement1);

	algorithm.m_algorithmLeveledSHE->EvalMultKeyGen(sk1,sk2, &linearKeySwitchHint2);
	algorithm.m_algorithmLeveledSHE->QuadraticEvalMultKeyGen(sk1,sk2, &quadraticKeySwitchHint2);

	cout << "HintGen Finished" << endl;
	///////////////////----------- Start LEVEL 1 Computation ---------------------/////////////////
	Ciphertext<ILVectorArray2n> cipherText4(cipherText1);
	algorithm.m_algorithmLeveledSHE->ComposedEvalMult(cipherText1,cipherText2,quadraticKeySwitchHint1,&cipherText4);
	//cipherText4.SetElement(cipherText1.GetElement() * cipherText2.GetElement());
	//cipherText4 = algorithm.m_algorithmLeveledSHE->KeySwitch(quadraticKeySwitchHint1, cipherText4);
	// cipherText4.GetElement().PrintValues();

	Ciphertext<ILVectorArray2n> cipherText5(cipherText3);
	//cipherText5 = algorithm.m_algorithmLeveledSHE->KeySwitch(linearKeySwitchHint1, cipherText5);
	// cipherText5.GetElement().PrintValues();
	algorithm.m_algorithmLeveledSHE->LevelReduce(cipherText3,linearKeySwitchHint1,&cipherText5);

	Ciphertext<ILVectorArray2n> cipherText6(cipherText2);
	//cipherText6.SetElement(cipherText2.GetElement() * cipherText3.GetElement());
	//cipherText6 = algorithm.m_algorithmLeveledSHE->KeySwitch(quadraticKeySwitchHint1, cipherText6);
	// cipherText6.GetElement().PrintValues();
	//cout << "STEP 1" << endl;
	//algorithm.m_algorithmLeveledSHE->ModReduce(&cipherText4);
	//cout << "STEP 2" << endl;
	//algorithm.m_algorithmLeveledSHE->ModReduce(&cipherText5);
	//cout << "STEP 3" << endl;
	//algorithm.m_algorithmLeveledSHE->ModReduce(&cipherText6);
	algorithm.m_algorithmLeveledSHE->ComposedEvalMult(cipherText2,cipherText3,quadraticKeySwitchHint1,&cipherText6);

	cout << "Level1 Finished" << endl;
	///////////////////----------- End LEVEL 1 Computation ---------------------/////////////////

	///////////////////----------- Start LEVEL 2 Computation ---------------------/////////////////
	Ciphertext<ILVectorArray2n> cipherText7(cipherText4);
	//cipherText7.SetElement(cipherText4.GetElement() * cipherText5.GetElement());
	//cipherText7 = algorithm.m_algorithmLeveledSHE->KeySwitch(quadraticKeySwitchHint2, cipherText7);
	algorithm.m_algorithmLeveledSHE->ComposedEvalMult(cipherText4,cipherText5,quadraticKeySwitchHint2,&cipherText7);

	Ciphertext<ILVectorArray2n> cipherText8(cipherText6);
	//cipherText8 = algorithm.m_algorithmLeveledSHE->KeySwitch(linearKeySwitchHint2, cipherText8);
	algorithm.m_algorithmLeveledSHE->LevelReduce(cipherText6,linearKeySwitchHint2,&cipherText8);

	//algorithm.m_algorithmLeveledSHE->ModReduce(&cipherText7);
	//algorithm.m_algorithmLeveledSHE->ModReduce(&cipherText8);

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
	 */

}

void TestParameterSelection(){

	double diff, start, finish;

	start = currentDateTime();

	usint m = 16;

	float stdDev = 4;

	usint size = 11;

	std::cout << "tower size: " << size << std::endl;

	// BytePlaintextEncoding ctxtd;

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

	ILDCRTParams params(m, moduli, rootsOfUnity);

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

void FinalLeveledComputation(){

	usint init_m = 16;

	float init_stdDev = 4;

	usint init_size = 3;

	std::cout << "tower size: " << init_size << std::endl;

	BytePlaintextEncoding ctxtd;

	vector<BigBinaryInteger> init_moduli(init_size);

	vector<BigBinaryInteger> init_rootsOfUnity(init_size);

	BigBinaryInteger q("1");
	BigBinaryInteger temp;
	BigBinaryInteger modulus("1");

	for(int i=0; i < init_size;i++){
		lbcrypto::NextQ(q, BigBinaryInteger::FIVE,init_m,BigBinaryInteger("4"), BigBinaryInteger("4"));
		init_moduli[i] = q;
		init_rootsOfUnity[i] = RootOfUnity(init_m,init_moduli[i]);
		modulus = modulus* init_moduli[i];

	}

	cout << "big modulus: " << modulus << endl;
	DiscreteGaussianGenerator dgg(init_stdDev);

	ILDCRTParams params(init_m, init_moduli, init_rootsOfUnity);

	LPCryptoParametersLTV<ILVectorArray2n> cryptoParams;
	cryptoParams.SetPlaintextModulus(BigBinaryInteger::THREE);
	cryptoParams.SetDistributionParameter(init_stdDev);
	cryptoParams.SetRelinWindow(1);
	cryptoParams.SetElementParams(params);
	cryptoParams.SetDiscreteGaussianGenerator(dgg);
	cryptoParams.SetAssuranceMeasure(6);
	cryptoParams.SetDepth(init_size-1);
	cryptoParams.SetSecurityLevel(1.006);

	usint n = 16;

	std::vector<BigBinaryInteger> moduliV(init_size);
	LPCryptoParametersLTV<ILVectorArray2n> finalParams;

	cryptoParams.ParameterSelection(&finalParams);

	const ILDCRTParams &dcrtParams = dynamic_cast<const ILDCRTParams&>(finalParams.GetElementParams()); 

	usint m = dcrtParams.GetCyclotomicOrder();
	usint size = finalParams.GetDepth()+1;
	const BigBinaryInteger &plainTextModulus = finalParams.GetPlaintextModulus();

	vector<BigBinaryInteger> moduli(size);
	moduli = dcrtParams.GetModuli();
	vector<BigBinaryInteger> rootsOfUnity(size);
	rootsOfUnity = dcrtParams.GetRootsOfUnity();

	CryptoContext<ILVectorArray2n> cc = CryptoContextFactory<ILVectorArray2n>::getCryptoContextDCRT(&finalParams);
	//scheme initialization: LTV Scheme
	cc.Enable(SHE);
	cc.Enable(ENCRYPTION);
	cc.Enable(LEVELEDSHE);

	//Generate the secret key for the initial ciphertext:
	LPKeyPair<ILVectorArray2n> kp = cc.GetEncryptionAlgorithm().KeyGen(cc);

	//Generate the secret keys for the levels
	std::vector< LPKeyPair<ILVectorArray2n> > levelPairs(finalParams.GetDepth());

	std::vector< ILDCRTParams > leveledDcrtParams;
	leveledDcrtParams.reserve(finalParams.GetDepth()+1);
	std::vector< LPCryptoParametersLTV<ILVectorArray2n> > leveledCryptoParams;
	leveledCryptoParams.reserve(finalParams.GetDepth()+1);

	//Populate the vector of DcrtParams
	leveledDcrtParams.push_back(dcrtParams);
	for(usint i=1;i <= finalParams.GetDepth(); i++){
		leveledDcrtParams.push_back(leveledDcrtParams[i-1]);
		leveledDcrtParams.back().PopLastParam();
	}

	//Populate the vector of CryptoParams
	for(usint i=0;i <= finalParams.GetDepth(); i++){
		leveledCryptoParams.push_back(finalParams);
		leveledCryptoParams.at(i).SetElementParams(leveledDcrtParams.at(i));

		// leveledCryptoParams.push_back(finalParams);
		// leveledCryptoParams.at(1).SetElementParams(leveledDcrtParams.at(1));

		// leveledCryptoParams.push_back(finalParams);
		// leveledCryptoParams.at(2).SetElementParams(leveledDcrtParams.at(2));
	}

	// contexts and KeyGen on all the SK's and PK's
	vector<CryptoContext<ILVectorArray2n>> leveledCryptoContexts;
	for(usint i=0; i < finalParams.GetDepth(); i++) {
		leveledCryptoContexts.push_back( CryptoContextFactory<ILVectorArray2n>::getCryptoContextDCRT(&leveledCryptoParams[i]) );
		levelPairs[i] = leveledCryptoContexts[i].KeyGen();
	}

	//key structure stores all the hints 
	LPLeveledSHEKeyStructure<ILVectorArray2n> keyStruc(finalParams.GetDepth());
	LPEvalKeyNTRU<ILVectorArray2n> linearKeySwitchHint1(leveledCryptoContexts[0]);
	LPEvalKeyNTRU<ILVectorArray2n> linearKeySwitchHint2(leveledCryptoContexts[1]);
	LPEvalKeyNTRU<ILVectorArray2n> quadraticKeySwitchHint1(leveledCryptoContexts[0]);
	LPEvalKeyNTRU<ILVectorArray2n> quadraticKeySwitchHint2(leveledCryptoContexts[1]);
	
	cc.GetEncryptionAlgorithm().EvalMultKeyGen(*kp.secretKey, *levelPairs[0].secretKey, &linearKeySwitchHint1);
	cc.GetEncryptionAlgorithm().QuadraticEvalMultKeyGen(*kp.secretKey, *levelPairs[0].secretKey, &quadraticKeySwitchHint1);
	auto e = levelPairs[0].secretKey->GetPrivateElement();
	e.DropElementAtIndex(e.GetNumOfElements()-1);
	levelPairs[0].secretKey->SetPrivateElement(e);

	cc.GetEncryptionAlgorithm().EvalMultKeyGen(*levelPairs[0].secretKey, *levelPairs[1].secretKey, &linearKeySwitchHint2);
	cc.GetEncryptionAlgorithm().QuadraticEvalMultKeyGen(*levelPairs[0].secretKey, *levelPairs[1].secretKey, &quadraticKeySwitchHint2);
	e = levelPairs[1].secretKey->GetPrivateElement();
	e.DropElementAtIndex(e.GetNumOfElements()-1);
	levelPairs[1].secretKey->SetPrivateElement(e);


	//keyStruc.SetLinearKeySwitchHintForLevel(linearKeySwitchHint1,0);
	//keyStruc.SetQuadraticKeySwitchHintForLevel(quadraticKeySwitchHint1,0);
	keyStruc.PushBackLinearKey(linearKeySwitchHint1);
	keyStruc.PushBackQuadraticKey(quadraticKeySwitchHint1);

	keyStruc.PushBackLinearKey(linearKeySwitchHint2);
	keyStruc.PushBackQuadraticKey(quadraticKeySwitchHint2);

	//create the ciphertexts for computation
	ILVectorArray2n element1(dcrtParams);
	element1.SwitchFormat();
	element1 = {1};
	shared_ptr<Ciphertext<ILVectorArray2n>> cipherText1 = cc.GetEncryptionAlgorithm().Encrypt(*kp.publicKey,element1);

	ILVectorArray2n element2(dcrtParams);
	element2.SwitchFormat();
	element2 = {2};
	shared_ptr<Ciphertext<ILVectorArray2n>> cipherText2 = cc.GetEncryptionAlgorithm().Encrypt(*kp.publicKey,element2);

	ILVectorArray2n element3(dcrtParams);
	element3.SwitchFormat();
	element3 = {3};
	shared_ptr<Ciphertext<ILVectorArray2n>> cipherText3 = cc.GetEncryptionAlgorithm().Encrypt(*kp.publicKey,element3);

	ILVectorArray2n element4(dcrtParams);
	element4.SwitchFormat();
	element4 = {4};
	shared_ptr<Ciphertext<ILVectorArray2n>> cipherText4 = cc.GetEncryptionAlgorithm().Encrypt(*kp.publicKey,element4);

	ILVectorArray2n element5(dcrtParams);
	element5.SwitchFormat();
	element5 = {5};
	shared_ptr<Ciphertext<ILVectorArray2n>> cipherText5 = cc.GetEncryptionAlgorithm().Encrypt(*kp.publicKey,element5);

	//Computation: C = (C1*C2 + C3*C4)*C5
//	Ciphertext<ILVectorArray2n> cipherText6(cipherText1);
//	cc.GetEncryptionAlgorithm().ComposedEvalMult(*cipherText1,*cipherText2,keyStruc.GetQuadraticKeySwitchHintForLevel(0),&cipherText6);
//
//	Ciphertext<ILVectorArray2n> cipherText7(*cipherText1);
//	cc.GetEncryptionAlgorithm().ComposedEvalMult(*cipherText3,*cipherText4,keyStruc.GetQuadraticKeySwitchHintForLevel(0),&cipherText7);
//	cc.GetEncryptionAlgorithm().LevelReduce(*cipherText5,keyStruc.GetLinearKeySwitchHintForLevel(0),&(*cipherText5));
//
//	Ciphertext<ILVectorArray2n> cipherText8(cipherText7);
//	cc.GetEncryptionAlgorithm().EvalAdd(cipherText6,cipherText7,&cipherText8);
//
//
//	Ciphertext<ILVectorArray2n> cipherText9(cipherText8);
//	cc.GetEncryptionAlgorithm().ComposedEvalMult(cipherText8,*cipherText5,keyStruc.GetQuadraticKeySwitchHintForLevel(1),&cipherText9);


//	//BytePlaintextEncoding plaintextNew;
//	//CryptoUtility<ILVector2n>::Decrypt(algorithm, levelSk[1], cipherText9, &plaintextNew);
//	ILVectorArray2n plaintextNew;
//
//	cc.GetEncryptionAlgorithm().Decrypt(*levelPairs[1].secretKey, cipherText9, &plaintextNew);
//
//	cout << plaintextNew.GetElementAtIndex(0).GetValAtIndex(0) << endl;
}

void NTRUPRE(usint input) {

	//Set element params

	// Remove the comments on the following to use a low-security, highly efficient parameterization for integration and debugging purposes.
	/*
	usint m = 16;
	BigBinaryInteger modulus("67108913");
	BigBinaryInteger rootOfUnity("61564");
	BytePlaintextEncoding plaintext = "N";
	 */

	// The comments below provide a high-security parameterization for prototype use.  If this code were verified/certified for high-security applications, we would say that the following parameters would be appropriate for "production" use.
	//usint m = 2048;
	//BigBinaryInteger modulus("8590983169");
	//BigBinaryInteger rootOfUnity("4810681236");
	//BytePlaintextEncoding plaintext = "NJIT_CRYPTOGRAPHY_LABORATORY_IS_DEVELOPING_NEW-NTRU_LIKE_PROXY_REENCRYPTION_SCHEME_USING_LATTICE_BASED_CRYPTOGRAPHY_ABCDEFGHIJKL";

	SecureParams const SECURE_PARAMS[] = {
		//{ 2048, "8589987841", "2678760785", 1 }, //r = 8
		{ 2048, "268441601", "16947867", 1 }, //r = 1
		{ 2048, "536881153", "267934765", 2 }, // r = 2
		{ 2048, "1073750017", "180790047", 4 },  // r = 4
		{ 2048, "8589987841", "2678760785", 8 }, //r = 8
		{ 4096, "2199023288321", "1858080237421", 16 }  // r= 16
		//{ 2048, CalltoModulusComputation(), CalltoRootComputation, 0 }  // r= 16
	};

	usint m = SECURE_PARAMS[input].m;
	BigBinaryInteger modulus(SECURE_PARAMS[input].modulus);
	BigBinaryInteger rootOfUnity(SECURE_PARAMS[input].rootOfUnity);
	usint relWindow = SECURE_PARAMS[input].relinWindow;

	BytePlaintextEncoding plaintext("NJIT_CRYPTOGRAPHY_LABORATORY_IS_DEVELOPING_NEW-NTRU_LIKE_PROXY_REENCRYPTION_SCHEME_USING_LATTICE_BASED_CRYPTOGRAPHY_ABCDEFGHIJKL");
	//BytePlaintextEncoding plaintext("NJIT_CRYPTOGRAPHY_LABORATORY_IS_DEVELOPING_NEW-NTRU_LIKE_PROXY_REENCRYPTION_SCHEME_USING_LATTICE_BASED_CRYPTOGRAPHY_ABCDEFGHIJKLNJIT_CRYPTOGRAPHY_LABORATORY_IS_DEVELOPING_NEW-NTRU_LIKE_PROXY_REENCRYPTION_SCHEME_USING_LATTICE_BASED_CRYPTOGRAPHY_ABCDEFGHIJKL");


	float stdDev = 4;

	ofstream fout;
	fout.open ("output.txt");


	std::cout << " \nCryptosystem initialization: Performing precomputations..." << std::endl;

//	//Prepare for parameters.
//	ILParams ilParams(m,modulus,rootOfUnity);
//
//	//Set crypto parametes
//	LPCryptoParametersLTV<ILVector2n> cryptoParams;
//	cryptoParams.SetPlaintextModulus(BigBinaryInteger::TWO);  	// Set plaintext modulus.
//	//cryptoParams.SetPlaintextModulus(BigBinaryInteger("4"));  	// Set plaintext modulus.
//	cryptoParams.SetDistributionParameter(stdDev);			// Set the noise parameters.
//	cryptoParams.SetRelinWindow(relWindow);				// Set the relinearization window
//	cryptoParams.SetElementParams(ilParams);			// Set the initialization parameters.
//
//	DiscreteGaussianGenerator dgg(stdDev);				// Create the noise generator
//	cryptoParams.SetDiscreteGaussianGenerator(dgg);
//
//	const ILParams &cpILParams = static_cast<const ILParams&>(cryptoParams.GetElementParams());

	CryptoContext<ILVector2n> cc = CryptoContextFactory<ILVector2n>::genCryptoContextLTV(2, SECURE_PARAMS[input].m,
			SECURE_PARAMS[input].modulus, SECURE_PARAMS[input].rootOfUnity, SECURE_PARAMS[input].relinWindow, stdDev);
	cc.Enable(ENCRYPTION);
	cc.Enable(PRE);

	double diff, start, finish;

	start = currentDateTime();

	//This code is run only when performing execution time measurements

	//Precomputations for FTT
	ChineseRemainderTransformFTT::GetInstance().PreCompute(rootOfUnity, m, modulus);

	//Precomputations for DGG
	ILVector2n::PreComputeDggSamples(cc.GetGenerator(), cc.GetILParams());

	finish = currentDateTime();
	diff = finish - start;

	cout << "Precomputation time: " << "\t" << diff << " ms" << endl;
	fout << "Precomputation time: " << "\t" << diff << " ms" << endl;

	//Regular LWE-NTRU encryption algorithm

	////////////////////////////////////////////////////////////
	//Perform the key generation operation.
	////////////////////////////////////////////////////////////

	bool successKeyGen=false;

	std::cout <<"\n" <<  "Running key generation..." << std::endl;

	start = currentDateTime();

	LPKeyPair<ILVector2n> kp = cc.GetEncryptionAlgorithm().KeyGen(cc);	// This is the core function call that generates the keys.

	finish = currentDateTime();
	diff = finish - start;

	cout<< "Key generation execution time: "<<"\t"<<diff<<" ms"<<endl;
	fout<< "Key generation execution time: "<<"\t"<<diff<<" ms"<<endl;

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
	cout<<"\n"<<"original plaintext: "<<plaintext<<"\n"<<endl;
	fout<<"\n"<<"original plaintext: "<<plaintext<<"\n"<<endl;

	vector<shared_ptr<Ciphertext<ILVector2n>>> ciphertext;
	//BytePlaintextEncoding ptxt(plaintext);
	//ptxt.Pad<ZeroPad>(m/16);
	//ptxt.Pad<ZeroPad>(m/8);

	std::cout << "Running encryption..." << std::endl;

	start = currentDateTime();

	CryptoUtility<ILVector2n>::Encrypt(cc.GetEncryptionAlgorithm(), *kp.publicKey, plaintext, &ciphertext);

	finish = currentDateTime();
	diff = finish - start;

	cout<< "Encryption execution time: "<<"\t"<<diff<<" ms"<<endl;
	fout<< "Encryption execution time: "<<"\t"<<diff<<" ms"<<endl;

	//cout<<"ciphertext: "<<ciphertext.GetValues()<<endl;

	////////////////////////////////////////////////////////////
	//Decryption
	////////////////////////////////////////////////////////////

	BytePlaintextEncoding plaintextNew;

	std::cout <<"\n"<< "Running decryption..." << std::endl;

	start = currentDateTime();

	BytePlaintextEncoding ctxtd;

	//DecodingResult result = algorithm.Decrypt(sk,ciphertext,&plaintextNew);  // This is the core decryption operation.

	DecryptResult result = CryptoUtility<ILVector2n>::Decrypt(cc.GetEncryptionAlgorithm(), *kp.secretKey, ciphertext, &ctxtd);

	finish = currentDateTime();
	diff = finish - start;

	cout<< "Decryption execution time: "<<"\t"<<diff<<" ms"<<endl;
	fout<< "Decryption execution time: "<<"\t"<<diff<<" ms"<<endl;

	cout<<"\n"<<"decrypted plaintext (NTRU encryption): "<<plaintextNew<<"\n"<<endl;
	fout<<"\n"<<"decrypted plaintext (NTRU encryption): "<<plaintextNew<<"\n"<<endl;

	//cout << "ciphertext at" << ciphertext.GetIndexAt(2);

	if (!result.isValid) {
		std::cout<<"Decryption failed!"<<std::endl;
		exit(1);
	}
	//PRE SCHEME

	//system("pause");

	//LPAlgorithmPRELTV<ILVector2n> algorithmPRE;

	////////////////////////////////////////////////////////////
	//Perform the second key generation operation.
	// This generates the keys which should be able to decrypt the ciphertext after the re-encryption operation.
	////////////////////////////////////////////////////////////

	std::cout << "Running second key generation (used for re-encryption)..." << std::endl;

	start = currentDateTime();

	LPKeyPair<ILVector2n> newKp = cc.GetEncryptionAlgorithm().KeyGen(cc);	// This is the same core key generation operation.

	finish = currentDateTime();
	diff = finish - start;

	cout << "Key generation execution time: "<<"\t"<<diff<<" ms"<<endl;
	fout << "Key generation execution time: "<<"\t"<<diff<<" ms"<<endl;

	//	cout<<"newPK = "<<newPK.GetPublicElement().GetValues()<<endl;
	//	cout<<"newSK = "<<newSK.GetPrivateElement().GetValues()<<endl;
	//	fout<<"newPK = "<<newPK.GetPublicElement().GetValues()<<endl;
	//	fout<<"newSK = "<<newSK.GetPrivateElement().GetValues()<<endl;

	////////////////////////////////////////////////////////////
	//Perform the proxy re-encryption key generation operation.
	// This generates the keys which are used to perform the key switching.
	////////////////////////////////////////////////////////////

	std::cout <<"\n"<< "Generating proxy re-encryption key..." << std::endl;

	LPEvalKeyNTRURelin<ILVector2n> evalKey(cc);

	start = currentDateTime();

	CryptoUtility<ILVector2n>::ReKeyGen(cc.GetEncryptionAlgorithm(), *newKp.publicKey, *kp.secretKey, &evalKey);  // This is the core re-encryption operation.

	finish = currentDateTime();
	diff = finish - start;

	cout<< "Re-encryption key generation time: "<<"\t"<<diff<<" ms"<<endl;
	fout<< "Re-encryption key generation time: "<<"\t"<<diff<<" ms"<<endl;

	////////////////////////////////////////////////////////////
	//Perform the proxy re-encryption operation.
	// This switches the keys which are used to perform the key switching.
	////////////////////////////////////////////////////////////


	vector<shared_ptr<Ciphertext<ILVector2n>>> newCiphertext;


	std::cout <<"\n"<< "Running re-encryption..." << std::endl;

	start = currentDateTime();

	CryptoUtility<ILVector2n>::ReEncrypt(cc.GetEncryptionAlgorithm(), evalKey, ciphertext, &newCiphertext); // This is the core re-encryption operation.

	finish = currentDateTime();
	diff = finish - start;

	cout<< "Re-encryption execution time: "<<"\t"<<diff<<" ms"<<endl;
	fout<< "Re-encryption execution time: "<<"\t"<<diff<<" ms"<<endl;

	//cout<<"new CipherText - PRE = "<<newCiphertext.GetValues()<<endl;

	////////////////////////////////////////////////////////////
	//Decryption
	////////////////////////////////////////////////////////////

	BytePlaintextEncoding plaintextNew2;

	std::cout <<"\n"<< "Running decryption of re-encrypted cipher..." << std::endl;

	start = currentDateTime();

	DecryptResult result1 = CryptoUtility<ILVector2n>::Decrypt(cc.GetEncryptionAlgorithm(),*newKp.secretKey,newCiphertext,&plaintextNew2);  // This is the core decryption operation.

	finish = currentDateTime();
	diff = finish - start;

	cout<< "Decryption execution time: "<<"\t"<<diff<<" ms"<<endl;
	fout<< "Decryption execution time: "<<"\t"<<diff<<" ms"<<endl;

	cout<<"\n"<<"decrypted plaintext (PRE Re-Encrypt): "<<plaintextNew2<<"\n"<<endl;
	fout<<"\n"<<"decrypted plaintext (PRE Re-Encrypt): "<<plaintextNew2<<"\n"<<endl;

	if (!result1.isValid) {
		std::cout<<"Decryption failed!"<<std::endl;
		exit(1);
	}

	std::cout << "Execution completed.  Please any key to finish." << std::endl;

	fout.close();

	//system("pause");

}

void ComposedEvalMultTest(){
	usint init_m = 16;

	float init_stdDev = 4;

	usint init_size = 3;

	vector<BigBinaryInteger> init_moduli(init_size);

	vector<BigBinaryInteger> init_rootsOfUnity(init_size);

	BigBinaryInteger q("1");
	BigBinaryInteger temp;
	BigBinaryInteger modulus("1");

	for (int i = 0; i < init_size; i++) {
		lbcrypto::NextQ(q, BigBinaryInteger::FIVE, init_m, BigBinaryInteger("4"), BigBinaryInteger("4"));
		init_moduli[i] = q;
		init_rootsOfUnity[i] = RootOfUnity(init_m, init_moduli[i]);
		modulus = modulus* init_moduli[i];

	}

	DiscreteGaussianGenerator dgg(init_stdDev);

	ILDCRTParams params(init_m, init_moduli, init_rootsOfUnity);

	LPCryptoParametersLTV<ILVectorArray2n> cryptoParams;
	cryptoParams.SetPlaintextModulus(BigBinaryInteger::FIVE);
	cryptoParams.SetDistributionParameter(init_stdDev);
	cryptoParams.SetRelinWindow(1);
	cryptoParams.SetElementParams(params);
	cryptoParams.SetDiscreteGaussianGenerator(dgg);
	cryptoParams.SetAssuranceMeasure(6);
	cryptoParams.SetDepth(init_size - 1);
	cryptoParams.SetSecurityLevel(1.006);

	LPCryptoParametersLTV<ILVectorArray2n> finalParamsThreeTowers;

	cryptoParams.ParameterSelection(&finalParamsThreeTowers);

	const ILDCRTParams &dcrtParams = dynamic_cast<const ILDCRTParams&>(finalParamsThreeTowers.GetElementParams());

	CryptoContext<ILVectorArray2n> cc = CryptoContextFactory<ILVectorArray2n>::getCryptoContextDCRT(&finalParamsThreeTowers);
	cc.Enable(SHE);
	cc.Enable(ENCRYPTION);
	cc.Enable(LEVELEDSHE);

	//Generate the secret key for the initial ciphertext:
	LPKeyPair<ILVectorArray2n> kp = cc.KeyGen();

	//Generate the switch cipher text
	LPKeyPair<ILVectorArray2n> kpNew = cc.KeyGen();

	//Generating original ciphertext to perform ComposedEvalMult on
	shared_ptr<Ciphertext<ILVectorArray2n>> c1;

	shared_ptr<Ciphertext<ILVectorArray2n>> c2;

	//Generating new cryptoparameters for when modulus reduction is done.
	LPCryptoParametersLTV<ILVectorArray2n> finalParamsTwoTowers(finalParamsThreeTowers);

	const ILDCRTParams &dcrtParams2 = dynamic_cast<const ILDCRTParams&>(finalParamsThreeTowers.GetElementParams());
	ILDCRTParams finalDcrtParamsTwoTowers(dcrtParams2);
	finalDcrtParamsTwoTowers.PopLastParam();
	finalParamsTwoTowers.SetElementParams(finalDcrtParamsTwoTowers);

	//Generating Quaraditic KeySwitchHint from sk^2 to skNew
	LPEvalKeyNTRU<ILVectorArray2n> quadraticKeySwitchHint(cc);
	cc.GetEncryptionAlgorithm().QuadraticEvalMultKeyGen(*kp.secretKey, *kpNew.secretKey, &quadraticKeySwitchHint);

	//Dropping the last tower of skNew, because ComposedEvalMult performs a ModReduce
	ILVectorArray2n skNewOldElement(kpNew.secretKey->GetPrivateElement());
	skNewOldElement.DropElementAtIndex(skNewOldElement.GetNumOfElements() - 1);
	kpNew.secretKey->SetPrivateElement(skNewOldElement);

}


bool canRingReduce(usint ringDimension, std::vector<BigBinaryInteger> moduli, double rootHermiteFactor) {
	if (ringDimension == 1) return false;
	ringDimension = ringDimension / 2;
	double multipliedModuli = 1;

	for (usint i = 0; i < moduli.size(); i++) {
		multipliedModuli = multipliedModuli*  moduli.at(i).ConvertToDouble();
	}
	double powerValue = (log(multipliedModuli) / log(2))/(4*ringDimension);
	double powerOfTwo = pow(2, powerValue);

	return rootHermiteFactor >= powerOfTwo;
}

void RootsOfUnitTest() {
	usint m1 = 32;
	BigBinaryInteger q("17729");
//	BigBinaryInteger rootOfUnity1 = RootOfUnity(m1/2, q);

	usint m2 = 16;
	BigBinaryInteger rootOfUnity2 = RootOfUnity(m2, q);
//	BigBinaryInteger rootOfUnity3 = RootOfUnity(m2, q);
//	BigBinaryInteger rootOfUnity4 = RootOfUnity(m2, q);


//	cout << rootOfUnity1 << endl;
	cout << rootOfUnity2 << endl;
//	cout << rootOfUnity3 << endl;
//	cout << rootOfUnity4 << endl;


}

void FFTTest() {
	usint m1 = 8;
	

	BigBinaryInteger modulus(17729);
	BigBinaryInteger rootOfUnity(RootOfUnity(m1, modulus));
	cout << rootOfUnity << endl;
	cout << rootOfUnity << endl;
	ILParams params(m1, modulus, rootOfUnity);

	ILVector2n x1(params, Format::COEFFICIENT);
	x1 = { 1,0,1,0};
	

	x1.Decompose();

	x1.SwitchFormat();
	x1.SwitchFormat();

	x1.PrintValues();

	
}
