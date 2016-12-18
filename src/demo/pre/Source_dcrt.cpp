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

#include "../../lib/palisade.h"
#include "../../lib/palisadespace.h"

#include "../../lib/utils/cryptocontexthelper.h"
#include "../../lib/crypto/cryptocontext.cpp"
#include "../../lib/utils/cryptocontexthelper.cpp"

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
void TestParameterSelection();
void FinalLeveledComputation();
void ComposedEvalMultTest();
bool canRingReduce(usint ringDimension, std::vector<BigBinaryInteger> moduli, double rootHermiteFactor);
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

	NTRU_DCRT();

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
	cout << "NTRU_DCRT" << endl;

	double diff, start, finish;

	start = currentDateTime();

	usint m = 16;
	m = 4096;

	const BytePlaintextEncoding plaintext = "I would like to see";

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
	ILVectorArray2n::PreComputeCRIFactors(moduli, m);
	shared_ptr<ILDCRTParams> params( new ILDCRTParams(m, moduli, rootsOfUnity) );

	LPCryptoParametersLTV<ILVectorArray2n> cryptoParams;
	cryptoParams.SetPlaintextModulus(BigBinaryInteger::TWO);
	cryptoParams.SetDistributionParameter(stdDev);
	cryptoParams.SetRelinWindow(1);
	cryptoParams.SetElementParams(params);

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

	if (!kp.good()) {
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

	ciphertext = cc.Encrypt(kp.publicKey,plaintext);

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

	DecryptResult result = cc.Decrypt(kp.secretKey,ciphertext,&plaintextNew);  // This is the core decryption operation.

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

	LPKeyPair<ILVectorArray2n> newKp = cc.KeyGen();

	////////////////////////////////////////////////////////////
	//Perform the proxy re-encryption key generation operation.
	// This generates the keys which are used to perform the key switching.
	////////////////////////////////////////////////////////////

	cout << "Running eval key gen" << endl;

	shared_ptr<LPEvalKey<ILVectorArray2n>> evalKey = cc.ReKeyGen(newKp.publicKey, newKp.secretKey);

	if( evalKey == NULL ) {
		cout << "EvalKeyGen failed!!!" << endl;
	}
	else {
		vector<ILVectorArray2n> av = evalKey->GetAVector();
		cout << "The eval key A vect size is " << av.size() << endl;

		vector<shared_ptr<Ciphertext<ILVectorArray2n>>> newCiphertext;

		cout << "Running re encryption" << endl;
		newCiphertext = cc.ReEncrypt(evalKey, ciphertext);

		//cout<<"new CipherText - PRE = "<<newCiphertext.GetValues()<<endl;

		////////////////////////////////////////////////////////////
		//Decryption
		////////////////////////////////////////////////////////////

		BytePlaintextEncoding plaintextNew2;

		DecryptResult result1 = cc.Decrypt(newKp.secretKey, newCiphertext, &plaintextNew2);

		if (!result1.isValid) {
			std::cout<<"Decryption failed!"<<std::endl;
			exit(1);
		}
	}

	std::cout << "Execution completed." << std::endl;
	ILVectorArray2n::DestroyPrecomputedCRIFactors();


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

	shared_ptr<ILDCRTParams> params( new ILDCRTParams(m, moduli, rootsOfUnity) );

	LPCryptoParametersLTV<ILVectorArray2n> cryptoParams;
	cryptoParams.SetPlaintextModulus(BigBinaryInteger::TWO);
	cryptoParams.SetDistributionParameter(stdDev);
	cryptoParams.SetRelinWindow(1);
	cryptoParams.SetElementParams(params);
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

	const shared_ptr<ILDCRTParams> dcrtParams = std::static_pointer_cast<ILDCRTParams>(cryptoParams2.GetElementParams());
	std::vector<BigBinaryInteger> moduli2 = dcrtParams->GetModuli();

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

	shared_ptr<ILDCRTParams> params( new ILDCRTParams(init_m, init_moduli, init_rootsOfUnity) );

	LPCryptoParametersLTV<ILVectorArray2n> cryptoParams;
	cryptoParams.SetPlaintextModulus(BigBinaryInteger::THREE);
	cryptoParams.SetDistributionParameter(init_stdDev);
	cryptoParams.SetRelinWindow(1);
	cryptoParams.SetElementParams(params);
	cryptoParams.SetAssuranceMeasure(6);
	cryptoParams.SetDepth(init_size-1);
	cryptoParams.SetSecurityLevel(1.006);

	usint n = 16;

	std::vector<BigBinaryInteger> moduliV(init_size);
	LPCryptoParametersLTV<ILVectorArray2n> finalParams;

	cryptoParams.ParameterSelection(&finalParams);

	const shared_ptr<ILDCRTParams> dcrtParams = std::static_pointer_cast<ILDCRTParams>( finalParams.GetElementParams() ) ;

	usint m = dcrtParams->GetCyclotomicOrder();
	usint size = finalParams.GetDepth()+1;
	const BigBinaryInteger &plainTextModulus = finalParams.GetPlaintextModulus();

	vector<BigBinaryInteger> moduli(size);
	moduli = dcrtParams->GetModuli();
	vector<BigBinaryInteger> rootsOfUnity(size);
	rootsOfUnity = dcrtParams->GetRootsOfUnity();

	CryptoContext<ILVectorArray2n> cc = CryptoContextFactory<ILVectorArray2n>::getCryptoContextDCRT(&finalParams);
	//scheme initialization: LTV Scheme
	cc.Enable(SHE);
	cc.Enable(ENCRYPTION);
	cc.Enable(LEVELEDSHE);

	//Generate the secret key for the initial ciphertext:
	LPKeyPair<ILVectorArray2n> kp = cc.KeyGen();

	//Generate the secret keys for the levels
	std::vector< LPKeyPair<ILVectorArray2n> > levelPairs(finalParams.GetDepth());

	std::vector< shared_ptr<ILDCRTParams> > leveledDcrtParams;
	leveledDcrtParams.reserve(finalParams.GetDepth()+1);
	std::vector< LPCryptoParametersLTV<ILVectorArray2n> > leveledCryptoParams;
	leveledCryptoParams.reserve(finalParams.GetDepth()+1);

	//Populate the vector of DcrtParams
	leveledDcrtParams.push_back(dcrtParams);
	for(usint i=1;i <= finalParams.GetDepth(); i++){
		leveledDcrtParams.push_back(leveledDcrtParams[i-1]);
		leveledDcrtParams.back()->PopLastParam();
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

	shared_ptr<LPEvalKey<ILVectorArray2n>> linearKeySwitchHint1;
	shared_ptr<LPEvalKey<ILVectorArray2n>> linearKeySwitchHint2;
	shared_ptr<LPEvalKey<ILVectorArray2n>> quadraticKeySwitchHint1;
	shared_ptr<LPEvalKey<ILVectorArray2n>> quadraticKeySwitchHint2;
	
	linearKeySwitchHint1 = cc.KeySwitchGen(kp.secretKey, levelPairs[0].secretKey);
	quadraticKeySwitchHint1 = cc.EvalMultKeyGen(kp.secretKey);
	auto e = levelPairs[0].secretKey->GetPrivateElement();
	e.DropElementAtIndex(e.GetNumOfElements()-1);
	levelPairs[0].secretKey->SetPrivateElement(e);

	linearKeySwitchHint2 = cc.KeySwitchGen(levelPairs[0].secretKey, levelPairs[1].secretKey);
	quadraticKeySwitchHint2 = cc.EvalMultKeyGen(levelPairs[0].secretKey);
	e = levelPairs[1].secretKey->GetPrivateElement();
	e.DropElementAtIndex(e.GetNumOfElements()-1);
	levelPairs[1].secretKey->SetPrivateElement(e);

	//create the ciphertexts for computation
	ILVectorArray2n element1(dcrtParams);
	element1.SwitchFormat();
	element1 = {1};
	shared_ptr<Ciphertext<ILVectorArray2n>> cipherText1 = cc.GetEncryptionAlgorithm()->Encrypt(kp.publicKey,element1);

	ILVectorArray2n element2(dcrtParams);
	element2.SwitchFormat();
	element2 = {2};
	shared_ptr<Ciphertext<ILVectorArray2n>> cipherText2 = cc.GetEncryptionAlgorithm()->Encrypt(kp.publicKey,element2);

	ILVectorArray2n element3(dcrtParams);
	element3.SwitchFormat();
	element3 = {3};
	shared_ptr<Ciphertext<ILVectorArray2n>> cipherText3 = cc.GetEncryptionAlgorithm()->Encrypt(kp.publicKey,element3);

	ILVectorArray2n element4(dcrtParams);
	element4.SwitchFormat();
	element4 = {4};
	shared_ptr<Ciphertext<ILVectorArray2n>> cipherText4 = cc.GetEncryptionAlgorithm()->Encrypt(kp.publicKey,element4);

	ILVectorArray2n element5(dcrtParams);
	element5.SwitchFormat();
	element5 = {5};
	shared_ptr<Ciphertext<ILVectorArray2n>> cipherText5 = cc.GetEncryptionAlgorithm()->Encrypt(kp.publicKey,element5);

	
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

	shared_ptr<ILDCRTParams> params( new ILDCRTParams(init_m, init_moduli, init_rootsOfUnity) );

	LPCryptoParametersLTV<ILVectorArray2n> cryptoParams(params,
			BigBinaryInteger::FIVE,
			init_stdDev,
			6,
			1.006,
			1,
			init_size - 1);

	LPCryptoParametersLTV<ILVectorArray2n> finalParamsThreeTowers;

	cryptoParams.ParameterSelection(&finalParamsThreeTowers);

	const shared_ptr<ILDCRTParams> dcrtParams = std::static_pointer_cast<ILDCRTParams>(finalParamsThreeTowers.GetElementParams());

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

	const shared_ptr<ILDCRTParams> dcrtParams2 = std::static_pointer_cast<ILDCRTParams>(finalParamsThreeTowers.GetElementParams());
	shared_ptr<ILDCRTParams> finalDcrtParamsTwoTowers( new ILDCRTParams(*dcrtParams2) );
	finalDcrtParamsTwoTowers->PopLastParam();
	finalParamsTwoTowers.SetElementParams(finalDcrtParamsTwoTowers);

	//FIXME: this is never used??
	//Generating Quaraditic KeySwitchHint from sk^2 to skNew
	shared_ptr<LPEvalKey<ILVectorArray2n>> quadraticKeySwitchHint;
	quadraticKeySwitchHint = cc.EvalMultKeyGen(kp.secretKey);

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


void FFTTest() {
	usint m1 = 8;
	

	BigBinaryInteger modulus(17729);
	BigBinaryInteger rootOfUnity(RootOfUnity(m1, modulus));
	cout << rootOfUnity << endl;
	cout << rootOfUnity << endl;
	shared_ptr<ILParams> params( new ILParams(m1, modulus, rootOfUnity) );

	ILVector2n x1(params, Format::COEFFICIENT);
	x1 = { 1,0,1,0};
	

	x1.Decompose();

	x1.SwitchFormat();
	x1.SwitchFormat();

	x1.PrintValues();

	
}
