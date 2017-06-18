/*
 * @file 
 * @author  TPOC: palisade@njit.edu
 *
 * @copyright Copyright (c) 2017, New Jersey Institute of Technology (NJIT)
 * All rights reserved.
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:
 * 1. Redistributions of source code must retain the above copyright notice, this
 * list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice, this
 * list of conditions and the following disclaimer in the documentation and/or other
 * materials provided with the distribution.
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR
 * ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
 * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
 * IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include <iostream>
#include <fstream>

#include "palisade.h"

#include "cryptocontexthelper.h"

#include "time.h"

#include <chrono>
#include "utils/debug.h"
#include "encoding/byteplaintextencoding.h"
#include "encoding/intplaintextencoding.h"

using namespace std;
using namespace lbcrypto;

void NTRU_DCRT();

//FIXME these methods do not work
void TestParameterSelection();
void FinalLeveledComputation();
void ComposedEvalMultTest();
bool canRingReduce(usint ringDimension, std::vector<BigBinaryInteger> moduli, double rootHermiteFactor);

// test scenarios
struct Scenario {
	usint bits;
	usint m;
	string modulus;
	string rootOfUnity;
} Scenarios[] = {
		{
				503,
				2048,
				"13093562431584567480052758787310396608866568184172259157933165472384535185618698219533080369303616628603546736510240284036869026183541572213314110873601",
				"12023848463855649466660377440069556144464267030949365165993725942220441412632799311989973938254823071405336623315668961501139592673000297887682895033094"
		},
		{
				132,
				8192,
				"2722258935367507707706996859454146142209",
				"1426115470453457649704739287701063827541"
		},
};

shared_ptr<ILParams> GenSinglePrimeParams(int sc) {
	return shared_ptr<ILParams>(new ILParams( Scenarios[sc].m, BigBinaryInteger(Scenarios[sc].modulus), BigBinaryInteger(Scenarios[sc].rootOfUnity)));
}

static const usint smbits = 28;

shared_ptr<ILDCRTParams<BigBinaryInteger>> GenDCRTParams(int sc) {
	usint m = Scenarios[sc].m;
	usint nTowers = Scenarios[sc].bits/smbits;

	vector<native_int::BinaryInteger> moduli(nTowers);

	vector<native_int::BinaryInteger> rootsOfUnity(nTowers);

	native_int::BinaryInteger q( (1<<smbits) -1 );
	native_int::BinaryInteger temp;
	BigBinaryInteger modulus(1);

	for(size_t i=0; i < nTowers; i++){
		lbcrypto::NextQ(q, native_int::BinaryInteger(2), m, native_int::BinaryInteger(4), native_int::BinaryInteger(4));
		moduli[i] = q;
		rootsOfUnity[i] = RootOfUnity(m,moduli[i]);
		modulus = modulus * BigBinaryInteger(moduli[i].ConvertToInt());

	}

	return shared_ptr<ILDCRTParams<BigBinaryInteger>>( new ILDCRTParams<BigBinaryInteger>(m, moduli, rootsOfUnity) );
}

void MakeTestPolynomial(int sc, ILVector2n& elem) {
	ILVector2n::DugType dug;
	dug.SetModulus(BigBinaryInteger(elem.GetParams()->GetModulus()));

	BigBinaryVector v = dug.GenerateVector(Scenarios[sc].m/2);
	elem.SetValues(v, Format::COEFFICIENT);
}

void CRTComposeTest() {
	for( int i=0; i<2; i++ ) {
		std::cout << "Case " << i << " m=" << Scenarios[i].m << " bits=" << Scenarios[i].bits << std::endl;
		shared_ptr<ILDCRTParams<BigBinaryInteger>> dcparm = GenDCRTParams(i);
		shared_ptr<ILParams> tvp( new ILParams(dcparm->GetCyclotomicOrder(), dcparm->GetModulus(), 1) );
		ILVector2n tVec(tvp);
		MakeTestPolynomial(i, tVec);

		double diff, start, finish;

		start = currentDateTime();
		ILDCRT2n testVector2(tVec, dcparm);
		finish = currentDateTime();
		diff = finish - start;
		std::cout << "vector Decompose " << diff << std::endl;

		start = currentDateTime();
		testVector2.CRTInterpolate();
		finish = currentDateTime();
		diff = finish - start;
		std::cout << "vector Interpolate " << diff << std::endl;
	}
}

void SwitchFormatTest(bool runsmall, bool runbig) {
	double diff, start, finish;

	for( int i=0; i<2; i++ ) {
		std::cout << "Case " << i << " m=" << Scenarios[i].m << " bits=" << Scenarios[i].bits << std::endl;
		if( runbig ) {
			shared_ptr<ILParams> spparm = GenSinglePrimeParams(i);
			ILVector2n testVector(spparm);
			MakeTestPolynomial(i, testVector);

			start = currentDateTime();
			testVector.SwitchFormat();
			finish = currentDateTime();
			diff = finish - start;
			std::cout << "big int SwitchFormat " << diff << std::endl;

			start = currentDateTime();
			testVector.SwitchFormat();
			finish = currentDateTime();
			diff = finish - start;
			std::cout << "big int SwitchFormat " << diff << std::endl;
		}

		if( runsmall ) {
			shared_ptr<ILDCRTParams<BigBinaryInteger>> dcparm = GenDCRTParams(i);
			shared_ptr<ILParams> tvp( new ILParams(dcparm->GetCyclotomicOrder(), dcparm->GetModulus(), 1) );
			ILVector2n tVec(tvp);
			MakeTestPolynomial(i, tVec);
			ILDCRT2n testVector2(tVec, dcparm);

			start = currentDateTime();
			testVector2.SwitchFormat();
			finish = currentDateTime();
			diff = finish - start;
			std::cout << "vector int SwitchFormat " << diff << std::endl;

			start = currentDateTime();
			testVector2.SwitchFormat();
			finish = currentDateTime();
			diff = finish - start;
			std::cout << "vector int SwitchFormat " << diff << std::endl;
		}
	}
}

// Going to use the BV scheme for these
void EvalMultTest(bool runsmall, bool runbig) {
	double diff, start, finish;

	for( int i=0; i<2; i++ ) {
		std::cout << "Case " << i << " m=" << Scenarios[i].m << " bits=" << Scenarios[i].bits << std::endl;
		if( runbig ) {
			shared_ptr<ILParams> spparm = GenSinglePrimeParams(i);
			CryptoContext<ILVector2n> cc1 = CryptoContextFactory<ILVector2n>::genCryptoContextBV(spparm, 16, 16, 4.0);
			cc1.Enable(ENCRYPTION);
			cc1.Enable(SHE);

			ILVector2n testVector1(spparm);
			ILVector2n testVector2(spparm);
			MakeTestPolynomial(i, testVector1);
			MakeTestPolynomial(i, testVector2);

			LPKeyPair<ILVector2n> kp1 = cc1.KeyGen();
			cc1.EvalMultKeyGen(kp1.secretKey);
			shared_ptr<Ciphertext<ILVector2n>> ciphertext1 = cc1.GetEncryptionAlgorithm()->Encrypt(kp1.publicKey, testVector1);
			shared_ptr<Ciphertext<ILVector2n>> ciphertext2 = cc1.GetEncryptionAlgorithm()->Encrypt(kp1.publicKey, testVector2);

			start = currentDateTime();
			shared_ptr<Ciphertext<ILVector2n>> ciphertext12 = cc1.EvalMult(ciphertext1,ciphertext2);
			finish = currentDateTime();
			diff = finish - start;
			std::cout << "ILVector2n EvalMult " << diff << std::endl;
		}

		if( runsmall ) {
			shared_ptr<ILDCRTParams<BigBinaryInteger>> dcparm = GenDCRTParams(i);
			shared_ptr<ILParams> tvp( new ILParams(dcparm->GetCyclotomicOrder(), dcparm->GetModulus(), 1) );
			CryptoContext<ILDCRT2n> cc2 = CryptoContextFactory<ILDCRT2n>::genCryptoContextBV(dcparm, 16, 16, 4.0);
			cc2.Enable(ENCRYPTION);
			cc2.Enable(SHE);

			ILVector2n tVec1(tvp);
			ILVector2n tVec2(tvp);
			MakeTestPolynomial(i, tVec1);
			MakeTestPolynomial(i, tVec2);

			LPKeyPair<ILDCRT2n> kp2 = cc2.KeyGen();
			cc2.EvalMultKeyGen(kp2.secretKey);
			shared_ptr<Ciphertext<ILDCRT2n>> ciphertext3 = cc2.GetEncryptionAlgorithm()->Encrypt(kp2.publicKey, tVec1);
			shared_ptr<Ciphertext<ILDCRT2n>> ciphertext4 = cc2.GetEncryptionAlgorithm()->Encrypt(kp2.publicKey, tVec2);

			start = currentDateTime();
			shared_ptr<Ciphertext<ILDCRT2n>> ciphertext34 = cc2.EvalMult(ciphertext3,ciphertext4);
			finish = currentDateTime();
			diff = finish - start;
			std::cout << "ILDCRT2n EvalMult " << diff << std::endl;
		}
	}
}

void MultiplyTest(bool runsmall, bool runbig) {
	double diff, start, finish;

	for( int i=0; i<2; i++ ) {
		std::cout << "Case " << i << " m=" << Scenarios[i].m << " bits=" << Scenarios[i].bits << std::endl;

		if( runsmall ) {
			shared_ptr<ILParams> spparm = GenSinglePrimeParams(i);
			ILVector2n testVector1(spparm);
			ILVector2n testVector2(spparm);
			MakeTestPolynomial(i, testVector1);
			MakeTestPolynomial(i, testVector2);
			testVector1.SwitchFormat();
			testVector2.SwitchFormat();

			start = currentDateTime();
			ILVector2n answer = testVector1 * testVector2;
			finish = currentDateTime();
			diff = finish - start;
			std::cout << "ILVector2n element multiply " << diff << std::endl;
		}

		if( runbig ) {
			shared_ptr<ILDCRTParams<BigBinaryInteger>> dcparm = GenDCRTParams(i);
			shared_ptr<ILParams> tvp( new ILParams(dcparm->GetCyclotomicOrder(), dcparm->GetModulus(), 1) );
			ILVector2n tVec1(tvp);
			ILVector2n tVec2(tvp);
			MakeTestPolynomial(i, tVec1);
			MakeTestPolynomial(i, tVec2);
			ILDCRT2n testVector3(tVec1, dcparm);
			ILDCRT2n testVector4(tVec2, dcparm);

			start = currentDateTime();
			ILDCRT2n answer2 = testVector3 * testVector4;
			finish = currentDateTime();
			diff = finish - start;
			std::cout << "ILDCRT2n element multiply " << diff << std::endl;
		}
	}
}

void usage(const string& msg) {
	cout << "Unrecognized " << msg << ", usage is:" << endl;
	cout << "big - run big-integer tests" << endl;
	cout << "small - run small-integer DCRT tests" << endl;
	cout << "   default is both" << endl;
	cout << "vec - run vector tests" << endl;
	cout << "lattice - run lattice tests" << endl;
	cout << "crypto - run encryption test" << endl;
	cout << "   default is all" << endl;
}

#include <iterator>
int main(int argc, char *argv[]) {
	bool runbig = false, runsmall = false, runvec = false, runlat = false, runcrypto = false;

	for( int i=1; i<argc; i++ ) {
		string arg(argv[i]);

		if( arg == "big" ) runbig = true;
		else if( arg == "small" ) runsmall = true;
		else if( arg == "vec" ) runvec = true;
		else if( arg == "lattice" ) runlat = true;
		else if( arg == "crypto" ) runcrypto = true;
		else {
			usage(arg);
			return 1;
		}
	}

	if( !runbig && !runsmall ) runbig = runsmall = true;
	if( !runvec && !runlat && !runcrypto ) runvec = runlat = runcrypto = true;

	if( runvec ) {
		if( runbig ) {
			CRTComposeTest();
			std::cout << "====================================================================" << std::endl;
		}

		SwitchFormatTest(runsmall, runbig);
		std::cout << "====================================================================" << std::endl;

		MultiplyTest(runsmall, runbig);
		std::cout << "====================================================================" << std::endl;
	}

	if( runlat ) {
		EvalMultTest(runsmall, runbig);
		std::cout << "====================================================================" << std::endl;
	}

	if( runcrypto ) {
		NTRU_DCRT();
	}


	return 0;
}

void NTRU_DCRT() {

	double diff, start, finish;

	usint m = 4096;
	usint ptm = 256;
	usint relinWindow = 1;

	BytePlaintextEncoding plaintext;

	size_t strSize = plaintext.GetChunksize(m/2, BigBinaryInteger(ptm));

	auto randchar = []() -> char {
		const char charset[] =
				"0123456789"
				"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
				"abcdefghijklmnopqrstuvwxyz";
		const size_t max_index = (sizeof(charset) - 1);
		return charset[ rand() % max_index ];
	};

	string shortStr(strSize,0);
	std::generate_n(shortStr.begin(), strSize/2, randchar);
	plaintext = shortStr;

	float stdDev = 4;


	shared_ptr<ILDCRTParams<BigBinaryInteger>> params = GenDCRTParams(0);
	cout << "big modulus: " << params->GetModulus() << endl;

	CryptoContext<ILDCRT2n> cc = CryptoContextFactory<ILDCRT2n>::genCryptoContextLTV(params, ptm, relinWindow, stdDev);
	cc.Enable(ENCRYPTION);
	cc.Enable(PRE);

	std::cout <<"\n" <<  "Running key generation..." << std::endl;

	start = currentDateTime();

	LPKeyPair<ILDCRT2n> kp = cc.KeyGen();	// This is the core function call that generates the keys.

	finish = currentDateTime();
	diff = finish - start;

	cout<< "Key generation execution time: "<<"\t"<<diff<<" ms"<<endl;

	if (!kp.good()) {
		std::cout<<"Key generation failed!"<<std::endl;
		exit(1);
	}

	////////////////////////////////////////////////////////////
	//Encryption
	////////////////////////////////////////////////////////////

	vector<shared_ptr<Ciphertext<ILDCRT2n>>> ciphertext;

	std::cout << "Running encryption..." << std::endl;

	start = currentDateTime();

	ciphertext = cc.Encrypt(kp.publicKey,plaintext);

	finish = currentDateTime();
	diff = finish - start;

	cout<< "Encryption execution time: "<<"\t"<<diff<<" ms"<<endl;

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

	if (!result.isValid) {
		std::cout<<"Decryption failed!"<<std::endl;
		return;
	}

	if( plaintextNew != plaintext ) {
		cout << "Decryption mismatch!" << endl;
		return;
	}

	LPKeyPair<ILDCRT2n> newKp = cc.KeyGen();

	////////////////////////////////////////////////////////////
	//Perform the proxy re-encryption key generation operation.
	// This generates the keys which are used to perform the key switching.
	////////////////////////////////////////////////////////////

	cout << "Running eval key gen" << endl;

	shared_ptr<LPEvalKey<ILDCRT2n>> evalKey = cc.ReKeyGen(newKp.publicKey, newKp.secretKey);

	if( evalKey == NULL ) {
		cout << "EvalKeyGen failed!!!" << endl;
	}
	else {
		vector<ILDCRT2n> av = evalKey->GetAVector();
		cout << "The eval key A vect size is " << av.size() << endl;

		vector<shared_ptr<Ciphertext<ILDCRT2n>>> newCiphertext;

		cout << "Running re encryption" << endl;
		newCiphertext = cc.ReEncrypt(evalKey, ciphertext);

		////////////////////////////////////////////////////////////
		//Decryption
		////////////////////////////////////////////////////////////

		BytePlaintextEncoding plaintextNew2;

		DecryptResult result1 = cc.Decrypt(newKp.secretKey, newCiphertext, &plaintextNew2);

		if (!result1.isValid) {
			std::cout<<"Decryption failed!"<<std::endl;
			exit(1);
		}

		if( plaintextNew2 != plaintext ) {
			cout << "Decryption mismatch!" << endl;
			return;
		}

	}
}


void TestParameterSelection(){

	usint m = 16;

	float stdDev = 4;

	usint size = 11;
	usint ptm = 2;

	std::cout << "tower size: " << size << std::endl;

	// BytePlaintextEncoding ctxtd;

	vector<native_int::BinaryInteger> moduli(size);

	vector<native_int::BinaryInteger> rootsOfUnity(size);

	native_int::BinaryInteger q(1);
	native_int::BinaryInteger temp;
	BigBinaryInteger modulus(1);

	for(usint i=0; i < size;i++){
		lbcrypto::NextQ(q, native_int::BinaryInteger(ptm), m, native_int::BinaryInteger(4), native_int::BinaryInteger(4));
		moduli[i] = q;
		cout << i << "::" << q << endl;
		rootsOfUnity[i] = RootOfUnity(m,moduli[i]);
		modulus = modulus * BigBinaryInteger(moduli[i].ConvertToInt());
	}

	cout << "big modulus: " << modulus << endl;

	shared_ptr<ILDCRTParams<BigBinaryInteger>> params( new ILDCRTParams<BigBinaryInteger>(m, moduli, rootsOfUnity) );

	LPCryptoParametersLTV<ILDCRT2n> cryptoParams;
	cryptoParams.SetPlaintextModulus(ptm);
	cryptoParams.SetDistributionParameter(stdDev);
	cryptoParams.SetRelinWindow(1);
	cryptoParams.SetElementParams(params);
	cryptoParams.SetAssuranceMeasure(6);
	cryptoParams.SetDepth(size-1);
	cryptoParams.SetSecurityLevel(1.006);

	std::vector<BigBinaryInteger> moduliV(size);
	LPCryptoParametersLTV<ILDCRT2n> cryptoParams2;

	cryptoParams.ParameterSelection(&cryptoParams2);
	//cryptoParams.ParameterSelection(n, moduliV);

	cout << "parameter selection test" << endl;
	cout << cryptoParams2.GetAssuranceMeasure() << endl;

	const shared_ptr<ILDCRTParams<BigBinaryInteger>> dcrtParams = std::static_pointer_cast<ILDCRTParams<BigBinaryInteger>>(cryptoParams2.GetElementParams());
	const std::vector<shared_ptr<native_int::ILParams>>& allparams = dcrtParams->GetParams();

	for(usint i =0; i < allparams.size();i++){
		cout<< allparams[i]->GetModulus() << endl;
	}
}

void FinalLeveledComputation(){

	usint m = 16;

	float init_stdDev = 4;

	usint size = 3;
	usint ptm = 3;

	std::cout << "tower size: " << size << std::endl;

	BytePlaintextEncoding ctxtd;

	vector<native_int::BinaryInteger> moduli(size);

	vector<native_int::BinaryInteger> rootsOfUnity(size);

	native_int::BinaryInteger q(1);
	native_int::BinaryInteger temp;
	BigBinaryInteger modulus(1);

	for(size_t i=0; i < size;i++){
		lbcrypto::NextQ(q, native_int::BinaryInteger(ptm), m, native_int::BinaryInteger(4), native_int::BinaryInteger(4));
		moduli[i] = q;
		rootsOfUnity[i] = RootOfUnity(m,moduli[i]);
		modulus = modulus * BigBinaryInteger(moduli[i].ConvertToInt());
	}

	cout << "big modulus: " << modulus << endl;

	shared_ptr<ILDCRTParams<BigBinaryInteger>> params( new ILDCRTParams<BigBinaryInteger>(m, moduli, rootsOfUnity) );

	std::vector<BigBinaryInteger> moduliV(size);
	LPCryptoParametersLTV<ILDCRT2n> finalParams;

	// use the parameter selection version when it works...
	CryptoContext<ILDCRT2n> cc = CryptoContextFactory<ILDCRT2n>::genCryptoContextLTV(params, ptm, 1, init_stdDev, size-1, 6, 1.006);
	cc.Enable(SHE);
	cc.Enable(ENCRYPTION);
	cc.Enable(LEVELEDSHE);

	//Generate the secret key for the initial ciphertext:
	LPKeyPair<ILDCRT2n> kp = cc.KeyGen();

	// FIXME or explain what, in the name of the old gods and the new, is going on in this code?

#ifdef OUT

	//Generate the secret keys for the levels
	std::vector< LPKeyPair<ILDCRT2n> > levelPairs(finalParams.GetDepth());

	std::vector< shared_ptr<ILDCRTParams<BigBinaryInteger>> > leveledDcrtParams;
	leveledDcrtParams.reserve(finalParams.GetDepth()+1);
	std::vector< LPCryptoParametersLTV<ILDCRT2n> > leveledCryptoParams;
	leveledCryptoParams.reserve(finalParams.GetDepth()+1);

	//Populate the vector of DcrtParams
	// ??? are these supposed to be copies, with different numbers of levels in each one? because they are not
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
	vector<CryptoContext<ILDCRT2n>> leveledCryptoContexts;
	for(usint i=0; i < finalParams.GetDepth(); i++) {
		leveledCryptoContexts.push_back( CryptoContextFactory<ILDCRT2n>::getCryptoContextDCRT(&leveledCryptoParams[i]) );
		levelPairs[i] = leveledCryptoContexts[i].KeyGen();
	}

	shared_ptr<LPEvalKey<ILDCRT2n>> linearKeySwitchHint1;
	shared_ptr<LPEvalKey<ILDCRT2n>> linearKeySwitchHint2;

	linearKeySwitchHint1 = cc.KeySwitchGen(kp.secretKey, levelPairs[0].secretKey);
	auto e = levelPairs[0].secretKey->GetPrivateElement();
	e.DropLastElement();
	levelPairs[0].secretKey->SetPrivateElement(e);

	linearKeySwitchHint2 = cc.KeySwitchGen(levelPairs[0].secretKey, levelPairs[1].secretKey);
	e = levelPairs[1].secretKey->GetPrivateElement();
	e.DropLastElement();
	levelPairs[1].secretKey->SetPrivateElement(e);

	//create the ciphertexts for computation
	ILVector2n element1(dcrtParams);
	element1.SwitchFormat();
	element1 = {1};
	shared_ptr<Ciphertext<ILDCRT2n>> cipherText1 = cc.GetEncryptionAlgorithm()->Encrypt(kp.publicKey,element1);

	ILVector2n element2(dcrtParams);
	element2.SwitchFormat();
	element2 = {2};
	shared_ptr<Ciphertext<ILDCRT2n>> cipherText2 = cc.GetEncryptionAlgorithm()->Encrypt(kp.publicKey,element2);

	ILVector2n element3(dcrtParams);
	element3.SwitchFormat();
	element3 = {3};
	shared_ptr<Ciphertext<ILDCRT2n>> cipherText3 = cc.GetEncryptionAlgorithm()->Encrypt(kp.publicKey,element3);

	ILVector2n element4(dcrtParams);
	element4.SwitchFormat();
	element4 = {4};
	shared_ptr<Ciphertext<ILDCRT2n>> cipherText4 = cc.GetEncryptionAlgorithm()->Encrypt(kp.publicKey,element4);

	ILVector2n element5(dcrtParams);
	element5.SwitchFormat();
	element5 = {5};
	shared_ptr<Ciphertext<ILDCRT2n>> cipherText5 = cc.GetEncryptionAlgorithm()->Encrypt(kp.publicKey,element5);
#endif

}

void ComposedEvalMultTest(){
	usint m = 16;

	float init_stdDev = 4;

	usint size = 3;
	usint relinWindow = 1;
	usint ptm = 5;

	vector<native_int::BinaryInteger> moduli(size);

	vector<native_int::BinaryInteger> rootsOfUnity(size);

	native_int::BinaryInteger q(1);
	native_int::BinaryInteger temp;
	BigBinaryInteger modulus(1);

	for(size_t i=0; i < size; i++){
		lbcrypto::NextQ(q, native_int::BinaryInteger(ptm), m, native_int::BinaryInteger(4), native_int::BinaryInteger(4));
		moduli[i] = q;
		rootsOfUnity[i] = RootOfUnity(m,moduli[i]);
		modulus = modulus * BigBinaryInteger(moduli[i].ConvertToInt());
	}

	shared_ptr<ILDCRTParams<BigBinaryInteger>> params( new ILDCRTParams<BigBinaryInteger>(m, moduli, rootsOfUnity) );

	// FIXME use the parm selection method when it works
	CryptoContext<ILDCRT2n> cc = CryptoContextFactory<ILDCRT2n>::genCryptoContextLTV(params, ptm, relinWindow, init_stdDev, size-1, 6, 1.006);
	cc.Enable(SHE);
	cc.Enable(ENCRYPTION);
	cc.Enable(LEVELEDSHE);

	//Generate the secret key for the initial ciphertext:
	LPKeyPair<ILDCRT2n> kp = cc.KeyGen();

	//Generate the switch cipher text
	LPKeyPair<ILDCRT2n> kpNew = cc.KeyGen();

//	//Generating original ciphertext to perform ComposedEvalMult on
//	shared_ptr<Ciphertext<ILDCRT2n>> c1;
//
//	shared_ptr<Ciphertext<ILDCRT2n>> c2;
//
//	//Generating new cryptoparameters for when modulus reduction is done.
//	LPCryptoParametersLTV<ILDCRT2n> finalParamsTwoTowers(finalParamsThreeTowers);
//
//	const shared_ptr<ILDCRTParams<BigBinaryInteger>> dcrtParams2 = std::static_pointer_cast<ILDCRTParams<BigBinaryInteger>>(finalParamsThreeTowers.GetElementParams());
//	shared_ptr<ILDCRTParams<BigBinaryInteger>> finalDcrtParamsTwoTowers( new ILDCRTParams<BigBinaryInteger>(*dcrtParams2) );
//	finalDcrtParamsTwoTowers->PopLastParam();
//	finalParamsTwoTowers.SetElementParams(finalDcrtParamsTwoTowers);
//
//	//Dropping the last tower of skNew, because ComposedEvalMult performs a ModReduce
//	ILDCRT2n skNewOldElement(kpNew.secretKey->GetPrivateElement());
//	skNewOldElement.DropLastElement();
//	kpNew.secretKey->SetPrivateElement(skNewOldElement);

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
