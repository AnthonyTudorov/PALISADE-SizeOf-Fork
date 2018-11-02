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
 /*
BFV RNS testing programs
*/

#include <iostream>
#include <fstream>
#include <limits>

#include "palisade.h"


#include "cryptocontexthelper.h"

#include "encoding/encodings.h"

#include "utils/debug.h"
#include <random>

#include "math/nbtheory.h"

typedef std::numeric_limits< double > dbl;

using namespace std;
using namespace lbcrypto;


#include <iterator>

//Poly tests
void BFVrns();
void NTT();

int main() {

	BFVrns();

	NTT();

	return 0;
}

#define PROFILE

void BFVrns() {

	int nthreads, tid;

	// Fork a team of threads giving them their own copies of variables
	//so we can see how many threads we have to work with
    #pragma omp parallel private(nthreads, tid)
	{

		/* Obtain thread number */
		tid = omp_get_thread_num();

		/* Only master thread does this */
		if (tid == 0)
		{
			nthreads = omp_get_num_threads();
			std::cout << "Number of threads = " << nthreads << std::endl;
		}
	}

	std::cout << "\n===========BENCHMARKING FOR BFVRNS===============: " << std::endl;

	usint ptm = 2;
	double sigma = 3.19;
	double rootHermiteFactor = 1.0048;

	size_t count = 100;

	//Set Crypto Parameters
	CryptoContext<DCRTPoly> cryptoContext = CryptoContextFactory<DCRTPoly>::genCryptoContextBFVrns(
			ptm, rootHermiteFactor, sigma, 0, 5, 0, OPTIMIZED,3,30,55);

	// enable features that you wish to use
	cryptoContext->Enable(ENCRYPTION);
	cryptoContext->Enable(SHE);

	std::cout << "\np = " << cryptoContext->GetCryptoParameters()->GetPlaintextModulus() << std::endl;
	std::cout << "n = " << cryptoContext->GetCryptoParameters()->GetElementParams()->GetCyclotomicOrder() / 2 << std::endl;
	std::cout << "log2 q = " << log2(cryptoContext->GetCryptoParameters()->GetElementParams()->GetModulus().ConvertToDouble()) << std::endl;

	// Initialize Public Key Containers
	LPKeyPair<DCRTPoly> keyPair;

	////////////////////////////////////////////////////////////
	// Perform Key Generation Operation
	////////////////////////////////////////////////////////////

	double timeKeyGen(0.0);
	TimeVar t1;

	std::cout << "Running key generation (used for source data)..." << std::endl;

	TIC(t1);

	keyPair = cryptoContext->KeyGen();

	timeKeyGen = TOC_US(t1);
	cout << "\nKey generation time: " << "\t" << timeKeyGen/1000 << " ms" << endl;

	if( !keyPair.good() ) {
		std::cout << "Key generation failed!" << std::endl;
		exit(1);
	}

	cryptoContext->EvalMultKeyGen(keyPair.secretKey);

	////////////////////////////////////////////////////////////
	// Encode source data
	////////////////////////////////////////////////////////////

	std::vector<int64_t> vectorOfInts1 = {1,0,1,0,1,1,1,0,1,1,1,0};
	Plaintext plaintext1 = cryptoContext->MakeCoefPackedPlaintext(vectorOfInts1);

	std::vector<int64_t> vectorOfInts2 = {1,1,1,1,1,1,1,0,1,1,1,0};
	Plaintext plaintext2 = cryptoContext->MakeCoefPackedPlaintext(vectorOfInts2);

	double timeDecrypt(0.0);
	double timeEncrypt(0.0);
	double timeMult(0.0);
	double timeRelin(0.0);

	for (size_t k=0; k < count; k++) {

		TimeVar tDecrypt;
		TimeVar tMult;
		TimeVar tRelin;
		TimeVar tEncrypt;

		auto ciphertext1 = cryptoContext->Encrypt(keyPair.publicKey, plaintext1);

		TIC(tEncrypt);
		auto ciphertext2 = cryptoContext->Encrypt(keyPair.publicKey, plaintext2);
		timeEncrypt+=TOC_US(tEncrypt);

		Plaintext plaintextDec1;
		cryptoContext->Decrypt(keyPair.secretKey, ciphertext1, &plaintextDec1);

		Plaintext plaintextDec2;
		TIC(tDecrypt);
		cryptoContext->Decrypt(keyPair.secretKey, ciphertext2, &plaintextDec2);
		timeDecrypt+=TOC_US(tDecrypt);

		TIC(tMult);
		auto ciphertextMul = cryptoContext->EvalMultNoRelin(ciphertext1,ciphertext2);
		timeMult+=TOC_US(tMult);

		TIC(tRelin);
		auto ciphertextMulRelin = cryptoContext->EvalMult(ciphertext1,ciphertext2);
		timeRelin+=TOC_US(tRelin);

	}

	std::cout << "Average encryption time:\t" << timeEncrypt/(1000*count) << " ms" << std::endl;
	std::cout << "Average decryption time:\t" << timeDecrypt/(1000*count) << " ms" << std::endl;
	std::cout << "Average multiplication time:\t" << timeMult/(1000*count) << " ms" <<  std::endl;
	std::cout << "Average relinearization time:\t" << (timeRelin-timeMult)/(1000*count) << " ms" << std::endl;
	std::cout << "Average multiplication + relinearization time:\t" << timeRelin/(1000*count) << " ms" <<  std::endl;

}

void NTT() {

	usint m = 2048;
	usint phim = 1024;

	NativeInteger modulusQ("288230376151748609");
	NativeInteger rootOfUnity("64073710037604316");

	uint64_t nRep;

	double timeRun(0.0);
	TimeVar t1;

	DiscreteUniformGeneratorImpl<NativeVector> dug;
	dug.SetModulus(modulusQ);
	NativeVector x = dug.GenerateVector(phim);

	NativeVector rootOfUnityTable(phim, modulusQ);
	NativeInteger t(1);
	for (usint i = 0; i<phim; i++) {
		rootOfUnityTable.at(i)= t;
		t = t.ModMul(rootOfUnity, modulusQ);
	}

	// test runs to force all precomputations
	NativeVector X(m/2), xx(m/2);
	ChineseRemainderTransformFTT<NativeVector>::ForwardTransform(x, rootOfUnity, m, &X);
	ChineseRemainderTransformFTT<NativeVector>::InverseTransform(X, rootOfUnity, m, &xx);


	nRep = 10000;
	TIC(t1);
	for(uint64_t n=0; n<nRep; n++){
		ChineseRemainderTransformFTT<NativeVector>::ForwardTransform(x, rootOfUnity, m, &X);
	}
	timeRun = TOC_US(t1);

	std::cout << "\n===========BENCHMARKING FOR NTT===============: " << std::endl;

	std::cout << "\nn = " << m / 2 << std::endl;
	std::cout << "log2 q = " << log2(modulusQ.ConvertToDouble()) << std::endl;

	std::cout << "\nNTT Average NTT time: " << timeRun/(nRep*1000) << " ms" << std::endl;

}

