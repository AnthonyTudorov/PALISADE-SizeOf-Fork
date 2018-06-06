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
benchmarking BFVrnsB pke scheme
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

#include "bench-out-format.h"

typedef std::numeric_limits< double > dbl;

using namespace std;
using namespace lbcrypto;


#include <iterator>

//Poly tests
void SHERun(usint inRunsCount, usint inPtm, double inSigma, double inRootHermiteFactor, usint level, usint runIdx);


const usint RUNS_COUNT = 10;
const int NUM_POLYNOMIAL_DEGREES = 6; // number of experiments (different parameters settings to test)
const size_t CRT_SIZE_BITS = 30; // CRT moduli size

// statistics buffers
double decPerfAvg[NUM_POLYNOMIAL_DEGREES];
double mulOnlyPerfAvg[NUM_POLYNOMIAL_DEGREES];
double relinPerfAvg[NUM_POLYNOMIAL_DEGREES];
double totHomoMulPerfAvg[NUM_POLYNOMIAL_DEGREES];

usint ringDimensions[NUM_POLYNOMIAL_DEGREES];
double logq[NUM_POLYNOMIAL_DEGREES];

int main() {


	cout << "PALISADE BFVrnsB benchmarking started ...\n";

	// old
//	int ptmArr[NUM_POLYNOMIAL_DEGREES] = {2, 2, 2, 2, 2};
//	double sigmaArr[NUM_POLYNOMIAL_DEGREES] = {3.2, 3.2, 3.2, 3.2, 3.2};
//	double rootHermiteFactorArr[NUM_POLYNOMIAL_DEGREES] = {1.020, 1.00763, 1.00763, 1.00763, 1.00862};
//	int levelsArr[NUM_POLYNOMIAL_DEGREES] = {2, 5, 19, 41, 57};

	// ======================================= Decryption exp ======================================

	// what we need (30-bits)
//	int ptmArr[NUM_POLYNOMIAL_DEGREES] = {2, 2, 2, 3, 2, 2};
//	double sigmaArr[NUM_POLYNOMIAL_DEGREES] = {8, 294.73, 64, 350, 1000, 300 };
//	double rootHermiteFactorArr[NUM_POLYNOMIAL_DEGREES] = {1.00763, 1.0061663, 1.00763, 1.007283, 1.007283, 1.007283};
//	int levelsArr[NUM_POLYNOMIAL_DEGREES] = {3, 8, 18, 39, 71, 101};

	// what we need (45-bits)
//	int ptmArr[NUM_POLYNOMIAL_DEGREES] = {2, 2, 2, 3, 2, 2};
//	double sigmaArr[NUM_POLYNOMIAL_DEGREES] = {8, 294.73, 64, 350, 1000, 300 };
//	double rootHermiteFactorArr[NUM_POLYNOMIAL_DEGREES] = {1.00763, 1.0061663, 1.00763, 1.007283, 1.007283, 1.007283};
//	int levelsArr[NUM_POLYNOMIAL_DEGREES] = {3, 5, 18, 36, 71, 101};

	// what we need (60-bits)
//	int ptmArr[NUM_POLYNOMIAL_DEGREES] = {2, 2, 2, 2, 2, 2};
//	double sigmaArr[NUM_POLYNOMIAL_DEGREES] = {3.2, 3.2, 3.2, 3.2, 72, 102};
//	double rootHermiteFactorArr[NUM_POLYNOMIAL_DEGREES] = {1.020, 1.00763, 1.00763, 1.00763, 1.006442, 1.00481};
//	int levelsArr[NUM_POLYNOMIAL_DEGREES] = {2, 5, 19, 41, 67, 95};

//	int ptmArr[NUM_POLYNOMIAL_DEGREES] = {2};
//	double sigmaArr[NUM_POLYNOMIAL_DEGREES] = {300};
//	double rootHermiteFactorArr[NUM_POLYNOMIAL_DEGREES] = {1.007283};
//	int levelsArr[NUM_POLYNOMIAL_DEGREES] = {101};

	//=======================================================================================





	// ======================================= Multiplication Experiment======================================
	// Multiplication Experiment
	int ptmArr[NUM_POLYNOMIAL_DEGREES] = {2, 2, 2, 2, 2, 2};
	double sigmaArr[NUM_POLYNOMIAL_DEGREES] = {3.2, 3.2, 3.2, 3.2, 72, 102};
	double rootHermiteFactorArr[NUM_POLYNOMIAL_DEGREES] = {1.0048, 1.0048, 1.0048, 1.0048, 1.0048, 1.0048};

//	int levelsArr[NUM_POLYNOMIAL_DEGREES] = {1, 5, 19, 33, 54, 97}; // t = 2; 30-bit
//	int levelsArr[NUM_POLYNOMIAL_DEGREES] = {0, 3, 17, 29, 51, 95}; // t = 2; 60-bit

	int levelsArr[NUM_POLYNOMIAL_DEGREES];
	if ( CRT_SIZE_BITS == 30 )
	{
		//{1, 5, 19, 33, 54, 97};
		levelsArr[0] = 1;
		levelsArr[1] = 5;
		levelsArr[2] = 19;
		levelsArr[3] = 33;
		levelsArr[4] = 54;
		levelsArr[5] = 97;
	}
	else // 60
	{
		//{0, 3, 17, 29, 51, 95};
		levelsArr[0] = 0;
		levelsArr[1] = 3;
		levelsArr[2] = 17;
		levelsArr[3] = 29;
		levelsArr[4] = 51;
		levelsArr[5] = 95;
	}


	//	int ptmArr[NUM_POLYNOMIAL_DEGREES] = {2};
//	double sigmaArr[NUM_POLYNOMIAL_DEGREES] = {72};
//	double rootHermiteFactorArr[NUM_POLYNOMIAL_DEGREES] = {1.008};
//	int levelsArr[NUM_POLYNOMIAL_DEGREES] = {67};
	// =======================================================================================================


	// clear buffers
	memset(decPerfAvg, 0, sizeof(decPerfAvg));
	memset(mulOnlyPerfAvg, 0, sizeof(mulOnlyPerfAvg));
	memset(relinPerfAvg, 0, sizeof(relinPerfAvg));
	memset(totHomoMulPerfAvg, 0, sizeof(totHomoMulPerfAvg));

	for (usint i = 0; i < NUM_POLYNOMIAL_DEGREES; i++)
	{
		usint ptm = ptmArr[i];
		double sigma = sigmaArr[i];
		double rootHermiteFactor = rootHermiteFactorArr[i];
		int level = levelsArr[i];

		cout << "==========================================================\n";
		cout << "                 Experiment [" << i+1 << "]:" << endl;
		cout << "==========================================================\n";


		if ( i >= 4) // large settings too slow
		{
			SHERun(RUNS_COUNT/10, ptm, sigma, rootHermiteFactor, level, i);
		}
		else
		{
			SHERun(RUNS_COUNT, ptm, sigma, rootHermiteFactor, level, i);
		}
	}

	cout << "--------------------------------------- RESULTS ------------------------------- " << endl << endl;

	const int stringWidth = 14;
	const int doubleNumWidth = 19;

	cout << "BFVrnsB primitives average values over " << RUNS_COUNT << " runs: " << endl;
	cout << "------------------------------------------------------------------------------------------------------------------------\n";
	for (int i = 0; i < NUM_POLYNOMIAL_DEGREES ; i++)
	{
		if (i == 0)
		{
			cout << left( "Func/(n,logq)", stringWidth );
		}
		cout << right( "("+std::to_string(ringDimensions[i])+ ","+ to_string((int)ceil(logq[i])) + ")" + "ms", doubleNumWidth );
	}
	cout << endl;
	cout << "------------------------------------------------------------------------------------------------------------------------\n";

	cout << left( "Dec", stringWidth );
	for (int i = 0 ; i < NUM_POLYNOMIAL_DEGREES ; i++)
	{
		cout << right( prd(decPerfAvg[i], 3), doubleNumWidth );
	}
	cout << endl;

	cout << left( "mul only", stringWidth );
	for (int i = 0 ; i < NUM_POLYNOMIAL_DEGREES ; i++)
	{
		cout << right( prd(mulOnlyPerfAvg[i], 3), doubleNumWidth );
	}
	cout << endl;

	cout << left( "relin only", stringWidth );
	for (int i = 0 ; i < NUM_POLYNOMIAL_DEGREES ; i++)
	{
		cout << right( prd(relinPerfAvg[i], 3), doubleNumWidth );
	}
	cout << endl;

	cout << left( "mul+relin", stringWidth );
	for (int i = 0 ; i < NUM_POLYNOMIAL_DEGREES ; i++)
	{
		 cout << right( prd(totHomoMulPerfAvg[i], 3), doubleNumWidth );
	}
	cout << endl;

	cout << "------------------------------------------------------------------------------- " << endl << endl;

cout << "BFVrnsB benchmarcking terminated!\n";

	//cin.get();
	return 0;
}

#define PROFILE

void SHERun(usint inRunsCount, usint inPtm, double inSigma, double inRootHermiteFactor, usint level, usint runIdx) {

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

	//Generate parameters.
	double diff, start, finish;

	usint ptm = inPtm;
	double sigma = inSigma;
	double rootHermiteFactor = inRootHermiteFactor;

	size_t count = inRunsCount;

	//Set Crypto Parameters
	CryptoContext<DCRTPoly> cryptoContext = CryptoContextFactory<DCRTPoly>::genCryptoContextBFVrnsB(
			ptm, rootHermiteFactor, sigma, 0, level, 0, OPTIMIZED,3, 0, CRT_SIZE_BITS);

	// enable features that you wish to use
	cryptoContext->Enable(ENCRYPTION);
	cryptoContext->Enable(SHE);

//	std::cout << "p = " << cryptoContext->GetCryptoParameters()->GetPlaintextModulus() << std::endl;
//	std::cout << "n = " << cryptoContext->GetCryptoParameters()->GetElementParams()->GetCyclotomicOrder() / 2 << std::endl;
//	std::cout << "log2 q = " << log2(cryptoContext->GetCryptoParameters()->GetElementParams()->GetModulus().ConvertToDouble()) << std::endl;

	ringDimensions[runIdx] = cryptoContext->GetCryptoParameters()->GetElementParams()->GetCyclotomicOrder() / 2;
//	logq[runIdx] = log2(cryptoContext->GetCryptoParameters()->GetElementParams()->GetModulus().ConvertToDouble());

	std::string strMod = cryptoContext->GetCryptoParameters()->GetElementParams()->GetModulus().ToString();
	NTL::ZZ zzMod;
	conv(zzMod, strMod.c_str());
	logq[runIdx] = NTL::NumBits(zzMod);

	if (RUNS_COUNT == 1)
	{
		cout << "n: " << ringDimensions[runIdx] << endl;
		cout << "logq: " << logq[runIdx] << endl;
	}

	// Initialize Public Key Containers
	LPKeyPair<DCRTPoly> keyPair;

	////////////////////////////////////////////////////////////
	// Perform Key Generation Operation
	////////////////////////////////////////////////////////////

	std::cout << "Running key generation (used for source data)..." << std::endl;

	start = currentDateTime();

	keyPair = cryptoContext->KeyGen();

	finish = currentDateTime();
	diff = finish - start;
	cout << "Key generation time: " << "\t" << diff << " ms" << endl;

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
	double timeMult(0.0);
	double timeRelin(0.0);

	for (size_t k=0; k < count; k++) {

		TimeVar tDecrypt;
		TimeVar tMult;
		TimeVar tRelin;

		auto ciphertext1 = cryptoContext->Encrypt(keyPair.publicKey, plaintext1);

		auto ciphertext2 = cryptoContext->Encrypt(keyPair.publicKey, plaintext2);

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

//	std::cout << "Average decryption time:\t" << timeDecrypt/(1000*count) << " ms" << std::endl;
//	std::cout << "Average multiplication time:\t" << timeMult/(1000*count) << " ms" <<  std::endl;
//	std::cout << "Average relinearization time:\t" << (timeRelin-timeMult)/(1000*count) << " ms" << std::endl;
//	std::cout << "Average multiplication + relinearization time:\t" << timeRelin/(1000*count) << " ms" <<  std::endl;

	decPerfAvg[runIdx] = timeDecrypt/(1000*count);
	mulOnlyPerfAvg[runIdx] = timeMult/(1000*count);
	relinPerfAvg[runIdx] = (timeRelin-timeMult)/(1000*count);
	totHomoMulPerfAvg[runIdx] = timeRelin/(1000*count);

}
