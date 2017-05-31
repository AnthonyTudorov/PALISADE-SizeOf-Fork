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


#include "palisade.h"


#include "cryptocontexthelper.h"

#include "encoding/byteplaintextencoding.h"
#include "encoding/packedintplaintextencoding.h"

#include "utils/debug.h"
#include <random>

#include "math/nbtheory.h"
#include "math/matrix.h"
#include "math/matrix.cpp"

using namespace std;
using namespace lbcrypto;


#include <iterator>

void ArbFVLinearRegressionPackedArray();
void FVAutomorphismPackedArray(usint i);

int main() {

	//ArbFVLinearRegressionPackedArray();

	FVAutomorphismPackedArray(3);

	std::cout << "Please press any key to continue..." << std::endl;

	std::cin.get();
	return 0;
}

void ArbFVLinearRegressionPackedArray() {

	double start, finish;

	usint m = 9742;
	usint N = GetTotient(m);
	usint p = 9743; // we choose s.t. 2m|p-1 to leverage CRTArb
	//BigBinaryInteger modulusQ("1329227995784915872903807060280351429");
	//BigBinaryInteger modulusP(p);
	//BigBinaryInteger rootOfUnity("526837940761322393507252072213464708");

	//BigBinaryInteger bigmodulus("56539106072908298546665520023773392506479484700019806659891398441363839489");
	//BigBinaryInteger bigroot("9767153299292203445583087811236008026651327014721082209123889105907321132");

	BigBinaryInteger modulusQ("1329227995784915872903807060281374689");
	BigBinaryInteger modulusP(p);
	BigBinaryInteger rootOfUnity("1103835257645791936030700335506173789");

	BigBinaryInteger bigmodulus("1852673427797059126777135760139006525652319754650249024631321344126610076631041");
	BigBinaryInteger bigroot("1011857408422309039039556907195908859561535234649870814154019834362746408101010");

	auto cycloPoly = GetCyclotomicPolynomial<BigBinaryVector, BigBinaryInteger>(m, modulusQ);
	//ChineseRemainderTransformArb<BigBinaryInteger, BigBinaryVector>::GetInstance().PreCompute(m, modulusQ);
	ChineseRemainderTransformArb<BigBinaryInteger, BigBinaryVector>::SetCylotomicPolynomial(cycloPoly, modulusQ);

	float stdDev = 4;

	shared_ptr<ILParams> params(new ILParams(m, modulusQ, rootOfUnity, bigmodulus, bigroot));

	BigBinaryInteger bigEvalMultModulus("56539106072908298546665520023773392506479484700019806659891398441365159009");
	BigBinaryInteger bigEvalMultRootOfUnity("27681748302031208086529357703675721915997519149708293786572755513112792120");
	BigBinaryInteger bigEvalMultModulusAlt("3351951982485649274893506249551461531869841455148098344430890360930441007518386744200468574541725856922507964546621512713438470702986642486608412265316353");
	BigBinaryInteger bigEvalMultRootOfUnityAlt("2651384661600703101500267622642179010771413784761520506253393444361764074502991984346270200858413920590791655430952921095238961909406720304044760347836013");

	auto cycloPolyBig = GetCyclotomicPolynomial<BigBinaryVector, BigBinaryInteger>(m, bigEvalMultModulus);
	//ChineseRemainderTransformArb<BigBinaryInteger, BigBinaryVector>::GetInstance().PreCompute(m, modulusQ);
	ChineseRemainderTransformArb<BigBinaryInteger, BigBinaryVector>::SetCylotomicPolynomial(cycloPolyBig, bigEvalMultModulus);

	std::cout << "Precomputing CRT coefficients" << std::endl;

	start = currentDateTime();
	
	PackedIntPlaintextEncoding::SetParams(modulusP, m);

	finish = currentDateTime();

	std::cout << "Precomputation time: " << "\t" << (finish - start) << " ms" << std::endl;
	
	usint batchSize = 4096;
	usint relinWindow = 24;

	shared_ptr<EncodingParams> encodingParams(new EncodingParams(modulusP, PackedIntPlaintextEncoding::GetInitRoot(), batchSize));

	BigBinaryInteger delta(modulusQ.DividedBy(modulusP));

	//genCryptoContextFV(shared_ptr<typename Element::Params> params,
	//	shared_ptr<typename EncodingParams> encodingParams,
	//	usint relinWindow, float stDev, const std::string& delta,
	//	MODE mode = RLWE, const std::string& bigmodulus = "0", const std::string& bigrootofunity = "0",
	//	int depth = 0, int assuranceMeasure = 0, float securityLevel = 0,
	//	const std::string& bigmodulusarb = "0", const std::string& bigrootofunityarb = "0")

	CryptoContext<ILVector2n> cc = CryptoContextFactory<ILVector2n>::genCryptoContextFV(params, encodingParams, relinWindow, stdDev, delta.ToString(), OPTIMIZED,
		bigEvalMultModulus.ToString(), bigEvalMultRootOfUnity.ToString(), 1, 9, 1.006, bigEvalMultModulusAlt.ToString(), bigEvalMultRootOfUnityAlt.ToString());

	cc.Enable(ENCRYPTION);
	cc.Enable(SHE);


	std::cout << "Starting key generation" << std::endl;

	start = currentDateTime();

		// Initialize the public key containers.
	LPKeyPair<ILVector2n> kp = cc.KeyGen();

	finish = currentDateTime();

	std::cout << "Key generation: " << "\t" << (finish - start) << " ms" << std::endl;

	std::cout << "Starting EValSum key generation" << std::endl;

	start = currentDateTime();

	//Compute evaluation key for EvalSum
	cc.EvalSumKeyGen(kp.secretKey);

	finish = currentDateTime();

	std::cout << "EvalSum key generation: " << "\t" << (finish - start) << " ms" << std::endl;

	// Compute evaluation keys
	cc.EvalMultKeyGen(kp.secretKey);

	auto zeroAlloc = [=]() { return lbcrypto::make_unique<PackedIntPlaintextEncoding>(); };

	Matrix<PackedIntPlaintextEncoding> xP = Matrix<PackedIntPlaintextEncoding>(zeroAlloc, 1, 2);

	xP(0, 0) = { 1,0,0,0,1,0,1,0,0,0,0,1,0,1,0,0,1,1,1,1,1,1,1,1,1,0,1,0,1,0,0,0,1,1,1,1,0,0,1,0,1,1,0,0,0,1,0,0,0,1,1,1,0,1,1,1,0,1,1,0,1,1,1,0,0,1,1,0,1,1,0,0,0,0,1,1,0,0,1,0,1,0,0,1,1,0,0,1,1,1,1,0,1,1,1,1,1,1,1,0,1,1,0,0,1,1,0,0,0,1,0,0,0,1,0,0,0,1,0,0,0,0,1,0,0,1,1,1,1,0,1,0,0,0,1,0,0,0,1,1,1,0,0,1,1,1,1,0,0,0,1,0,0,1,1,0,1,1,0,0,1,0,1,1,0,0,0,1,0,0,0,1,0,1,0,1,1,0,0,1,1,1,0,1,1,0,0,0,1,1,1,1,1,0,1,1,0,1,1,0,1,0,0,0,0,0,1,1,0,0,0,0,1,1,0,0,1,0,0,1,0,1,1,0,0,1,1,1,0,1,0,1,1,0,0,0,0,0,0,0,1,0,1,1,1,0,1,0,1,1,1,0,0,0,0,0,1,0,0,1,0,1,0,0,0,1,0,1,1,1,1,0,0,0,0,1,0,1,0,0,1,0,0,0,0,0,0,0,1,0,0,1,1,0,0,0,1,0,1,1,1,0,0,0,0,1,1,0,1,0,1,1,1,1,0,0,1,0,1,0,1,1,0,0,0,1,1,0,1,1,0,0,1,0,1,0,0,1,1,1,0,1,1,0,1,0,1,1,0,1,0,0,0,0,1,0,0,0,0,1,0,0,0,1,0,0,1,1,1,1,0,0,1,1,0,1,0,0,0,0,0,0,0,0,1,1,0,1,0,0,0,0,1,0,0,1,0,0,1,0,0,1,0,0,0,1,0,0,0,1,1,1,1,0,0,1,1,0,0,0,0,1,1,1,0,0,0,1,1,0,0,0,1,1,1,1,1,1,1,0,1,0,0,1,1,0,0,1,0,1,0,1,1,1,0,0,1,1,0,1,1,1,1,1,1,0,0,1,1,1,1,0,1,1,0,0,1,0,1,1,1,1,1,0,0,1,0,1,1,0,1,1,1,0,1,0,0,1,1,0,0,0,1,0,1,1,0,1,0,0,0,0,1,1,0,0,0,1,0,1,1,1,1,0,0,0,0,0,1,0,0,0,1,1,0,1,0,0,1,1,0,0,0,1,0,0,1,1,1,1,1,1,1,0,0,0,0,0,1,0,0,1,0,0,1,1,1,0,0,1,0,1,1,0,0,0,1,0,0,1,1,0,1,1,1,0,0,1,1,0,1,0,1,0,1,0,0,1,1,1,0,1,0,1,1,0,0,1,0,1,0,0,0,1,0,1,1,0,0,0,1,1,0,0,1,0,0,0,0,0,0,1,0,0,1,0,0,0,1,0,0,1,0,0,0,0,0,0,0,1,1,1,0,0,1,0,0,0,1,0,0,0,1,0,0,1,0,1,1,1,1,0,1,0,1,0,1,1,0,1,1,1,1,0,1,0,1,0,1,0,0,0,0,1,1,0,1,0,1,1,0,1,1,0,1,1,1,0,1,0,1,0,1,0,1,0,1,0,1,1,0,0,1,0,0,0,1,0,0,1,1,1,1,1,1,1,0,1,0,0,0,1,1,0,1,0,1,1,1,1,0,1,1,1,1,1,0,0,1,0,1,0,1,0,1,1,1,1,0,0,0,1,0,0,0,1,0,1,1,0,0,0,1,0,1,0,0,0,0,1,0,0,1,1,0,0,1,1,0,0,1,1,1,1,1,1,0,1,1,0,1,1,0,1,1,0,1,1,1,1,1,1,0,1,1,0,1,1,0,1,0,1,0,0,1,0,1,1,1,1,0,0,0,1,1,0,0,1,1,0,1,1,0,0,1,0,0,1,1,0,1,0,1,1,0,1,1,1,1,0,0,1,0,1,0,1,1,0,0,1,1,0,0,0,0,0,1,1,0,0,0,1,0,1,0,0,1,0,1,1,1,0,1,0,0,1,1,0,1,0,1,0,0,0,1,0,0,0,0,0,1,0,0,0,0,1,0,1,0,0,0,1,1,1,1,1,1,0,1,0,0,0,1,1,0,0,1,0,0,1,0,1,1,1,0,1,1,1,1,0,1,0,0,0,0,0,1,0,1,0,1,0,0,1,1,1,0,1,0,0,0,0,0,1,1,0,0,0,1,0,1,0,0,0,1,1,1,1,0,1,1,0,0,1,0,0,0,0,0,0,0,0,1,1,1,1,0,1,0,1,0,0,1,1,1,1,0,0,0,0,1,1,0,1,0,1,1,0,1,1,0,0,0,1,1,0,0,1,0,1,1,0,1,1,1,0,0,1,1,1,1,1,0,0,1,0,1,0,0,1,0,0,1,1,0,1,1,0,0,1,1,0,0,1,0,0,1,1,1,1,0,1,0,1,1,1,1,1,0,1,1,1,1,1,1,0,0,1,0,0,0,0,1,0,1,0,0,1,0,0,1,0,1,0,1,0,1,0,0,1,0,0,0,1,0,0,1,1,0,1,1,0,1,1,0,1,0,0,0,1,1,1,0,0,1,1,0,0,1,1,1,1,1,0,0,1,0,1,1,1,1,1,0,1,1,1,0,1,1,0,1,0,0,0,0,0,1,0,1,1,1,0,0,0,1,0,0,1,0,1,0,0,0,0,0,0,1,1,1,1,1,0,0,1,1,1,0,1,1,1,0,0,1,1,0,0,1,0,0,1,0,0,0,1,1,1,0,1,0,0,1,1,1,0,0,1,0,1,0,1,1,1,0,1,0,0,1,1,0,0,0,0,1,1,1,1,1,1,1,1,1,0,0,0,0,0,0,1,1,1,1,1,0,1,0,0,0,0,0,1,1,1,1,0,0,0,1,1,1,1,1,0,0,0,0,0,1,1,0,0,0,1,0,0,1,1,0,0,0,0,1,1,0,1,0,1,1,0,0,0,1,0,0,1,0,0,0,0,0,0,1,0,0,0,0,0,0,1,0,1,1,1,0,1,0,0,1,1,0,1,0,1,0,1,1,0,0,0,1,1,1,0,1,1,1,0,1,1,1,1,0,1,1,0,0,1,0,1,0,1,0,1,0,1,1,1,0,1,0,0,0,1,1,0,1,0,1,1,0,0,0,1,1,0,0,1,0,1,0,1,1,1,0,0,1,1,1,1,1,0,1,1,1,1,1,0,1,0,0,0,1,1,1,1,1,0,0,1,1,0,0,0,1,0,1,1,0,1,1,1,1,0,0,0,0,1,0,1,0,0,1,1,1,1,1,1,1,1,0,1,0,1,0,1,0,1,1,0,1,1,1,0,1,1,0,0,1,1,0,0,1,1,0,0,1,1,0,0,1,0,1,0,0,1,0,0,1,1,0,1,1,0,1,0,0,1,1,1,1,0,0,1,1,0,0,1,1,0,0,1,1,1,1,1,0,0,0,0,1,1,1,0,0,0,1,0,1,0,1,0,0,0,1,1,0,0,1,1,0,1,0,1,1,1,1,0,1,0,1,1,0,1,1,0,1,0,1,1,0,1,0,0,1,1,0,1,1,1,1,1,1,0,1,0,1,0,1,1,0,0,1,0,0,1,1,1,1,1,0,1,1,1,0,0,1,0,0,1,1,0,1,1,1,1,0,0,0,0,1,0,0,1,1,0,1,0,0,1,1,1,1,1,0,0,1,1,1,0,0,0,0,0,1,1,0,0,1,0,1,1,1,0,0,0,1,1,1,1,1,0,1,1,1,1,1,0,0,0,0,0,1,0,0,0,0,1,0,1,1,0,1,0,1,0,0,0,0,0,1,1,1,0,0,0,1,1,1,0,0,1,1,1,1,0,1,0,1,0,0,1,1,1,0,1,1,0,0,0,1,0,1,0,0,1,1,0,1,0,1,1,0,0,0,1,0,0,1,0,0,0,0,0,1,1,0,0,0,1,0,1,1,0,0,0,0,0,0,1,1,1,1,1,1,1,1,1,1,0,0,0,1,1,1,1,0,0,1,1,1,1,1,1,0,1,0,0,1,0,0,1,1,1,1,0,0,1,0,1,0,0,1,0,1,1,1,0,0,0,1,1,0,0,1,0,1,1,0,0,1,1,1,0,1,1,1,1,0,0,0,1,0,0,0,0,0,1,1,1,1,0,1,0,0,1,0,0,0,0,1,1,1,0,0,0,1,0,1,1,0,1,1,1,0,1,0,0,1,1,0,0,0,0,0,1,1,1,1,0,1,0,1,0,0,0,0,1,0,1,1,1,0,0,0,0,0,0,0,1,1,1,1,1,1,0,1,1,1,0,1,1,0,1,0,1,0,0,0,1,0,0,0,1,0,0,0,0,1,0,1,1,1,1,0,0,0,1,1,0,0,1,0,1,0,0,0,1,1,1,0,1,0,0,1,1,0,1,1,0,1,1,0,1,1,1,1,0,1,1,0,0,0,0,1,0,0,1,1,0,1,0,0,0,1,0,0,1,1,1,0,1,0,1,0,1,0,0,1,0,1,0,0,1,1,0,1,0,0,1,0,1,0,1,1,1,0,0,1,1,1,1,1,1,0,0,1,1,0,1,0,1,1,0,0,0,1,0,0,0,1,1,1,1,1,1,1,1,0,1,1,0,0,0,0,0,0,0,0,1,0,0,1,1,0,1,0,0,0,1,1,0,0,1,0,1,0,1,0,0,0,1,0,1,0,0,0,1,0,0,0,1,1,1,0,1,0,1,0,1,0,1,0,0,0,1,1,1,1,1,0,1,1,1,1,0,0,1,0,0,0,1,0,1,1,0,0,1,0,0,0,1,0,0,0,1,1,0,1,0,0,1,0,1,0,0,0,0,1,1,0,0,0,0,1,1,0,0,0,1,1,0,1,0,1,1,1,1,0,1,1,1,1,1,0,1,1,0,1,1,0,0,1,0,0,1,0,1,1,0,1,0,0,1,0,0,0,0,0,1,1,0,1,0,1,0,1,0,0,1,0,1,0,0,1,0,1,0,1,1,1,1,0,1,0,0,1,1,1,1,1,0,1,0,1,0,1,1,1,0,1,1,1,1,1,1,0,1,1,0,1,1,0,0,1,0,0,0,0,0,0,0,1,1,1,0,1,0,1,0,0,1,0,1,0,1,1,1,1,0,0,0,0,0,1,0,1,0,1,0,1,0,1,0,1,0,0,1,1,1,1,0,0,1,0,1,0,0,1,0,1,1,1,0,0,1,0,0,0,0,1,0,1,0,1,0,1,1,1,1,1,0,0,1,0,1,0,1,1,1,0,1,1,0,1,0,1,1,1,1,0,1,0,1,0,0,1,1,1,1,1,1,1,1,1,0,0,1,1,0,1,1,0,1,1,0,0,1,0,0,1,0,0,1,1,0,1,1,0,0,1,1,0,1,0,0,1,1,1,1,0,1,1,0,0,0,0,1,1,0,1,1,0,0,1,0,0,0,1,1,1,1,0,0,1,1,1,1,1,0,0,0,1,1,1,1,0,1,1,0,1,1,0,1,0,1,0,0,0,0,0,1,1,1,1,1,0,1,1,0,1,1,0,1,1,1,0,0,0,1,1,1,0,0,0,1,0,0,0,0,1,1,0,1,1,1,1,0,1,0,1,0,1,0,1,0,0,1,1,0,1,1,0,0,0,1,1,0,0,1,1,1,0,1,1,1,1,0,0,1,1,1,1,1,1,1,0,0,0,0,0,0,0,0,0,0,0,0,0,1,1,0,1,0,1,1,1,0,1,0,0,1,0,0,0,1,0,1,0,0,0,1,0,1,0,1,1,0,0,0,1,1,0,0,0,1,1,1,0,1,0,0,0,1,1,1,1,1,1,1,1,1,0,0,1,1,1,1,1,0,1,0,1,1,0,0,1,1,0,1,0,0,0,0,0,0,0,0,0,0,1,0,0,0,0,0,1,0,1,0,1,1,1,0,0,0,1,1,0,1,0,1,0,1,1,0,0,0,0,1,1,1,1,1,0,0,0,1,1,0,1,0,0,0,0,0,0,0,1,0,1,0,1,0,0,0,0,1,1,1,1,1,0,1,0,0,0,0,1,0,0,1,1,1,1,0,0,1,1,1,0,1,1,1,1,1,0,0,0,0,0,1,1,0,1,1,1,0,0,0,0,1,0,1,0,0,0,0,0,1,1,1,0,1,1,0,1,1,1,1,0,1,0,0,0,0,0,0,1,1,0,1,1,1,1,1,1,0,1,0,1,1,1,1,1,1,0,1,0,1,0,1,0,1,1,1,0,0,0,0,1,0,0,0,1,1,1,0,1,1,0,0,1,0,0,1,1,0,1,0,0,1,1,1,1,0,0,1,0,0,1,1,1,0,1,1,1,0,1,1,0,1,0,1,0,1,0,1,1,0,1,1,1,1,1,1,0,0,1,0,1,1,1,1,0,1,1,0,0,0,1,1,0,0,0,1,0,0,1,1,1,1,0,0,0,0,1,0,0,1,1,0,0,1,0,1,0,0,0,1,0,0,0,0,1,1,1,0,1,1,0,1,0,0,0,0,1,1,1,1,1,1,1,0,0,0,1,0,0,0,1,1,0,1,0,1,1,1,0,1,0,0,1,1,1,1,1,0,0,0,0,1,1,1,1,0,0,0,1,0,0,1,0,1,1,0,1,1,1,0,1,0,0,1,0,1,0,1,1,1,0,0,1,1,0,0,0,1,1,1,1,0,0,0,1,1,0,1,1,0,0,1,1,0,1,0,1,1,0,0,1,0,0,0,0,0,0,1,1,1,0,1,0,1,1,1,1,1,1,0,0,0,1,1,1,1,1,0,0,0,0,0,0,1,0,0,1,0,1,0,0,1,0,0,0,1,1,0,1,1,0,0,1,1,0,0,0,0,1,1,1,0,1,0,1,1,0,1,1,1,1,1,1,1,0,1,0,1,1,1,1,1,1,1,1,0,1,1,1,0,0,1,0,1,1,1,0,1,1,1,0,0,1,0,1,0,0,0,0,0,0,1,1,0,1,1,0,1,1,1,1,0,0,0,0,1,1,0,1,1,1,1,1,1,0,1,0,0,1,1,0,1,1,1,0,1,0,0,1,0,0,1,0,1,0,1,1,1,1,0,1,1,1,0,0,1,1,1,0,0,0,1,0,0,1,0,0,0,0,0,0,1,0,0,1,0,0,1,0,0,1,1,1,1,1,0,1,1,0,1,0,0,0,1,1,0,0,0,0,0,1,1,0,1,0,0,0,0,0,0,0,1,1,0,1,0,0,1,1,0,0,1,1,0,0,0,1,0,0,0,1,0,0,0,1,1,0,1,1,1,1,1,0,1,1,1,1,0,0,0,0,0,1,0,1,0,0,1,1,1,0,0,1,0,1,0,0,1,0,1,0,0,0,1,0,0,1,0,0,0,1,1,0,1,1,1,1,1,1,1,0,1,1,1,0,1,0,1,0,0,1,0,1,1,1,1,0,0,0,0,1,0,1,1,0,0,0,1,0,1,0,1,0,0,0,0,1,0,0,0,0,0,1,0,1,0,1,0,1,0,1,0,1,1,1,0,1,0,1,0,0,1,1,0,0,1,0,1,0,1,0,0,1,0,0,1,0,0,1,0,0,0,1,0,1,1,1,1,0,0,0,0,0,1,1,1,1,1,1,1,0,1,1,1,1,1,0,0,1,1,0,1,0,0,0,1,1,1,0,1,0,1,0,0,1,0,0,1,0,0,1,1,0,0,0,0,1,1,0,0,1,1,1,1,0,1,1,0,0,0,1,0,0,0,0,0,0,1,1,1,0,1,0,1,1,1,1,1,1,1,0,1,0,1,0,0,0,0,1,1,0,1,0,0,0,0,1,1,1,1,0,1,1,1,1,0,0,1,1,1,0,0,1,1,0,0,1,1,0,0,0,1,0,1,0,1,0,1,0,1,0,0,1,1,1,1,1,1,1,0,0,0,1,1,1,0,1,1,1,1,1,1,0,0,1,1,1,1,1,0,0,0,0,1,1,0,1,1,1,0,0,0,1,1,0,0,0,1,1,0,1,0,1,0,1,1,0,0,0,1,0,0,0,1,1,0,0,1,1,0,0,0,1,1,0,0,1,0,1,1,1,1,1,0,0,0,0,0,1,1,1,0,0,0,1,1,1,0,0,1,1,0,1,0,1,0,0,1,1,0,1,1,0,0,0,0,0,0,1,1,1,0,1,1,1,1,1,1,0,1,1,1,0,1,1,1,0,0,1,0,0,0,1,1,0,1,1,1,1,1,1,1,0,0,0,1,1,1,0,0,0,0,0,1,0,0,0,1,1,0,1,1,0,1,0,0,0,0,1,1,1,0,0,1,1,1,1,0,0,1,0,1,0,1,0,1,0,1,0,1,0,1,0,1,1,1,0,1,0,0,0,1,1,0,1,1,0,1,0,1,1,1,0,0,0,1,1,0,0,1,0,0,0,0,1,1,1,1,1,0,1,1,1,1,1,0,1,1,1,1,0,1,0,1,0,1,1,1,1,0,0,0,1,0,0,1,1,0,0,0,0,1,1,0,0,0,0,0,1,0,0,0,1,0,0,1,1,1,1,0,1,1,1,0,1,0,0,1,0,1,1,0,1,0,0,0,1,0,0,0,1,0,1,1,0,0,1,0,1,1,0,0,0,1,0,1,1,0,0,0,1,0,1,1,0,0,1,1,1,1,1,1,0,0,1,1,0,1,0,1,0,1,0,1,1,0,0,1,1,1,1,0,0,1,0,1,0,1,1,0,0,1,0,1,0,0,0,1,0,0,1,1,0,1,1,0,0,0,0,1,1,1,1,1,1,0,1,0,0,0,1,0,0,1,1,1,1,1,0,0,0,0,0,0,1,1,0,0,0,1,0,0,0,0,0,0,1,1,0,0,0,0,0,0,0,0,1,0,1,1,1,1,0,1,1,1,0,1,1,0,0,0,1,0,0,1,0,0,1,0,1,0,0,1,1,0,1,0,0,1,0,1,1,1,1,0,1,0,1,0,0,1,0,0,1,0,1,1,1,0,0,1,1,0,1,0,0,0,1,1,0,1,0,1,1,1,0,1,0,1,1,1,0,1,0,1,0,0,1,1,1,1,0,0,0,1,0,0,0,1,1,1,0,1,1,0,0,0,0,0,1,0,1,1,0,1,0,0,1,1,1,0,1,0,0,1,0,0,0,1,0,0,0,1,0,1,0,0 };

	xP(0, 1) = { 0,1,0,1,0,1,1,1,0,0,0,0,1,0,1,0,0,1,0,0,1,0,1,1,0,1,0,1,0,0,1,0,0,0,1,1,1,1,1,0,0,0,1,0,0,0,1,1,1,0,1,0,1,1,1,0,1,0,1,1,1,1,0,1,0,1,1,1,1,1,0,1,1,0,0,1,1,1,1,0,1,1,1,1,0,0,0,1,0,1,1,1,1,0,1,1,1,1,1,0,1,1,0,0,0,1,1,0,0,1,1,1,0,1,1,1,1,0,1,1,1,1,1,1,1,0,0,1,0,1,0,1,1,1,0,0,1,0,0,1,0,1,1,1,1,0,1,0,0,0,0,0,0,1,1,1,1,0,1,0,1,1,1,1,1,1,0,0,0,0,0,1,0,1,0,1,0,0,0,1,1,0,0,0,1,0,1,1,1,1,1,1,0,0,1,1,1,1,0,1,0,1,0,1,1,0,1,0,0,1,0,1,1,0,1,0,0,0,0,1,1,1,1,0,1,1,0,0,0,1,1,1,0,0,1,1,1,1,0,1,0,0,1,0,1,0,0,1,0,0,0,1,0,0,1,1,0,0,0,0,0,1,1,0,1,0,0,1,1,1,1,0,1,0,0,1,0,0,1,1,0,1,1,1,0,1,0,1,0,1,0,1,1,0,1,0,0,0,1,0,1,0,1,1,1,0,1,1,0,0,1,1,1,1,0,1,0,1,1,0,0,0,1,0,0,1,0,0,1,1,0,0,1,1,1,1,1,0,0,1,1,1,0,1,1,0,1,1,1,0,0,1,1,0,0,0,0,0,1,0,0,0,1,1,0,0,1,1,0,0,1,0,1,1,1,1,1,0,1,1,0,1,0,1,1,0,0,0,1,1,1,0,0,0,1,0,0,0,1,0,1,0,0,0,0,0,1,1,1,0,1,0,1,1,1,1,0,1,1,0,0,0,0,1,1,1,1,0,0,0,0,0,0,0,0,0,1,1,1,0,1,0,1,0,1,0,0,0,1,0,0,1,1,1,1,0,0,0,1,1,0,0,1,1,1,0,0,1,1,1,1,0,1,1,0,0,0,1,0,1,0,1,0,0,1,0,1,0,0,0,1,0,1,0,1,0,0,0,1,0,0,0,1,1,0,1,0,0,1,0,1,1,0,0,1,1,1,0,1,1,0,0,0,1,1,1,1,1,1,0,0,0,0,1,0,0,1,0,0,0,0,1,1,0,0,1,1,0,1,1,0,0,0,1,0,0,0,1,0,1,0,1,0,0,1,0,0,1,1,1,0,0,0,0,1,0,1,0,0,0,1,1,0,0,1,0,1,0,1,1,0,1,1,0,1,0,0,0,0,0,1,1,0,0,0,1,0,0,1,0,1,0,0,0,1,0,1,0,0,1,0,1,0,1,1,0,1,1,0,0,0,0,0,1,1,1,0,1,0,1,0,1,1,0,1,1,0,0,1,1,1,0,0,0,0,0,1,1,0,0,0,1,0,1,0,0,1,1,0,1,0,0,0,1,0,1,0,1,1,1,1,0,0,0,0,1,0,1,1,1,1,1,0,1,1,1,1,0,1,1,1,0,1,0,1,1,1,1,0,0,1,0,1,0,1,0,0,1,1,0,0,0,1,1,0,0,0,0,1,0,0,1,1,0,1,0,0,1,0,1,1,1,1,1,1,1,1,1,0,0,1,0,0,1,0,1,1,1,0,0,0,1,0,0,0,0,0,1,0,1,1,0,0,0,0,1,0,0,1,0,1,0,0,0,0,0,1,1,1,1,1,1,1,1,0,1,1,1,0,0,0,0,1,1,1,0,1,1,0,1,0,1,1,1,1,1,1,0,0,1,1,1,0,1,1,1,0,1,0,0,0,1,0,1,1,0,0,0,0,0,1,1,0,0,1,1,0,0,1,0,1,0,0,1,0,0,0,0,0,1,1,1,0,0,1,1,0,0,0,1,1,1,0,1,0,1,0,0,0,0,1,1,1,0,0,0,0,0,1,0,1,1,1,1,1,1,1,1,1,0,0,1,1,1,0,1,1,0,0,1,1,1,0,0,0,0,1,1,0,0,1,0,0,0,0,0,0,0,0,1,1,0,0,0,0,0,0,1,1,0,1,0,1,0,1,0,1,1,1,0,1,0,0,0,0,0,0,1,1,1,0,1,0,1,1,0,1,1,0,1,1,1,0,1,1,0,0,0,1,1,1,1,1,0,0,1,1,0,1,0,0,1,0,1,0,0,1,0,1,0,0,1,1,0,0,0,1,0,1,0,0,1,1,1,1,0,1,1,1,0,1,0,0,0,0,1,1,0,0,1,1,1,0,1,1,0,1,0,0,1,1,0,1,0,0,1,0,1,0,0,0,1,1,1,0,0,1,1,0,0,1,1,0,1,0,1,1,1,0,0,0,0,0,1,1,0,0,0,1,1,1,0,1,0,0,1,0,1,1,1,1,1,1,0,1,0,0,1,1,1,1,0,0,1,0,0,1,0,1,0,1,1,0,0,1,0,1,1,1,1,0,0,0,1,0,1,0,1,1,0,1,0,1,0,0,1,1,1,0,0,1,0,0,1,1,1,0,0,0,1,0,0,1,0,0,1,1,1,0,0,0,0,0,0,1,0,1,0,0,0,0,0,0,1,1,1,0,1,0,1,0,1,1,1,0,0,1,1,0,0,1,0,1,0,1,1,1,0,1,0,0,1,1,1,0,0,1,1,1,0,0,0,0,1,1,1,1,1,1,0,0,1,1,1,1,1,1,0,0,0,1,0,0,0,0,0,1,1,1,1,0,0,1,0,1,0,0,0,1,0,1,0,1,0,0,1,1,1,1,1,0,0,1,1,1,1,1,1,0,1,0,1,1,1,1,0,0,1,1,1,1,1,1,1,1,1,1,1,1,1,1,0,1,1,1,1,0,1,1,0,1,1,1,1,0,1,1,0,1,0,1,1,1,1,1,0,0,1,1,1,1,1,0,1,0,0,0,1,1,1,1,1,1,0,1,1,0,1,1,1,0,1,0,0,0,0,1,0,0,1,1,0,0,0,1,1,0,0,1,1,1,1,0,0,0,0,1,0,0,0,1,1,0,1,1,0,0,1,1,1,0,1,0,0,0,0,0,1,0,0,0,1,1,0,1,1,1,0,1,1,0,0,1,0,1,0,1,1,1,1,0,0,0,0,0,0,0,0,0,0,0,1,0,1,0,0,0,1,1,0,0,1,1,1,0,0,1,0,1,0,0,1,1,1,0,1,0,0,1,1,1,1,0,0,0,1,1,0,1,1,0,0,0,1,1,0,0,0,1,0,1,0,1,0,0,1,1,0,1,0,0,0,0,0,0,0,1,0,0,0,1,1,1,1,0,1,0,0,1,1,1,1,0,1,0,0,1,0,0,1,0,0,0,0,0,0,1,0,1,0,1,1,1,1,1,1,0,1,0,1,0,1,1,0,0,0,0,1,1,1,0,1,1,1,1,0,0,0,1,0,0,0,1,0,1,1,1,1,0,1,1,0,1,1,0,0,1,0,1,0,1,0,0,0,1,0,1,0,0,0,1,0,0,1,0,1,0,0,1,1,0,0,0,0,0,1,0,0,1,1,1,0,0,0,1,0,0,0,0,0,0,1,0,0,0,0,0,1,0,1,0,1,1,0,0,0,1,1,1,1,1,1,0,1,0,1,1,0,0,0,0,1,0,0,0,1,0,1,1,0,1,1,0,1,0,1,1,0,0,1,0,1,1,0,1,0,1,1,1,1,1,0,0,0,0,0,0,1,1,0,1,0,0,0,0,0,1,0,0,1,1,1,1,1,0,1,0,0,1,1,1,1,0,1,0,0,0,0,0,0,1,0,0,1,0,1,1,1,0,0,1,1,0,0,0,0,0,1,0,1,0,1,0,0,1,0,0,1,0,1,1,0,1,0,1,0,0,0,1,0,0,1,1,1,0,0,0,1,1,1,1,0,1,0,1,0,0,1,0,0,0,0,1,0,1,0,0,1,1,0,1,1,1,1,0,1,0,0,0,0,0,1,1,1,0,1,1,1,0,1,1,0,1,0,0,1,1,1,0,1,1,1,1,0,0,0,0,0,1,1,1,0,0,1,1,1,0,1,1,1,0,0,0,0,0,1,0,1,0,1,0,0,1,0,1,0,0,1,1,0,0,1,1,0,0,0,1,0,0,1,0,1,1,1,0,0,0,0,1,1,0,1,1,1,1,0,1,1,1,1,0,1,0,0,1,1,0,0,0,1,1,0,0,1,0,1,0,1,0,0,0,0,1,1,1,0,1,1,1,0,0,0,1,0,0,0,1,1,0,1,1,0,0,1,0,0,0,1,1,0,1,0,1,1,1,1,1,0,1,0,1,1,1,1,0,1,0,1,0,0,1,1,1,0,1,0,1,1,1,0,1,1,0,0,1,1,0,0,1,1,0,0,1,0,1,1,0,1,0,0,0,1,0,0,1,0,1,0,1,0,0,0,1,1,0,1,0,1,1,0,0,1,0,1,1,0,0,0,1,1,0,1,0,1,0,0,1,1,1,0,0,0,1,1,0,0,1,0,1,1,0,0,0,1,0,0,1,1,0,1,0,0,0,1,0,1,0,1,1,1,0,0,0,1,0,1,1,1,0,1,1,0,0,0,1,0,1,0,1,0,1,1,0,0,1,1,1,1,0,0,1,1,0,0,1,1,1,1,0,0,0,0,1,0,0,0,0,1,0,0,1,1,0,0,1,0,1,1,0,1,1,1,1,1,0,0,0,0,0,0,0,0,1,0,1,1,0,1,0,0,1,1,0,0,1,1,1,0,1,0,0,0,0,1,0,1,1,1,1,0,1,0,0,1,0,0,1,0,1,0,0,1,1,1,1,0,1,0,0,1,1,1,0,1,0,0,0,1,0,1,0,1,1,0,0,0,0,0,1,0,1,0,1,0,1,1,0,1,0,1,1,0,1,0,0,1,1,1,1,0,0,0,0,0,0,0,1,1,0,0,0,0,0,0,1,1,0,1,0,0,1,1,1,1,1,0,0,0,1,0,0,1,0,0,0,1,1,0,1,0,0,0,1,0,0,1,0,1,0,1,0,1,0,0,0,0,1,1,1,0,1,1,1,0,1,0,1,0,1,1,1,1,0,0,0,0,1,0,0,1,1,0,0,0,1,0,0,1,1,0,1,1,1,0,0,1,1,1,0,1,1,1,0,0,1,1,0,0,0,0,0,1,0,0,1,0,0,0,0,0,0,1,1,0,1,0,1,1,0,1,0,1,1,0,0,0,0,0,1,0,0,1,0,0,0,1,1,0,1,0,1,1,1,1,1,1,0,1,1,0,1,1,0,0,0,1,0,0,0,1,0,0,0,0,1,1,1,0,0,0,1,0,0,0,0,1,0,0,0,0,1,0,0,1,0,0,1,1,0,0,0,1,1,1,0,1,0,1,0,1,0,1,1,0,0,0,1,1,0,1,1,1,1,1,0,1,0,1,0,1,1,0,1,1,0,0,0,1,1,0,0,0,0,1,0,1,0,0,1,0,1,1,1,1,1,0,0,1,1,1,0,0,0,0,1,1,0,0,0,1,1,0,1,0,1,1,1,0,0,1,0,1,1,0,0,1,1,1,1,1,0,0,1,1,1,0,0,1,1,1,0,1,0,0,1,0,0,0,1,0,0,1,0,1,1,0,1,0,0,0,0,1,0,1,1,1,0,0,0,0,1,0,0,1,1,1,1,0,1,0,0,1,1,0,0,1,1,0,1,1,1,1,0,0,1,0,1,0,1,1,1,0,0,1,1,0,0,0,0,0,0,0,0,1,0,1,1,0,1,1,0,0,0,0,0,0,1,1,0,0,0,0,1,0,1,0,0,0,1,1,1,1,1,1,0,1,1,1,0,1,1,1,0,0,1,1,1,1,1,1,1,1,1,0,1,1,0,1,0,0,1,1,0,1,0,1,1,1,1,0,0,0,1,1,0,0,0,0,1,1,1,0,0,0,1,1,0,0,0,0,1,0,0,1,1,1,1,0,0,1,1,1,0,0,1,1,0,0,0,1,1,0,1,0,0,0,1,1,1,1,0,1,0,1,1,0,1,1,1,0,0,0,1,1,0,0,1,1,1,1,0,1,1,0,1,0,1,0,1,1,0,0,0,1,0,1,0,0,1,1,0,1,1,1,1,1,1,0,1,0,1,0,1,0,1,0,1,0,0,1,1,0,1,0,1,0,0,0,1,0,1,1,0,0,0,1,0,0,1,1,0,0,0,0,0,0,0,1,1,0,1,0,1,0,1,1,0,1,0,1,1,1,1,1,1,0,0,0,0,1,0,0,0,0,1,1,0,0,1,0,1,0,0,1,0,0,0,1,0,0,1,0,1,1,0,0,1,1,0,1,1,0,0,1,0,1,1,1,0,0,0,0,1,1,1,1,0,0,1,1,0,0,1,1,1,1,0,1,0,0,0,0,1,1,1,1,0,1,0,1,1,1,0,1,1,0,1,1,0,0,0,1,1,0,1,1,1,1,1,0,1,1,1,0,1,0,1,0,0,1,0,1,1,1,0,0,0,1,0,0,0,0,1,1,1,1,0,1,1,0,1,1,0,0,0,1,1,0,1,0,0,1,0,1,0,1,1,1,0,1,0,1,1,0,1,1,0,0,0,0,1,1,0,1,0,1,1,1,0,1,1,1,1,0,1,0,0,1,0,1,1,0,1,1,0,1,1,0,0,0,0,0,0,1,0,1,1,1,0,1,1,0,1,1,0,1,1,1,0,0,1,1,1,1,1,0,0,0,0,0,1,1,1,1,1,0,0,1,0,0,1,1,0,1,0,1,1,0,0,0,0,0,0,1,1,0,0,1,0,0,1,1,0,0,1,0,0,0,0,1,0,0,1,0,0,1,0,0,1,1,1,0,0,1,0,0,0,1,0,1,1,0,1,1,0,1,0,1,0,0,0,0,1,0,1,0,0,0,0,1,1,1,0,0,1,0,1,0,1,1,0,1,1,1,1,0,0,1,0,0,0,0,1,1,1,1,1,0,0,1,0,0,0,1,1,1,0,0,0,0,1,0,1,0,1,1,0,1,0,0,1,1,0,1,1,0,1,0,0,0,0,0,0,0,0,0,0,1,1,0,1,1,1,0,1,0,1,0,0,0,0,1,0,1,0,0,0,0,0,1,1,0,1,0,0,1,1,0,1,1,1,1,0,0,1,1,0,0,0,1,0,1,0,1,0,0,1,0,1,0,0,0,0,1,0,1,1,1,0,0,1,0,0,0,1,1,1,0,1,1,1,0,0,0,1,1,1,1,1,0,0,1,0,0,0,1,1,1,0,1,0,0,0,1,0,0,1,1,1,1,0,1,0,1,1,0,0,1,1,1,0,0,0,0,0,0,1,1,1,1,1,1,0,0,1,1,1,1,1,1,0,1,1,0,0,0,0,1,0,0,1,1,0,0,0,0,1,1,0,0,1,0,0,0,1,1,1,0,0,0,1,1,1,1,1,0,1,1,1,0,1,1,0,0,0,1,1,0,1,0,1,0,0,0,0,0,1,0,0,0,1,1,1,0,0,1,0,1,1,0,1,0,0,0,0,0,1,0,1,0,1,0,0,0,1,1,0,1,1,1,0,0,1,1,0,1,0,0,1,1,1,0,1,1,1,0,1,0,0,0,1,0,1,1,1,1,0,1,0,1,0,1,0,1,1,0,1,1,1,0,1,0,1,1,1,1,0,0,0,1,0,1,0,1,1,1,1,0,1,1,1,0,0,0,1,0,0,1,1,1,1,0,1,1,1,1,0,0,1,0,0,1,1,0,0,1,0,0,1,0,0,1,1,0,1,1,0,1,0,0,0,0,0,0,1,0,1,1,1,1,1,1,1,0,0,0,0,1,0,1,0,1,1,1,0,1,1,0,0,1,0,1,0,0,0,1,1,1,1,0,1,1,1,1,0,0,1,0,1,1,1,0,0,0,1,0,0,0,0,1,1,1,1,0,1,1,0,1,0,0,0,1,1,0,1,0,1,0,1,1,1,0,1,1,1,0,0,1,0,0,0,1,1,1,1,0,1,1,1,0,1,1,0,1,1,0,0,1,0,1,0,1,0,0,1,0,0,1,0,1,1,0,0,1,1,0,0,0,1,1,0,1,1,1,0,1,0,1,0,0,0,0,1,0,1,0,1,0,1,1,0,1,1,1,0,0,0,1,0,1,0,1,1,0,1,1,0,0,0,0,0,1,0,1,1,0,0,0,0,0,0,0,1,0,1,0,1,0,0,1,1,1,0,0,1,0,0,1,1,1,0,0,1,1,0,0,0,1,1,0,0,0,1,0,0,0,1,1,0,0,1,1,1,0,1,0,1,1,0,1,0,1,1,0,1,0,1,0,0,0,0,0,0,1,1,1,1,1,0,1,0,1,0,1,1,1,0,0,1,1,1,0,1,0,0,0,1,0,1,1,0,0,0,1,1,0,0,0,1,1,1,1,1,1,1,0,0,0,1,0,1,0,1,1,0,1,1,0,1,1,0,1,1,1,1,1,0,1,0,0,0,1,0,0,0,0,0,0,1,0,1,1,0,0,1,1,0,0,0,1,1,0,0,0,1,1,0,0,0,0,0,1,1,1,0,1,0,1,1,0,1,1,0,0,1,0,0,0,0,0,0,1,0,0,1,0,1,0,0,0,0,1,0,0,1,0,1,1,1,1,1,0,0,0,1,1,0,1,0,0,0,1,1,1,1,1,1,1,0,1,0,0,1,1,0,1,1,1,0,0,1,1,1,1,1,0,1,0,1,1,0,0,0,1,0,1,0,1,0,1,1,1,1,1,0,1,1,1,1,0,1,0,0,1,0,1,0,1,0,0,1,1,0,0,1,1,0,1,1,1,1,0,1,1,0,1,0,1,1,1,1,1,0,0,1,1,0,0,1,0,1,0,0,1,0,1,1,1,1,1,0,0,1,1,1,1,0,1,0,0,1,1,1,1,0,1,1,0,1,1,0,1,0,0,0,0,1,0,0,0,1,1,1,1,0,1,1,0,0,1,0,0,0,1,0,1,1,0,0,0,1,0,0,1,0,1,1,0,0,0,0,1,0,1,0,0,1,1,1,1,1,1,1,1,0,1,1,0,1,1,0,0,1,0,1,1,0,0,1,0,0,1,0,1,1,0,0,1,0,0,0,1,0,0,1,0,0,1,0,0,0,0,0,0,0,0 };

	//std::cout << "Input array X0 \n\t" << xP(0, 0) << std::endl;
	//std::cout << "Input array X1 \n\t" << xP(0, 1) << std::endl;

	Matrix<PackedIntPlaintextEncoding> yP = Matrix<PackedIntPlaintextEncoding>(zeroAlloc, 2, 1);

	yP(0, 0) = { 1,0,1,0,1,0,1,1,0,1,1,0,0,1,1,0,0,0,1,1,0,0,0,0,0,0,1,1,1,0,1,0,1,1,0,1,0,0,0,1,0,1,1,0,0,0,0,1,0,1,0,0,0,0,0,1,1,0,0,0,0,0,0,0,1,0,1,1,0,1,1,1,0,0,1,1,1,0,0,0,1,1,0,1,1,0,1,0,0,1,1,1,1,1,1,1,1,1,0,1,1,0,0,0,0,0,0,0,1,1,1,1,0,0,1,0,0,0,0,0,1,0,1,0,1,0,0,0,1,0,1,1,1,1,1,0,1,0,0,0,1,1,1,0,0,0,0,0,0,0,1,1,0,1,1,0,1,1,0,0,1,0,1,0,1,0,0,0,1,1,0,0,0,0,0,1,1,1,1,0,0,0,0,1,0,1,0,1,0,0,0,0,1,0,0,1,0,0,0,1,0,1,1,1,0,1,1,0,1,0,1,1,1,0,1,1,0,0,1,0,0,1,0,1,0,0,1,1,1,1,0,0,0,0,1,1,0,0,1,1,1,1,0,0,1,0,0,0,0,1,1,1,0,1,0,0,1,0,1,0,0,0,1,0,0,0,0,1,1,0,0,1,0,0,1,0,1,0,1,0,0,1,0,1,0,1,1,0,0,0,1,0,0,0,0,0,1,0,1,0,1,1,1,1,0,1,1,0,0,0,1,1,1,1,0,1,0,0,1,0,0,1,0,1,0,0,1,0,0,1,1,0,1,1,0,1,1,0,0,1,0,1,1,0,0,0,0,0,1,0,1,0,1,0,0,1,1,1,0,0,1,0,0,0,0,0,1,0,0,1,0,1,1,0,0,1,0,0,1,0,0,1,0,1,0,0,1,0,0,1,0,0,0,1,1,1,0,0,1,0,0,0,1,0,1,1,1,1,0,0,1,1,0,0,1,0,1,0,0,1,1,1,0,0,0,0,0,0,1,1,1,0,0,0,1,1,0,0,0,0,0,0,0,1,0,0,1,0,0,0,1,0,1,0,0,0,1,0,1,1,1,1,0,0,1,1,1,1,1,1,0,1,0,0,0,1,1,1,1,0,1,0,1,1,0,0,1,1,0,1,1,0,1,0,0,0,1,0,1,1,1,0,1,1,0,1,0,0,1,1,0,0,0,0,1,0,0,0,1,1,0,1,1,1,0,0,1,1,0,0,0,0,0,0,0,1,1,1,1,1,0,0,0,1,1,0,0,1,1,0,0,1,1,1,0,1,0,1,1,0,1,0,0,0,1,0,1,1,1,0,1,1,1,1,1,1,0,1,1,1,1,1,0,0,1,1,1,0,0,1,1,1,0,1,0,1,0,1,0,0,1,0,0,1,1,0,0,1,0,0,1,1,1,0,0,1,0,0,1,1,1,1,1,0,0,0,1,1,0,0,0,1,1,0,0,0,0,0,0,1,1,1,0,1,0,0,1,1,0,1,0,1,1,1,0,0,1,0,1,0,1,0,1,0,1,0,1,0,1,1,0,0,1,0,1,1,1,0,0,1,0,1,1,0,0,0,1,1,0,1,1,1,0,1,0,0,0,0,0,1,1,0,0,0,1,0,1,0,0,1,1,0,1,0,1,0,1,1,1,0,0,1,1,1,0,1,0,0,0,1,1,0,1,0,0,0,0,1,1,0,0,1,0,1,0,0,1,0,1,0,1,1,1,1,1,1,1,1,1,1,1,1,0,0,1,0,0,1,1,0,0,1,1,1,0,0,0,1,1,0,1,1,0,1,0,1,1,1,1,1,0,1,0,1,1,0,1,1,0,1,0,0,0,1,1,1,0,1,0,1,0,1,1,0,1,1,0,0,0,1,0,0,0,0,0,1,1,0,1,0,0,1,0,0,1,1,0,0,0,1,0,1,0,0,0,0,0,1,1,1,0,1,1,0,0,0,0,1,0,1,1,1,1,1,0,1,1,1,1,0,0,0,1,0,0,1,0,1,1,1,0,1,0,0,0,0,1,1,1,0,0,0,0,1,0,0,1,1,0,0,0,0,0,0,1,1,0,0,1,1,1,0,1,1,0,1,1,0,0,1,1,0,1,0,1,1,1,1,1,0,1,0,1,1,1,0,0,0,1,1,0,1,0,1,1,1,1,0,1,0,0,1,0,0,0,0,0,1,1,1,1,0,0,1,1,1,1,1,0,0,1,1,1,0,0,1,0,1,0,0,0,0,1,0,0,0,0,0,1,0,1,0,0,0,0,0,0,1,1,0,0,1,0,0,1,0,0,1,1,0,0,1,1,1,1,1,0,1,1,1,0,0,1,1,0,0,0,0,0,0,0,1,1,1,0,0,1,1,1,0,1,0,0,1,0,0,0,0,1,1,0,0,0,0,0,0,0,0,0,1,1,0,1,1,1,1,0,0,0,1,1,1,1,0,0,0,0,1,1,1,0,1,1,1,1,1,1,1,0,0,0,1,0,0,1,0,0,1,0,1,1,1,0,1,0,0,0,1,0,1,1,1,1,1,0,1,1,1,0,0,1,1,1,0,0,0,1,0,1,1,1,1,0,1,0,0,1,0,0,1,0,0,1,1,0,1,0,0,0,1,0,0,0,0,1,0,1,0,0,1,1,0,0,1,1,0,0,1,0,0,1,0,0,0,0,1,1,0,0,0,1,1,1,1,1,0,0,1,0,1,0,1,0,1,1,0,1,1,0,1,1,0,1,0,1,0,0,1,1,0,1,0,1,0,0,0,1,0,0,1,0,0,1,1,0,1,1,0,0,0,0,0,1,0,0,0,1,1,1,1,0,1,0,1,1,0,0,0,1,0,1,1,1,0,0,0,0,1,1,0,0,0,0,1,1,0,1,1,1,1,0,0,0,1,0,0,1,0,1,1,1,0,1,1,0,1,1,1,1,1,1,0,0,0,0,0,1,0,0,0,0,1,0,0,1,0,0,0,0,1,1,0,0,1,0,0,0,0,1,1,1,1,0,1,1,1,0,1,0,1,0,1,0,0,1,0,1,0,1,0,1,1,1,0,1,1,1,0,1,1,0,1,0,1,1,0,0,0,1,1,1,1,1,1,1,1,1,0,0,0,0,0,1,0,1,1,1,0,0,0,0,0,0,1,1,0,0,0,0,1,1,1,1,1,0,1,1,0,0,0,0,1,1,1,1,0,1,1,0,0,0,0,1,1,0,1,0,1,0,0,1,1,0,1,1,0,1,0,1,0,0,0,0,1,0,1,1,1,1,1,1,1,1,0,1,0,0,1,0,0,0,1,1,1,1,0,0,1,0,0,0,0,1,0,0,1,1,1,0,1,0,1,0,1,1,1,1,1,0,0,1,0,0,0,0,0,0,1,1,0,1,1,0,0,0,0,0,1,1,1,1,1,0,0,1,0,1,0,0,1,1,0,0,1,0,1,1,1,0,0,1,0,1,0,0,1,1,1,1,1,1,1,1,0,0,0,0,0,1,0,0,1,0,1,1,1,1,0,1,0,0,0,0,0,1,1,0,1,0,0,0,0,0,1,1,1,1,0,1,1,0,0,1,0,1,0,0,0,0,1,0,1,1,0,1,0,1,0,1,0,1,1,1,0,1,0,0,0,0,1,1,0,0,1,0,0,1,1,1,0,1,1,0,0,1,0,1,1,1,0,0,1,0,1,1,1,1,1,1,0,0,1,0,0,0,0,1,0,0,1,0,1,0,1,0,0,1,1,0,1,0,0,1,1,0,0,0,0,0,0,1,1,1,0,0,1,1,0,1,0,0,0,0,1,1,0,0,0,0,0,1,1,1,0,0,0,0,1,1,0,1,0,0,0,1,0,0,1,0,1,1,0,0,0,1,1,0,0,1,0,0,0,1,0,1,1,0,1,0,1,0,0,1,0,0,0,0,0,1,1,1,0,1,1,1,0,1,0,0,1,0,1,0,1,0,1,0,0,0,0,0,0,0,0,1,1,1,1,1,0,0,1,0,1,1,1,0,1,1,1,0,0,0,0,1,1,0,0,0,1,0,0,1,0,0,0,0,1,0,0,0,0,1,0,1,0,1,1,0,1,0,0,1,1,0,0,1,0,0,1,0,0,1,0,1,1,0,1,1,1,0,1,1,1,0,1,1,1,0,0,1,1,1,1,1,1,0,1,1,1,1,0,0,1,0,1,0,1,1,1,1,0,0,1,1,1,0,1,0,1,0,1,1,1,1,1,0,0,1,1,0,0,1,1,0,0,0,0,1,1,1,0,0,0,1,1,0,1,0,1,0,0,1,0,0,0,0,1,1,0,0,1,0,1,0,1,0,1,1,1,0,1,0,0,0,1,0,0,0,0,1,0,0,1,1,0,1,1,0,0,1,1,0,0,0,0,1,0,0,1,0,0,1,1,1,1,0,0,1,0,1,0,0,1,0,0,0,1,0,1,1,1,1,0,0,0,1,1,1,1,1,0,1,1,1,0,0,0,0,0,0,0,0,1,0,0,1,0,0,0,0,0,1,1,1,0,1,1,0,1,1,1,0,1,1,0,1,1,0,1,0,0,1,1,1,1,1,1,0,1,0,0,1,0,1,0,1,0,0,1,1,0,1,1,1,1,1,1,1,0,0,1,1,0,1,0,1,0,0,0,0,1,0,1,0,0,1,0,0,0,1,1,0,1,1,0,0,1,1,0,1,0,0,1,1,1,1,1,0,0,1,0,1,1,1,1,1,1,0,0,1,1,0,1,0,1,1,0,0,1,1,1,1,0,0,1,0,1,1,0,1,0,0,1,0,0,1,0,0,1,1,1,1,0,1,0,0,1,0,1,1,0,0,1,0,0,1,1,1,1,0,1,0,0,1,0,0,1,1,0,0,0,0,1,0,1,0,1,1,0,0,1,1,0,1,1,0,1,1,1,0,0,0,0,1,0,0,1,1,0,0,1,0,0,1,0,0,0,0,0,1,1,1,1,1,0,1,0,0,1,1,0,0,1,0,1,1,0,0,0,0,1,1,1,0,1,0,1,1,0,1,0,1,1,0,0,1,1,0,1,1,1,1,1,1,1,0,1,1,0,1,0,0,0,1,1,0,0,1,0,0,1,1,0,0,0,1,1,1,0,1,0,1,0,1,0,1,0,0,0,0,0,0,0,0,1,0,0,0,0,0,0,1,1,1,0,1,0,0,1,0,1,1,0,1,0,0,1,0,1,1,0,1,0,0,1,1,0,0,0,0,0,0,1,0,1,0,1,1,1,0,0,0,0,0,0,1,1,1,1,0,1,1,1,1,1,0,1,1,0,1,1,0,1,1,1,0,0,0,1,0,0,0,0,0,0,0,1,1,1,1,1,0,0,1,0,0,1,1,0,0,1,1,0,0,0,1,0,0,1,1,1,0,1,1,1,0,0,0,0,0,1,0,0,1,1,1,0,0,1,0,0,1,1,0,1,1,0,0,0,0,1,1,1,1,0,0,1,0,0,0,0,1,0,1,1,1,1,1,1,0,1,1,0,1,0,0,0,1,1,0,0,1,0,0,1,1,0,1,0,0,0,0,1,0,1,0,0,1,1,0,1,1,1,0,1,1,1,0,0,1,1,1,1,1,1,1,1,1,0,1,1,0,1,0,1,1,0,1,1,0,0,1,1,1,0,0,1,1,0,0,1,0,1,0,1,1,0,1,1,1,1,1,1,0,1,1,0,0,0,1,1,0,0,1,0,0,1,0,1,0,0,0,0,1,1,1,1,0,0,1,1,0,1,0,1,0,0,0,1,1,0,1,1,0,0,1,0,0,1,0,1,0,1,1,1,1,0,1,1,0,1,0,0,1,0,0,0,1,0,1,1,1,1,1,0,1,0,0,1,0,0,1,0,0,0,0,1,1,0,0,1,0,1,0,1,1,0,0,0,1,1,0,1,0,0,0,1,1,0,1,0,1,1,1,1,1,1,0,0,0,0,0,0,1,1,1,1,1,1,0,0,1,0,0,0,1,0,1,1,1,0,0,0,1,1,1,1,1,1,0,0,0,1,0,0,1,1,0,1,0,0,0,0,0,1,1,0,1,0,1,1,0,1,1,1,0,0,0,1,1,0,1,1,1,0,0,1,0,1,1,1,1,0,1,0,0,1,0,0,0,1,1,1,0,1,0,0,1,1,1,0,1,1,1,1,0,1,0,0,1,0,1,0,1,0,0,0,0,1,0,0,0,1,0,1,0,1,0,0,0,1,0,0,0,0,0,1,1,0,1,0,1,1,0,1,0,0,0,1,0,0,1,1,1,0,1,0,1,1,0,0,1,1,1,0,0,1,1,1,0,1,0,1,1,1,0,0,1,0,1,1,1,1,0,0,1,0,1,0,0,1,1,0,1,1,0,0,0,1,1,1,0,0,1,1,1,0,1,0,0,0,0,1,0,0,0,1,1,0,0,1,1,0,0,0,0,0,0,1,0,1,1,1,0,0,1,0,0,0,0,1,1,1,1,1,0,1,1,1,0,1,0,0,0,1,0,1,1,1,0,1,0,1,1,0,1,1,0,0,0,1,1,0,0,1,1,1,1,1,0,0,1,1,1,0,0,0,1,0,0,0,0,1,0,0,1,0,1,1,1,1,0,1,1,1,0,1,1,0,0,1,1,1,1,0,1,0,0,0,1,0,0,1,0,0,1,1,1,1,0,0,1,0,1,0,0,0,1,0,1,1,0,1,0,1,0,0,0,1,0,0,1,0,1,0,0,1,1,1,0,1,1,1,1,0,1,0,1,1,0,0,1,1,1,0,1,1,0,0,0,0,1,0,1,1,0,1,0,1,1,1,1,0,0,0,1,0,1,0,0,1,0,1,0,0,1,1,0,1,1,1,0,0,0,0,1,1,1,1,0,1,0,0,0,0,0,1,0,1,0,1,0,1,0,0,0,1,1,1,1,1,0,0,1,0,1,1,0,0,1,1,1,1,1,0,1,1,1,0,0,0,0,1,0,0,1,0,1,0,0,0,0,1,1,1,0,1,1,1,1,0,0,1,0,1,0,1,0,0,1,0,0,1,1,0,0,0,1,0,0,1,0,1,1,0,1,1,0,1,1,0,1,0,0,1,1,0,1,1,1,0,0,1,0,1,1,0,1,0,0,0,0,0,0,0,0,0,1,1,0,0,0,1,1,0,1,0,0,0,1,1,1,1,1,1,1,1,1,1,1,0,0,1,1,0,0,0,0,1,1,1,0,1,1,1,1,0,0,1,1,1,0,1,1,0,0,1,0,1,0,1,1,1,0,1,0,0,0,0,0,1,0,0,0,1,1,1,0,0,0,0,1,1,1,0,1,0,0,0,1,1,0,0,1,0,1,1,0,1,0,0,0,1,1,1,0,0,0,0,0,1,0,1,1,0,0,1,1,1,1,0,0,1,0,1,1,1,1,0,0,0,0,0,0,0,1,0,1,0,0,1,1,1,1,1,0,1,1,1,1,1,1,1,0,0,0,0,1,0,0,1,0,0,0,0,1,1,1,0,1,1,1,1,0,1,1,0,0,1,0,1,1,0,1,1,1,0,0,1,0,1,0,0,1,0,1,0,0,1,1,0,0,0,0,1,1,1,0,1,0,0,0,1,0,0,1,1,1,0,1,1,0,1,0,1,1,1,1,0,1,1,0,1,0,0,1,1,0,0,0,0,0,0,0,1,0,1,0,1,1,0,0,0,1,1,0,1,0,1,0,0,0,1,1,1,1,0,1,0,1,1,1,1,1,1,0,1,1,1,1,1,1,0,1,0,0,1,1,0,0,1,0,1,0,0,0,0,1,0,1,0,1,1,1,1,1,0,1,1,0,1,0,0,0,1,1,0,1,0,0,1,1,0,1,0,1,0,1,1,1,0,0,0,0,1,0,0,1,1,0,1,0,0,1,0,0,1,0,1,1,1,1,1,0,0,0,1,0,0,1,0,1,0,1,1,1,1,0,0,0,1,0,1,0,1,1,1,0,1,1,1,0,0,1,0,0,1,1,0,0,0,0,0,0,1,0,1,0,1,1,1,1,0,0,0,1,1,0,0,1,0,0,1,1,0,1,0,1,0,0,1,0,1,1,0,1,1,0,1,0,0,0,0,1,0,0,0,1,1,0,0,0,0,1,0,0,1,1,1,0,0,1,1,0,0,1,0,0,0,0,0,0,0,1,1,0,0,0,1,0,1,1,1,1,1,0,0,0,0,1,1,0,0,1,1,1,0,0,0,0,0,0,0,0,1,1,0,1,1,0,1,1,1,1,1,0,1,1,0,0,1,0,1,0,0,0,0,0,0,0,0,1,1,0,1,1,0,1,1,1,1,0,0,1,1,0,0,0,1,0,0,1,1,0,1,1,0,1,0,1,1,1,1,0,1,1,1,0,0,1,0,0,1,0,0,1,0,0,1,0,0,1,0,1,1,1,1,1,0,0,1,1,0,0,1,1,0,0,0,0,1,1,0,0,1,0,1,1,1,0,1,0,1,1,1,0,1,1,1,0,1,1,1,1,0,0,0,1,1,0,1,0,1,0,1,0,1,1,1,1,0,1,0,0,1,1,0,1,0,0,1,0,1,0,0,0,0,1,1,0,0,1,0,1,1,1,1,0,1,1,0,0,1,0,1,1,1,1,1,1,1,1,1,0,1,1,0,1,0,0,1,1,1,0,0,0,1,1,1,0,1,1,1,1,1,0,1,0,1,0,0,1,1,0,0,1,0,1,1,1,1,1,1,1,1,0,0,1,0,0,1,1,0,1,1,1,1,1,0,0,0,1,0,1,1,1,0,1,1,0,1,1,1,1,1,0,1,1,1,1,1,1,1,0,0,0,1,0,0,1,0,1,0,0,1,1,1,1,1,0,1,1,1,0,0,1,0,0,1,0,1,1,1,1,1,0,0,0,0,1,1,1,0,0,0,1,0,1,1,0,0,0,1,0,1,0,1,1,0,0,1,1,1,0,1,1,0,1,1,1,0,1,1,1,1,0,0,1,0,0,0,1,1,0,0,1,0,0,1,0,1,0,1,1,1,0,1,1,0,0,0,0,0,0,1,0,1,0,0,1,1,0,1,1,0,0,0,1,1,1,1,0,0,1,1,1,1,1,1,0,1,1,1,1,0,1,1,1,1,0,1,0,1,0,1,0,0,1,1,0,1,0,1,1,0,1,0,1,1,1,1,0,1,0,0,1,1,0,0,1,1,0,1,1,1,0,1,1,0,1,0,1,1,1,0,0,1,0,0,0,0,1,1,0,0 };
	
	//std::cout << "Input array Y \n\t" << yP(0, 0) << std::endl;

	////////////////////////////////////////////////////////////
	//Encryption
	////////////////////////////////////////////////////////////

	std::cout << "Starting encryption of x" << std::endl;
	
	start = currentDateTime();
	
	shared_ptr<Matrix<RationalCiphertext<ILVector2n>>> x = cc.EncryptMatrix(kp.publicKey, xP);

	finish = currentDateTime();

	std::cout << "Encryption/Batching time for x: " << "\t" << (finish - start) << " ms" << std::endl;
	
	std::cout << "Starting encryption of y" << std::endl;

	start = currentDateTime();

	shared_ptr<Matrix<RationalCiphertext<ILVector2n>>> y = cc.EncryptMatrix(kp.publicKey, yP);

	finish = currentDateTime();

	std::cout << "Encryption/Batching time for y: " << "\t" << (finish - start) << " ms" << std::endl;


	////////////////////////////////////////////////////////////
	//Linear Regression
	////////////////////////////////////////////////////////////

	std::cout << "Starting linear regression computation" << std::endl;

	start = currentDateTime();

	auto result = cc.EvalLinRegressBatched(x, y, batchSize);

	finish = currentDateTime();

	std::cout << "Linear regression time: " << "\t" << (finish - start) << " ms" << std::endl;
	

	////////////////////////////////////////////////////////////
	//Decryption
	////////////////////////////////////////////////////////////

	Matrix<PackedIntPlaintextEncoding> numerator = Matrix<PackedIntPlaintextEncoding>(zeroAlloc, 2, 1);
	Matrix<PackedIntPlaintextEncoding> denominator = Matrix<PackedIntPlaintextEncoding>(zeroAlloc, 2, 1);

	std::cout << "Starting decryption" << std::endl;

	start = currentDateTime();

	DecryptResult result1 = cc.DecryptMatrix(kp.secretKey, result, &numerator, &denominator);

	finish = currentDateTime();

	std::cout << "Decryption time: " << "\t" << (finish - start) << " ms" << std::endl;

	std::cout << numerator(0, 0)[0] << "," << numerator(1, 0)[0] << std::endl;
	std::cout << denominator(0, 0)[0] << "," << denominator(1, 0)[0] << std::endl;

}

void FVAutomorphismPackedArray(usint i) {

	double start, finish;

	usint m = 9742;
	usint N = GetTotient(m);
	usint p = 9743; // we choose s.t. 2m|p-1 to leverage CRTArb
	//BigBinaryInteger modulusQ("1329227995784915872903807060280351429");
	//BigBinaryInteger modulusP(p);
	//BigBinaryInteger rootOfUnity("526837940761322393507252072213464708");

	//BigBinaryInteger bigmodulus("56539106072908298546665520023773392506479484700019806659891398441363839489");
	//BigBinaryInteger bigroot("9767153299292203445583087811236008026651327014721082209123889105907321132");

	BigBinaryInteger modulusQ("1329227995784915872903807060281374689");
	BigBinaryInteger modulusP(p);
	BigBinaryInteger rootOfUnity("1103835257645791936030700335506173789");

	BigBinaryInteger bigmodulus("1852673427797059126777135760139006525652319754650249024631321344126610076631041");
	BigBinaryInteger bigroot("1011857408422309039039556907195908859561535234649870814154019834362746408101010");

	auto cycloPoly = GetCyclotomicPolynomial<BigBinaryVector, BigBinaryInteger>(m, modulusQ);
	//ChineseRemainderTransformArb<BigBinaryInteger, BigBinaryVector>::GetInstance().PreCompute(m, modulusQ);
	ChineseRemainderTransformArb<BigBinaryInteger, BigBinaryVector>::SetCylotomicPolynomial(cycloPoly, modulusQ);

	float stdDev = 4;

	shared_ptr<ILParams> params(new ILParams(m, modulusQ, rootOfUnity, bigmodulus, bigroot));

	BigBinaryInteger bigEvalMultModulus("56539106072908298546665520023773392506479484700019806659891398441363836893");
	BigBinaryInteger bigEvalMultRootOfUnity("53052183869611088031939364019843997045058225850224038885225625276029776524");
	BigBinaryInteger bigEvalMultModulusAlt("3273390607896141870013189696827599152216642046043064789483291368096133796404674554883270092325904157150886684127560071009217256545885393053328527589697");
	BigBinaryInteger bigEvalMultRootOfUnityAlt("2563034951385710135829466043208881424511641993674209890551611119759558880324006822420799164240195246658218008396013111810180897559508170734600399554363");

	auto cycloPolyBig = GetCyclotomicPolynomial<BigBinaryVector, BigBinaryInteger>(m, bigEvalMultModulus);
	//ChineseRemainderTransformArb<BigBinaryInteger, BigBinaryVector>::GetInstance().PreCompute(m, modulusQ);
	ChineseRemainderTransformArb<BigBinaryInteger, BigBinaryVector>::SetCylotomicPolynomial(cycloPolyBig, bigEvalMultModulus);

	std::cout << "Precomputing CRT coefficients" << std::endl;

	start = currentDateTime();

	PackedIntPlaintextEncoding::SetParams(modulusP, m);

	finish = currentDateTime();

	std::cout << "Precomputation time: " << "\t" << (finish - start) << " ms" << std::endl;

	usint batchSize = 4096;
	usint relinWindow = 24;

	shared_ptr<EncodingParams> encodingParams(new EncodingParams(modulusP, PackedIntPlaintextEncoding::GetInitRoot(), batchSize));

	BigBinaryInteger delta(modulusQ.DividedBy(modulusP));

	//genCryptoContextFV(shared_ptr<typename Element::Params> params,
	//	shared_ptr<typename EncodingParams> encodingParams,
	//	usint relinWindow, float stDev, const std::string& delta,
	//	MODE mode = RLWE, const std::string& bigmodulus = "0", const std::string& bigrootofunity = "0",
	//	int depth = 0, int assuranceMeasure = 0, float securityLevel = 0,
	//	const std::string& bigmodulusarb = "0", const std::string& bigrootofunityarb = "0")

	CryptoContext<ILVector2n> cc = CryptoContextFactory<ILVector2n>::genCryptoContextFV(params, encodingParams, relinWindow, stdDev, delta.ToString(), OPTIMIZED,
		bigEvalMultModulus.ToString(), bigEvalMultRootOfUnity.ToString(), 1, 9, 1.006, bigEvalMultModulusAlt.ToString(), bigEvalMultRootOfUnityAlt.ToString());

	cc.Enable(ENCRYPTION);
	cc.Enable(SHE);

	// Initialize the public key containers.
	LPKeyPair<ILVector2n> kp = cc.KeyGen();

	vector<shared_ptr<Ciphertext<ILVector2n>>> ciphertext;

	//std::vector<usint> vectorOfInts = { 0,1,0,2,0,3,0,4,0,5 };
	std::vector<usint> vectorOfInts = { 1,2,3,4,5,6,7,8 };
	PackedIntPlaintextEncoding intArray(vectorOfInts);
	//IntPlaintextEncoding intArray(vectorOfInts);

	if (i == 3)
		std::cout << "Input array\n\t" << intArray << std::endl;
	//std::cout << intArray << std::endl;

	std::cout << "Encryption" << std::endl;

	start = currentDateTime();

	ciphertext = cc.Encrypt(kp.publicKey, intArray, false);

	finish = currentDateTime();

	std::cout << "Encryption time: " << "\t" << (finish - start) << " ms" << std::endl;

	std::vector<usint> indexList = { 3,5,7,9,11,13,15 };

	std::cout << "Starting automorphism key generation " << std::endl;

	start = currentDateTime();

	auto evalKeys = cc.EvalAutomorphismKeyGen(kp.secretKey, indexList);

	finish = currentDateTime();

	std::cout << "Automorphism key generation time: " << "\t" << (finish - start) << " ms" << std::endl;

	vector<shared_ptr<Ciphertext<ILVector2n>>> permutedCiphertext;

	shared_ptr<Ciphertext<ILVector2n>> p1;

	std::cout << "Starting automorphism" << std::endl;

	start = currentDateTime();

	p1 = cc.EvalAutomorphism(ciphertext[0], i, *evalKeys);

	finish = currentDateTime();

	std::cout << "Automorphism time: " << "\t" << (finish - start) << " ms" << std::endl;

	permutedCiphertext.push_back(p1);

	PackedIntPlaintextEncoding intArrayNew;
	//IntPlaintextEncoding intArrayNew;

	std::cout << "Starting decryption" << std::endl;

	start = currentDateTime();

	cc.Decrypt(kp.secretKey, permutedCiphertext, &intArrayNew, false);
	//cc.Decrypt(kp.secretKey, ciphertext, &intArrayNew, false);

	finish = currentDateTime();

	std::cout << "Decryption time: " << "\t" << (finish - start) << " ms" << std::endl;

	std::cout << "Automorphed array - at index " << i << " (using only odd coefficients)\n\t" << intArrayNew << std::endl;

	std::cout << intArrayNew << std::endl;

}