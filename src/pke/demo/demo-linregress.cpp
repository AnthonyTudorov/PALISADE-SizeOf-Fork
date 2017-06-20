/*
 * @file demo-linregress.cpp This code shows multiple demonstrations of how to perform linear regression in PALISADE.
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

*/

#include <iostream>
#include <fstream>
#include <random>
#include <iterator>

#include "palisade.h"
#include "cryptocontexthelper.h"

#include "encoding/byteplaintextencoding.h"
#include "encoding/packedintplaintextencoding.h"

#include "utils/debug.h"

#include "math/nbtheory.h"
#include "math/matrix.h"
#include "math/matrix.cpp"

using namespace std;
using namespace lbcrypto;



void ArbBVLinearRegressionPackedArray();
void ArbFVLinearRegressionPackedArray();

int main() {

	std::cout << "\nThis code demonstrates the use of bit-pakcing for linear regression using the BV scheme. " << std::endl;
	std::cout << "This code shows how parameters can be manually set in our library. " << std::endl;
	
	std::cout << "\n===========BV TESTS (LINEAR-REGRESSION-ARBITRARY)===============: " << std::endl;

	ArbBVLinearRegressionPackedArray();

	std::cout << "\n===========FV TESTS (INNER-PRODUCT-ARBITRARY)===============: " << std::endl;

	ArbFVLinearRegressionPackedArray();

	std::cout << "Please press any key to continue..." << std::endl;

	std::cin.get();
	return 0;
}

void ArbBVLinearRegressionPackedArray() {

	PackedIntPlaintextEncoding::Destroy();

	usint m = 22;
	//usint p = 524591;
	usint p = 2333;
	BigBinaryInteger modulusP(p);
	/*BigBinaryInteger modulusQ("577325471560727734926295560417311036005875689");
	BigBinaryInteger squareRootOfRoot("576597741275581172514290864170674379520285921");*/
	//BigBinaryInteger modulusQ("955263939794561");
	//BigBinaryInteger squareRootOfRoot("941018665059848");
	BigBinaryInteger modulusQ("1267650600228229401496703214121");
	BigBinaryInteger squareRootOfRoot("498618454049802547396506932253");
	//BigBinaryInteger squareRootOfRoot = RootOfUnity(2*m,modulusQ);
	//std::cout << squareRootOfRoot << std::endl;

	//BigBinaryInteger bigmodulus("80899135611688102162227204937217");
	//BigBinaryInteger bigroot("77936753846653065954043047918387");
	BigBinaryInteger bigmodulus("1645504557321206042154969182557350504982735865633579863348616321");
	BigBinaryInteger bigroot("201473555181182026164891698186176997440470643522932663932844212");
	//std::cout << bigroot << std::endl;

	auto cycloPoly = GetCyclotomicPolynomial<BigBinaryVector, BigBinaryInteger>(m, modulusQ);
	ChineseRemainderTransformArb<BigBinaryInteger, BigBinaryVector>::GetInstance().SetCylotomicPolynomial(cycloPoly, modulusQ);

	PackedIntPlaintextEncoding::SetParams(modulusP, m);

	float stdDev = 4;

	usint batchSize = 8;

	shared_ptr<ILParams> params(new ILParams(m, modulusQ, squareRootOfRoot, bigmodulus, bigroot));

	shared_ptr<EncodingParams> encodingParams(new EncodingParams(modulusP,PackedIntPlaintextEncoding::GetAutomorphismGenerator(modulusP),batchSize));

	CryptoContext<ILVector2n> cc = CryptoContextFactory<ILVector2n>::genCryptoContextBV(params, encodingParams, 8, stdDev, OPTIMIZED);

	cc.Enable(ENCRYPTION);
	cc.Enable(SHE);

	std::cout << "Starting key generation" << std::endl;

	// Initialize the public key containers.
	LPKeyPair<ILVector2n> kp = cc.KeyGen();

	// Compute evaluation keys
	cc.EvalSumKeyGen(kp.secretKey);
	cc.EvalMultKeyGen(kp.secretKey);

	auto zeroAlloc = [=]() { return lbcrypto::make_unique<PackedIntPlaintextEncoding>(); };

	Matrix<PackedIntPlaintextEncoding> xP = Matrix<PackedIntPlaintextEncoding>(zeroAlloc, 1, 2);

	xP(0, 0) = { 0, 2, 1, 3,  2,  2, 1, 2 };
	xP(0, 1) = { 1 , 1 , 2 , 1 , 1 , 1, 3 , 2 };

	std::cout << "Input array X0 \n\t" << xP(0, 0) << std::endl;
	std::cout << "Input array X1 \n\t" << xP(0, 1) << std::endl;

	Matrix<PackedIntPlaintextEncoding> yP = Matrix<PackedIntPlaintextEncoding>(zeroAlloc, 2, 1);

	yP(0, 0) = { 0, 1, 2, 6, 1, 2, 3, 4};
	std::cout << "Input array Y \n\t" << yP(0, 0) << std::endl;

	////////////////////////////////////////////////////////////
	//Encryption
	////////////////////////////////////////////////////////////

	std::cout << "Starting encryption of x" << std::endl;

	shared_ptr<Matrix<RationalCiphertext<ILVector2n>>> x = cc.EncryptMatrix(kp.publicKey, xP);

	std::cout << "Starting encryption of y" << std::endl;

	shared_ptr<Matrix<RationalCiphertext<ILVector2n>>> y = cc.EncryptMatrix(kp.publicKey, yP);

	////////////////////////////////////////////////////////////
	//Linear Regression
	////////////////////////////////////////////////////////////

	auto result = cc.EvalLinRegressBatched(x, y, 8);

	////////////////////////////////////////////////////////////
	//Decryption
	////////////////////////////////////////////////////////////

	Matrix<PackedIntPlaintextEncoding> numerator = Matrix<PackedIntPlaintextEncoding>(zeroAlloc, 2, 1);
	Matrix<PackedIntPlaintextEncoding> denominator = Matrix<PackedIntPlaintextEncoding>(zeroAlloc, 2, 1);

	cc.DecryptMatrix(kp.secretKey, result, &numerator, &denominator);

	std::cout << numerator(0, 0)[0] << "," << numerator(1, 0)[0] << std::endl;
	std::cout << denominator(0, 0)[0] << "," << denominator(1, 0)[0] << std::endl;

}

void ArbFVLinearRegressionPackedArray() {

	usint m = 22;

	usint p = 2333; // we choose s.t. 2m|p-1 to leverage CRTArb
	BigBinaryInteger modulusQ("1152921504606847009");
	BigBinaryInteger modulusP(p);
	BigBinaryInteger rootOfUnity("1147559132892757400");

	BigBinaryInteger bigmodulus("42535295865117307932921825928971026753");
	BigBinaryInteger bigroot("13201431150704581233041184864526870950");

	auto cycloPoly = GetCyclotomicPolynomial<BigBinaryVector, BigBinaryInteger>(m, modulusQ);
	//ChineseRemainderTransformArb<BigBinaryInteger, BigBinaryVector>::GetInstance().PreCompute(m, modulusQ);
	ChineseRemainderTransformArb<BigBinaryInteger, BigBinaryVector>::SetCylotomicPolynomial(cycloPoly, modulusQ);

	float stdDev = 4;

	shared_ptr<ILParams> params(new ILParams(m, modulusQ, rootOfUnity, bigmodulus, bigroot));

	BigBinaryInteger bigEvalMultModulus("42535295865117307932921825928971026753");
	BigBinaryInteger bigEvalMultRootOfUnity("22649103892665819561201725524201801241");
	BigBinaryInteger bigEvalMultModulusAlt("115792089237316195423570985008687907853269984665640564039457584007913129642241");
	BigBinaryInteger bigEvalMultRootOfUnityAlt("37861550304274465568523443986246841530644847113781666728121717722285667862085");

	auto cycloPolyBig = GetCyclotomicPolynomial<BigBinaryVector, BigBinaryInteger>(m, bigEvalMultModulus);
	//ChineseRemainderTransformArb<BigBinaryInteger, BigBinaryVector>::GetInstance().PreCompute(m, modulusQ);
	ChineseRemainderTransformArb<BigBinaryInteger, BigBinaryVector>::SetCylotomicPolynomial(cycloPolyBig, bigEvalMultModulus);

	PackedIntPlaintextEncoding::SetParams(modulusP, m);

	usint batchSize = 8;

	shared_ptr<EncodingParams> encodingParams(new EncodingParams(modulusP, PackedIntPlaintextEncoding::GetAutomorphismGenerator(modulusP), batchSize));

	BigBinaryInteger delta(modulusQ.DividedBy(modulusP));

	//genCryptoContextFV(shared_ptr<typename Element::Params> params,
	//	shared_ptr<typename EncodingParams> encodingParams,
	//	usint relinWindow, float stDev, const std::string& delta,
	//	MODE mode = RLWE, const std::string& bigmodulus = "0", const std::string& bigrootofunity = "0",
	//	int depth = 0, int assuranceMeasure = 0, float securityLevel = 0,
	//	const std::string& bigmodulusarb = "0", const std::string& bigrootofunityarb = "0")

	CryptoContext<ILVector2n> cc = CryptoContextFactory<ILVector2n>::genCryptoContextFV(params, encodingParams, 1, stdDev, delta.ToString(), OPTIMIZED,
		bigEvalMultModulus.ToString(), bigEvalMultRootOfUnity.ToString(), 1, 9, 1.006, bigEvalMultModulusAlt.ToString(), bigEvalMultRootOfUnityAlt.ToString());

	cc.Enable(ENCRYPTION);
	cc.Enable(SHE);

	std::cout << "Starting key generation" << std::endl;

	// Initialize the public key containers.
	LPKeyPair<ILVector2n> kp = cc.KeyGen();

	// Compute evaluation keys
	cc.EvalSumKeyGen(kp.secretKey);
	cc.EvalMultKeyGen(kp.secretKey);

	auto zeroAlloc = [=]() { return lbcrypto::make_unique<PackedIntPlaintextEncoding>(); };

	Matrix<PackedIntPlaintextEncoding> xP = Matrix<PackedIntPlaintextEncoding>(zeroAlloc, 1, 2);

	xP(0, 0) = { 0, 2, 1, 3,  2,  2, 1, 2 };
	xP(0, 1) = { 1 , 1 , 2 , 1 , 1 , 1, 3 , 2 };

	std::cout << "Input array X0 \n\t" << xP(0, 0) << std::endl;
	std::cout << "Input array X1 \n\t" << xP(0, 1) << std::endl;

	Matrix<PackedIntPlaintextEncoding> yP = Matrix<PackedIntPlaintextEncoding>(zeroAlloc, 2, 1);

	yP(0, 0) = { 0, 1, 2, 6, 1, 2, 3, 4 };
	std::cout << "Input array Y \n\t" << yP(0, 0) << std::endl;

	////////////////////////////////////////////////////////////
	//Encryption
	////////////////////////////////////////////////////////////

	std::cout << "Starting encryption of x" << std::endl;

	shared_ptr<Matrix<RationalCiphertext<ILVector2n>>> x = cc.EncryptMatrix(kp.publicKey, xP);

	std::cout << "Starting encryption of y" << std::endl;

	shared_ptr<Matrix<RationalCiphertext<ILVector2n>>> y = cc.EncryptMatrix(kp.publicKey, yP);

	////////////////////////////////////////////////////////////
	//Linear Regression
	////////////////////////////////////////////////////////////

	auto result = cc.EvalLinRegressBatched(x, y, 8);

	////////////////////////////////////////////////////////////
	//Decryption
	////////////////////////////////////////////////////////////

	Matrix<PackedIntPlaintextEncoding> numerator = Matrix<PackedIntPlaintextEncoding>(zeroAlloc, 2, 1);
	Matrix<PackedIntPlaintextEncoding> denominator = Matrix<PackedIntPlaintextEncoding>(zeroAlloc, 2, 1);

	cc.DecryptMatrix(kp.secretKey, result, &numerator, &denominator);

	std::cout << numerator(0, 0)[0] << "," << numerator(1, 0)[0] << std::endl;
	std::cout << denominator(0, 0)[0] << "," << denominator(1, 0)[0] << std::endl;

}
