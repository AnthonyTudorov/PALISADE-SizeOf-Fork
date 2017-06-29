/*
Encrypted-NN: Approximate Inner Product Demo

List of Authors:
Chiraag Juvekar, chiraag@mit.edu

Description:
This code calculated an approximate inner product over a batch of ciphertexts.

License Information:
MIT License
Copyright (c) 2017, Massachusetts Institute of Technology (MIT)

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

using namespace std;
using namespace lbcrypto;


#include <iterator>

int main() {
	std::cout << "\n===========FV TESTS (INNER-PRODUCT-ARBITRARY)===============: " << std::endl;

	//------------------ Setup Parameters ------------------
	usint m = 1117;
	usint p = 261379; // we choose s.t. 2m|p-1 to leverage CRTArb

	BigBinaryInteger modulusQ("1099522651739");
	BigBinaryInteger modulusP(p);
	BigBinaryInteger rootOfUnity("683946667136");

	BigBinaryInteger bigmodulus("9903520314283042199461429249");
	BigBinaryInteger bigroot("7428946567876166717508364269");

	auto cycloPoly = GetCyclotomicPolynomial<BigBinaryVector, BigBinaryInteger>(m, modulusQ);
	//ChineseRemainderTransformArb<BigBinaryInteger, BigBinaryVector>::GetInstance().PreCompute(m, modulusQ);
	ChineseRemainderTransformArb<BigBinaryInteger, BigBinaryVector>::SetCylotomicPolynomial(cycloPoly, modulusQ);

	float stdDev = 4;

	shared_ptr<ILParams> params(new ILParams(m, modulusQ, rootOfUnity, bigmodulus, bigroot));

	BigBinaryInteger bigEvalMultModulus("2535301200456458802993568493569");
	BigBinaryInteger bigEvalMultRootOfUnity("999805358370954002599032711849");
	BigBinaryInteger bigEvalMultModulusAlt("52656145834278593348959013841835216159447547700274555628027904001");
	BigBinaryInteger bigEvalMultRootOfUnityAlt("26852658184530345724247415131100175672644121901406632622613144552");

	auto cycloPolyBig = GetCyclotomicPolynomial<BigBinaryVector, BigBinaryInteger>(m, bigEvalMultModulus);
	//ChineseRemainderTransformArb<BigBinaryInteger, BigBinaryVector>::GetInstance().PreCompute(m, modulusQ);
	ChineseRemainderTransformArb<BigBinaryInteger, BigBinaryVector>::SetCylotomicPolynomial(cycloPolyBig, bigEvalMultModulus);

	PackedIntPlaintextEncoding::SetParams(modulusP, m);

	usint batchSize = 1024;

	shared_ptr<EncodingParams> encodingParams(new EncodingParams(modulusP, PackedIntPlaintextEncoding::GetAutomorphismGenerator(modulusP), batchSize));

	BigBinaryInteger delta(modulusQ.DividedBy(modulusP));

	//genCryptoContextFV(shared_ptr<typename Element::Params> params,
	//	shared_ptr<typename EncodingParams> encodingParams,
	//	usint relinWindow, float stDev, const std::string& delta,
	//	MODE mode = RLWE, const std::string& bigmodulus = "0", const std::string& bigrootofunity = "0",
	//	int depth = 0, int assuranceMeasure = 0, float securityLevel = 0,
	//	const std::string& bigmodulusarb = "0", const std::string& bigrootofunityarb = "0")

	/*
	usint phim = GetTotient(m);
	BigBinaryVector x(phim, modulusQ);
	for(usint i=0; i<phim; i++){
		x.SetValAtIndex(i, BigBinaryInteger(i));
	}
	BigBinaryVector X = ChineseRemainderTransformArb<BigBinaryInteger,BigBinaryVector>::GetInstance()
			.ForwardTransform(x, rootOfUnity, bigmodulus, bigroot, m);
	BigBinaryVector xx = ChineseRemainderTransformArb<BigBinaryInteger,BigBinaryVector>::GetInstance()
			.InverseTransform(X, rootOfUnity, bigmodulus, bigroot, m);
	std::cout << "x: " << x << std::endl;
	std::cout << "X: " << X << std::endl;
	std::cout << "xx: " << xx << std::endl;

	std::cout << "zinv: " << bigroot.ModExp(BigBinaryInteger(2*4096), bigmodulus) << std::endl;
	//precompute bigroot of unity and inverse root of unity table if it's not yet computed.
	if (BluesteinFFT<BigBinaryInteger, BigBinaryVector>::GetInstance().m_rootOfUnityTableByModulus[bigmodulus].GetLength() == 0) {
		BluesteinFFT<BigBinaryInteger, BigBinaryVector>::GetInstance().SetPreComputedNTTModulus(m, modulusQ, bigmodulus);
		BluesteinFFT<BigBinaryInteger, BigBinaryVector>::GetInstance().SetRootTableForNTT(m, modulusQ, bigmodulus, bigroot);
	}

	BigBinaryInteger rootInv(rootOfUnity.ModInverse(modulusQ));
	//precompute powers table
	if (BluesteinFFT<BigBinaryInteger, BigBinaryVector>::GetInstance().m_powersTableByRoot[rootOfUnity].GetLength() == 0) {
		BluesteinFFT<BigBinaryInteger, BigBinaryVector>::GetInstance().PreComputePowers(m, modulusQ, rootOfUnity);
		BluesteinFFT<BigBinaryInteger, BigBinaryVector>::GetInstance().PreComputePowers(m, modulusQ, rootInv);
		BluesteinFFT<BigBinaryInteger, BigBinaryVector>::GetInstance().PreComputeRBTable(m, modulusQ, rootOfUnity, bigmodulus, bigroot);
		BluesteinFFT<BigBinaryInteger, BigBinaryVector>::GetInstance().PreComputeRBTable(m, modulusQ, rootInv, bigmodulus, bigroot);
	}

	BigBinaryVector y(m, modulusQ);
	for(usint i=0; i<m; i++){
		y.SetValAtIndex(i, BigBinaryInteger(i));
	}
	BigBinaryVector Y = BluesteinFFT<BigBinaryInteger,BigBinaryVector>::GetInstance()
			.ForwardTransform(y, rootOfUnity, m);
	BigBinaryVector yy = BluesteinFFT<BigBinaryInteger,BigBinaryVector>::GetInstance()
			.ForwardTransform(Y, rootInv, m);
	std::cout << "y: " << y << std::endl;
	std::cout << "Y: " << Y << std::endl;
	std::cout << "yy: " << yy*BigBinaryInteger(m).ModInverse(modulusQ) << std::endl;
	*/

	CryptoContext<ILVector2n> cc = CryptoContextFactory<ILVector2n>::genCryptoContextFV(params, encodingParams, 8, stdDev, delta.ToString(), OPTIMIZED,
		bigEvalMultModulus.ToString(), bigEvalMultRootOfUnity.ToString(), 1, 9, 1.006, bigEvalMultModulusAlt.ToString(), bigEvalMultRootOfUnityAlt.ToString());

	//BigBinaryInteger modulusQ("955263939794561");
	//BigBinaryInteger squareRootOfRoot("941018665059848");

	cc.Enable(ENCRYPTION);
	cc.Enable(SHE);
	//------------------------------------------------------

	// Initialize the public key containers.
	LPKeyPair<ILVector2n> kp = cc.KeyGen();

	vector<shared_ptr<Ciphertext<ILVector2n>>> ciphertext;

	std::vector<usint> vectorOfInts1(m-1, 2);
	PackedIntPlaintextEncoding intArray1(vectorOfInts1);

	std::vector<usint> vectorOfInts2(m-1, 4);
	PackedIntPlaintextEncoding intArray2(vectorOfInts2);
	shared_ptr<ILVector2n> plaintext(new ILVector2n(params, EVALUATION, true));
	for(usint i=0; i<(m-1); i++){
		plaintext->SetValAtIndex(i, BigBinaryInteger(vectorOfInts2[i]));
	}


	cc.EvalSumKeyGen(kp.secretKey);
	cc.EvalMultKeyGen(kp.secretKey);

	ciphertext = cc.Encrypt(kp.publicKey, intArray1, false, true);

	std::cout << "Input array 1 \n\t" << intArray1 << std::endl;
	std::cout << "Input array 2 \n\t" << intArray2 << std::endl;

	/*
	vector<shared_ptr<Ciphertext<ILVector2n>>> ciphertextResult;
	auto ciphertextMult = cc.EvalMultPlain(ciphertext.at(0), plaintext);
	auto ciphertextInnerProd = cc.EvalSum(ciphertextMult, batchSize);
	auto ciphertextFin = cc.GetEncryptionAlgorithm()->AddRandomNoise(ciphertextInnerProd);
	ciphertextResult.insert(ciphertextResult.begin(), ciphertextFin);
	PackedIntPlaintextEncoding intArrayNew;

	cc.Decrypt(kp.secretKey, ciphertextResult, &intArrayNew, false);

	std::cout << "Sum = " << intArrayNew[0] << std::endl;

	std::cout << "Actual = " << intArrayNew << std::endl;
	*/
	return 0;
}
