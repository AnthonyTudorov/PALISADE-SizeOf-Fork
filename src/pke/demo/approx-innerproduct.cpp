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
	usint m = 1051;
	usint p = 4304897; // we choose s.t. 2m|p-1 to leverage CRTArb

	BigBinaryInteger modulusQ("277982008135681");
	BigBinaryInteger modulusP(p);
	BigBinaryInteger rootOfUnity("24403853649624");

	BigBinaryInteger bigmodulus("277982008135681");
	BigBinaryInteger bigroot("27937174802548");

	auto cycloPoly = GetCyclotomicPolynomial<BigBinaryVector, BigBinaryInteger>(m, modulusQ);
	//ChineseRemainderTransformArb<BigBinaryInteger, BigBinaryVector>::GetInstance().PreCompute(m, modulusQ);
	ChineseRemainderTransformArb<BigBinaryInteger, BigBinaryVector>::SetCylotomicPolynomial(cycloPoly, modulusQ);

	float stdDev = 4;

	shared_ptr<ILParams> params(new ILParams(m, modulusQ, rootOfUnity, bigmodulus, bigroot));

	BigBinaryInteger bigEvalMultModulus("5316911983139663491615228241270218753");
	BigBinaryInteger bigEvalMultRootOfUnity("358051043311792747609278323720231473");
	BigBinaryInteger bigEvalMultModulusAlt("5316911983139663491615228241270218753");
	BigBinaryInteger bigEvalMultRootOfUnityAlt("1719066664281287604371558126323533989");

	auto cycloPolyBig = GetCyclotomicPolynomial<BigBinaryVector, BigBinaryInteger>(m, bigEvalMultModulus);
	//ChineseRemainderTransformArb<BigBinaryInteger, BigBinaryVector>::GetInstance().PreCompute(m, modulusQ);
	ChineseRemainderTransformArb<BigBinaryInteger, BigBinaryVector>::SetCylotomicPolynomial(cycloPolyBig, bigEvalMultModulus);

	usint batchSize = 1024;
	PackedIntPlaintextEncoding::SetParams(modulusP, m);

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

	std::cout << "zinv: " << bigroot.ModExp(BigBinaryInteger(4096), bigmodulus) << std::endl;
	//precompute bigroot of unity and inverse root of unity table if it's not yet computed.
	ModulusRoot<BigBinaryInteger> bigmodulusroot = { bigmodulus, bigroot };
	if (BluesteinFFT<BigBinaryInteger, BigBinaryVector>::GetInstance().m_rootOfUnityTableByModulusRoot[bigmodulusroot].GetLength() == 0) {
		BluesteinFFT<BigBinaryInteger, BigBinaryVector>::GetInstance().SetPreComputedNTTModulus(m, modulusQ, bigmodulus);
		BluesteinFFT<BigBinaryInteger, BigBinaryVector>::GetInstance().SetRootTableForNTT(m, bigmodulus, bigroot);
	}

	BigBinaryInteger rootInv(rootOfUnity.ModInverse(modulusQ));
	ModulusRoot<BigBinaryInteger> modulusroot = { modulusQ, rootOfUnity };
	//precompute powers table
	if (BluesteinFFT<BigBinaryInteger, BigBinaryVector>::GetInstance().m_powersTableByModulusRoot[modulusroot].GetLength() == 0) {
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
			.ForwardTransform(y, rootOfUnity, m, bigroot);
	BigBinaryVector yy = BluesteinFFT<BigBinaryInteger,BigBinaryVector>::GetInstance()
			.ForwardTransform(Y, rootInv, m, bigroot);
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

	std::vector<usint> vectorOfInts1(m-1, 2);
	PackedIntPlaintextEncoding intArray1(vectorOfInts1);

	std::vector<usint> vectorOfInts2(m-1, 3);
	PackedIntPlaintextEncoding intArray2(vectorOfInts2);
	shared_ptr<ILVector2n> plaintext(new ILVector2n(params, EVALUATION, true));
	for(usint i=0; i<(m-1); i++){
		plaintext->SetValAtIndex(i, BigBinaryInteger(vectorOfInts2[i]));
	}


	cc.EvalSumKeyGen(kp.secretKey);
	cc.EvalMultKeyGen(kp.secretKey);

	vector<shared_ptr<Ciphertext<ILVector2n>>> ciphertext;
	vector<shared_ptr<Ciphertext<ILVector2n>>> ciphertext2;

	ciphertext = cc.Encrypt(kp.publicKey, intArray1, false, true);
	ciphertext2 = cc.Encrypt(kp.publicKey, intArray2, false, false);

	std::cout << "Input array 1 \n\t" << intArray1 << std::endl;
	std::cout << "Input array 2 \n\t" << intArray2 << std::endl;

	vector<shared_ptr<Ciphertext<ILVector2n>>> ciphertextResult;
	auto ciphertextMult = cc.EvalMultPlain(ciphertext.at(0), ciphertext2.at(0));
	auto ciphertextInnerProd = cc.EvalSum(ciphertextMult, batchSize);
	ciphertextResult.insert(ciphertextResult.begin(), ciphertextInnerProd);
	PackedIntPlaintextEncoding intArrayNew;
	cc.Decrypt(kp.secretKey, ciphertextResult, &intArrayNew, false);
	std::cout << "Actual = " << intArrayNew << std::endl;

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
