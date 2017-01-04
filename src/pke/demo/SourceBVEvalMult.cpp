

#include <iostream>
#include <vector>


#include "palisade.h"

#include "cryptocontext.h"
#include "cryptocontexthelper.h"

#include "encoding/byteplaintextencoding.h"
#include "encoding/intplaintextencoding.h"

using namespace std;
using namespace lbcrypto;

bool EvalMultTest();


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

	for (usint i = 0; i < 4000; i++) {
		if(!EvalMultTest())
			std::cout << "EvalMult Failed \n";
	}

	std::cin.get();
	ChineseRemainderTransformFTT::GetInstance().Destroy();
	NumberTheoreticTransform::GetInstance().Destroy();

	return 0;
}


bool EvalMultTest() {

	usint m = 8;

	float stdDev = 4;

	BigBinaryInteger q("219902");
	BigBinaryInteger temp;

	lbcrypto::NextQ(q, BigBinaryInteger::FIVE, m, BigBinaryInteger("4"), BigBinaryInteger("4"));
	BigBinaryInteger rootOfUnity(RootOfUnity(m, q));
	shared_ptr<ILParams> params(new ILParams(m, q, rootOfUnity));

	//	ChineseRemainderTransformFTT::GetInstance().PreCompute(rootOfUnity, m, q);

	LPCryptoParametersBV<ILVector2n> cryptoParams;
	cryptoParams.SetPlaintextModulus(BigBinaryInteger::FIVE); // Set plaintext modulus.
	cryptoParams.SetDistributionParameter(stdDev);          // Set the noise parameters.
	cryptoParams.SetRelinWindow(8);						   // Set the relinearization window
	cryptoParams.SetElementParams(params);                // Set the initialization parameters.

	//Precomputations for DGG
	ILVector2n::PreComputeDggSamples(cryptoParams.GetDiscreteGaussianGenerator(), params);

	CryptoContext<ILVector2n> cc = CryptoContextFactory<ILVector2n>::genCryptoContextBV(&cryptoParams);
	cc.Enable(ENCRYPTION);
	cc.Enable(SHE);
	cc.Enable(LEVELEDSHE);


	std::vector<usint> vectorOfInts1 = { 4,0,0,0 };

	IntPlaintextEncoding intArray1(vectorOfInts1);

	std::vector<usint> vectorOfInts2 = { 3,0,0,0 };

	IntPlaintextEncoding intArray2(vectorOfInts2);

	std::vector<usint> vectorOfIntsExpected = { 2,0,0,0 };

	IntPlaintextEncoding intArrayExpected(vectorOfIntsExpected);

	// Initialize the public key containers.
	LPKeyPair<ILVector2n> kp = cc.KeyGen();

	vector<shared_ptr<Ciphertext<ILVector2n>>> ciphertext1 =
		cc.Encrypt(kp.publicKey, intArray1, false);

	vector<shared_ptr<Ciphertext<ILVector2n>>> ciphertext2 =
		cc.Encrypt(kp.publicKey, intArray2, false);

	shared_ptr<LPEvalKey<ILVector2n>> keySwitchHint = cc.EvalMultKeyGen(kp.secretKey);

	vector<shared_ptr<Ciphertext<ILVector2n>>> cResult;

	cResult.insert(cResult.begin(), cc.EvalMult(ciphertext1.at(0), ciphertext2.at(0), keySwitchHint));


	IntPlaintextEncoding results;

	cc.Decrypt(kp.secretKey, cResult, &results, false);

	if (results != intArrayExpected) {
		return false;
	}
	
	return true;


}
