/*

Multi-party linear regression model

//Without testing intermediate results

bin/demo/pke/Temp-lr-ols-multi paramgen demoData ccLRMulti
bin/demo/pke/Temp-lr-ols-multi keygen1 demoData ccLRMulti demoData TEST
bin/demo/pke/Temp-lr-ols-multi keygen2 demoData ccLRMulti demoData demoData TEST
bin/demo/pke/Temp-lr-ols-multi keygen3 demoData ccLRMulti demoData demoData demoData TEST

bin/demo/pke/Temp-lr-ols-multi encrypt demoData ccLRMulti demoData TEST demoData lr-multi-data-A.csv demoData A
bin/demo/pke/Temp-lr-ols-multi encrypt demoData ccLRMulti demoData TEST demoData lr-multi-data-B.csv demoData B

bin/demo/pke/Temp-lr-ols-multi computemultiparty demoData ccLRMulti demoData demoData TEST demoData A demoData B demoData AB

bin/demo/pke/Temp-lr-ols-multi partialdecrypt1 demoData ccLRMulti demoData TEST demoData AB demoData A
bin/demo/pke/Temp-lr-ols-multi partialdecrypt2 demoData ccLRMulti demoData TEST demoData AB demoData B
bin/demo/pke/Temp-lr-ols-multi fusedecode demoData ccLRMulti demoData A demoData B demoData AB

FINAL RESULT SHOULD MATCH THE FOLLOWING

[ 6.74695 -0.000470922 0.541544 -0.000357417 ]
/////////////// OLS Linear Regression AB////////////
Total Number of Features: 3
(Intercept): 6.746946
field1: -0.000471
field2: 0.541544
field3: -0.000357


//With testing intermediate results

bin/demo/pke/Temp-lr-ols-multi paramgen demoData ccLRMulti
bin/demo/pke/Temp-lr-ols-multi keygen1 demoData ccLRMulti demoData TEST
bin/demo/pke/Temp-lr-ols-multi keygen2 demoData ccLRMulti demoData demoData TEST
bin/demo/pke/Temp-lr-ols-multi keygen3 demoData ccLRMulti demoData demoData demoData TEST

bin/demo/pke/Temp-lr-ols-multi testevalkeys demoData ccLRMulti demoData demoData demoData TEST

bin/demo/pke/Temp-lr-ols-multi encrypt demoData ccLRMulti demoData TEST demoData lr-multi-data-A.csv demoData A
bin/demo/pke/Temp-lr-ols-multi encrypt demoData ccLRMulti demoData TEST demoData lr-multi-data-B.csv demoData B

bin/demo/pke/Temp-lr-ols-multi computemultiparty demoData ccLRMulti demoData demoData TEST demoData A demoData B demoData AB

bin/demo/pke/Temp-lr-ols-multi testlr demoData ccLRMulti demoData TEST demoData AB

bin/demo/pke/Temp-lr-ols-multi partialdecrypt1 demoData ccLRMulti demoData TEST demoData AB demoData A
bin/demo/pke/Temp-lr-ols-multi partialdecrypt2 demoData ccLRMulti demoData TEST demoData AB demoData B
bin/demo/pke/Temp-lr-ols-multi fusedecode demoData ccLRMulti demoData A demoData B demoData AB

*/

#include <iostream>
#include <fstream>


#include "palisade.h"

#include "utils/serialize-binary.h"
#include "scheme/bgv/bgv-ser.h"
#include "pubkeylp-ser.h"
#include "cryptocontext-ser.h"
#include "ciphertext-ser.h"
#include <random>

#include "../../core/lib/math/matrix.cpp"

#include "Temp-matrixinverse.h"

using namespace std;
using namespace lbcrypto;

#include <iterator>

// Multi-party methods

// Generate 3 crypto contexts and serialize them
void ParamGen(string &paramDir, const string &contextID);

// Key generation - round 1 - done by Provider A
// KeyDir1 stores private and public key for provider A
void KeyGen1(const string &paramDir,  const string &contextID, const string &keyDir1, const string &JointKeyId);

//Key generation - round 2  - done by Provider B
// KeyDir1 stores private key for provider B
// KeyDir2 stores joint public key and EvalAuto keys; also stores intermediate keys for EvalMult
void KeyGen2(const string &paramDir,  const string &contextID, const string &keyDir1, const string &keyDir2, const string &JointKeyId);

//Key generation - round 3 -  - done by Provider A
// KeyDir1 stores private key for provider A
// KeyDir2 initially stores joint public key and EvalAuto keys; also stores intermediate keys for EvalMult
// KeyDir3 stores the final EvalMult keys; also joint public and EvalAuto keys are moved there
void KeyGen3(const string &paramDir,  const string &contextID, const string &keyDir1, const string &keyDir2, const string &keyDir3, const string &JointKeyId);

//Encryption - done by providers A and B
// KeyDir2 stores joint public key
void Encrypt(const string &paramDir,  const string &contextID, const string &keyDir2, const string &ptxtDir, const string &ptxtId, const string &ctxtDir, const string &ctxId, const string &JointKeyId);

//Matrix joint and encrypted computation 
// KeyDir2 stores joint public and EvalAuto keys
// KeyDir3 stores joint eval mult key
void ComputeMultiparty(const string &paramDir,  const string &contextID, const string &keyDir2, const string &keyDir3, const string &JointKeyId, 
	const string &ctxt1Dir, const string &ctx1Id, const string &ctxt2Dir, const string &ctx2Id,
	const string &ctxtOutDir, const string &ctxOutId);

//Partial decryption - Leader mode - done by Provider A
// KeyDir1 stores private key for Provider A
void PartialDecrypt1(const string &paramDir,  const string &contextID, const string &keyDir1, const string &JointKeyId, const string &ctxtInDir, 
	const string &ctxInId, const string &ctxtOutDir, const string &ctxOutId);

//Partial decryption - Follower mode - done by Provider B
// KeyDir1 stores private key for Provider B
void PartialDecrypt2(const string &paramDir,  const string &contextID, const string &keyDir1, const string &JointKeyId, const string &ctxtInDir, 
	const string &ctxInId, const string &ctxtOutDir, const string &ctxOutId);

//Fusion, cleartext operations, and decoding - done by Viewer
void FuseDecode(const string &paramDir, const string &contextID, 
	const string &ctxtIn1Dir, const string &ctxIn1Id, const string &ctxtIn2Dir,
	const string &ctxIn2Id, const string &plaintextResultDir, const string &plaintextResultFileName);



void TestEvalKeys(const string &paramDir,  const string &contextID, const string &keyDir1, const string &keyDir2, const string &keyDir3, const string &JointKeyId);

void TestLR(const string &paramDir,  const string &contextID, const string &keyDir1, const string &JointKeyId, const string &ctxtDir, const string &ctxId);

CryptoContext<DCRTPoly> DeserializeContext(const string& ccFileName);
void ReadCSVFile(string dataFileName,  vector<string>& headers, vector<vector<double> >& dataColumns);
void EncodeData(CryptoContext<DCRTPoly> cc, const std::vector<string> &headers, const vector<vector<double>>& dataColumns, Matrix<Plaintext> &x, Plaintext &y);
void CRTInterpolate(const vector<shared_ptr<Matrix<Plaintext>>> &crtVector, Matrix<NativeInteger> &result);
void MatrixInverse(const Matrix<NativeInteger> &in, Matrix<double> &out);
void DecodeData(const Matrix<double> &lr, const Matrix<NativeInteger>& XTX, const Matrix<NativeInteger>& XTY, std::vector<double> &result);

void ConvertMatrixInto2DVector(const Matrix<RationalCiphertext<DCRTPoly>> &matrix, vector<vector<Ciphertext<DCRTPoly>>> &vec);

void Convert2DVectorIntoMatrix(const vector<vector<Ciphertext<DCRTPoly>>> &vec, Matrix<RationalCiphertext<DCRTPoly>> &matrix);

template <class Element>
LPEvalKey<Element> MultiKeySwitchGen(const LPPrivateKey<Element> originalPrivateKey, const LPPrivateKey<Element> newPrivateKey,
	const LPEvalKey<DCRTPoly> ek);

template <class Element>
shared_ptr<std::map<usint, LPEvalKey<Element>>> MultiEvalAutomorphismKeyGen(const LPPrivateKey<Element> privateKey,
	const shared_ptr<std::map<usint, LPEvalKey<Element>>> eAuto,
	const std::vector<usint> &indexList);

template <class Element>
shared_ptr<std::map<usint, LPEvalKey<Element>>> MultiEvalSumKeyGen(const LPPrivateKey<Element> privateKey,
	const shared_ptr<std::map<usint, LPEvalKey<Element>>> eSum);

template <class Element>
LPEvalKey<Element> AddEvalKeys(LPEvalKey<Element> a, LPEvalKey<Element> b);

template <class Element>
LPEvalKey<Element> MultiplyEvalKey(LPEvalKey<Element> evalKey, LPPrivateKey<Element> sk);

template <class Element>
shared_ptr<std::map<usint, LPEvalKey<Element>>> AddEvalSumKeys(const shared_ptr<std::map<usint, LPEvalKey<Element>>> es1,
	const shared_ptr<std::map<usint, LPEvalKey<Element>>> es2);

template <class Element>
LPEvalKey<Element> AddEvalMultKeys(LPEvalKey<Element> evalKey1, LPEvalKey<Element> evalKey2);

template <class Element>
LPPrivateKey<Element> AddSecretKeys(LPPrivateKey<Element> a, LPPrivateKey<Element> b);

// number of primitive prime plaintext moduli in the CRT representation of plaintext
const size_t SIZE = 2;

int main(int argc, char* argv[]) {

	if (argc < 2) { // called with no arguments
		std::cout << "Usage is `" << argv[0] << " arg1 ' where: " << std::endl;
		std::cout << "  arg1 can be one of the following: paramgen, keygen{1,2,3}, testevalKeys, encrypt, computemultiparty, testlr, partialdecrypt1, partialdecrypt2, or fusedecode" << std::endl;
	}

	if (argc > 1) {

		if (std::string(argv[1]) == "paramgen")
		{
			string paramDir = string(argv[2]);
			string contextID = string(argv[3]);
			ParamGen(paramDir,contextID);
		}
		else {
			//Serial::DisableKeysInSerializedContext();
			{
				if (std::string(argv[1]) == "keygen1")
				{
					string paramDir = string(argv[2]);
					string contextID = string(argv[3]);
					string keyDir1 = string(argv[4]);
					string jointKeyId = string(argv[5]);
					KeyGen1(paramDir, contextID, keyDir1, jointKeyId);
				}
				else if (std::string(argv[1]) == "keygen2")
				{
					string paramDir = string(argv[2]);
					string contextID = string(argv[3]);
					string keyDir1 = string(argv[4]);
					string keyDir2 = string(argv[5]);
					string jointKeyId = string(argv[6]);
					KeyGen2(paramDir, contextID, keyDir1, keyDir2, jointKeyId);
				}
				else if (std::string(argv[1]) == "keygen3")
				{
					string paramDir = string(argv[2]);
					string contextID = string(argv[3]);
					string keyDir1 = string(argv[4]);
					string keyDir2 = string(argv[5]);
					string keyDir3 = string(argv[6]);
					string jointKeyId = string(argv[7]);
					KeyGen3(paramDir, contextID, keyDir1, keyDir2, keyDir3, jointKeyId);
				}
				else if (std::string(argv[1]) == "testevalkeys")
				{
					string paramDir = string(argv[2]);
					string contextID = string(argv[3]);
					string keyDir1 = string(argv[4]);
					string keyDir2 = string(argv[5]);
					string keyDir3 = string(argv[6]);
					string jointKeyId = string(argv[7]);
					TestEvalKeys(paramDir, contextID, keyDir1, keyDir2, keyDir3, jointKeyId);
				}
				else if (std::string(argv[1]) == "encrypt")
				{
					string paramDir = string(argv[2]);
					string contextID = string(argv[3]);
					string keyDir2 = string(argv[4]);
					string jointKeyId = string(argv[5]);
					string ptxtDir = string(argv[6]);
					string ptxtId = string(argv[7]);
					string ctxtDir = string(argv[8]);
					string ctxtId = string(argv[9]);
					Encrypt(paramDir, contextID, keyDir2, jointKeyId, ptxtDir, ptxtId, ctxtDir, ctxtId);
				}
				else if (std::string(argv[1]) == "computemultiparty")
				{
					string paramDir = string(argv[2]);
					string contextID = string(argv[3]);
					string keyDir2 = string(argv[4]);
					string keyDir3 = string(argv[5]);
					string jointKeyId = string(argv[6]);
					string ctxt1Dir = string(argv[7]);
					string ctx1Id = string(argv[8]);
					string ctxt2Dir = string(argv[9]);
					string ctx2Id = string(argv[10]);
					string ctxtOutDir = string(argv[11]);
					string ctxOutId = string(argv[12]);
					ComputeMultiparty(paramDir, contextID, keyDir2, keyDir3, jointKeyId, ctxt1Dir, ctx1Id, ctxt2Dir, ctx2Id, ctxtOutDir, ctxOutId);
				}
				else if (std::string(argv[1]) == "testlr")
				{
					string paramDir = string(argv[2]);
					string contextID = string(argv[3]);
					string keyDir1 = string(argv[4]);
					string jointKeyId = string(argv[5]);
					string ctxtDir = string(argv[6]);
					string ctxId = string(argv[7]);
					TestLR(paramDir, contextID, keyDir1, jointKeyId, ctxtDir, ctxId);
				}
				else if (std::string(argv[1]) == "partialdecrypt1")
				{
					string paramDir = string(argv[2]);
					string contextID = string(argv[3]);
					string keyDir1 = string(argv[4]);
					string jointKeyId = string(argv[5]);
					string ctxtInDir = string(argv[6]);
					string ctxInId = string(argv[7]);
					string ctxtOutDir = string(argv[8]);
					string ctxOutId = string(argv[9]);
					PartialDecrypt1(paramDir, contextID, keyDir1, jointKeyId, ctxtInDir, ctxInId, ctxtOutDir, ctxOutId);
				}
				else if (std::string(argv[1]) == "partialdecrypt2")
				{
					string paramDir = string(argv[2]);
					string contextID = string(argv[3]);
					string keyDir1 = string(argv[4]);
					string jointKeyId = string(argv[5]);
					string ctxtInDir = string(argv[6]);
					string ctxInId = string(argv[7]);
					string ctxtOutDir = string(argv[8]);
					string ctxOutId = string(argv[9]);
					PartialDecrypt2(paramDir, contextID, keyDir1, jointKeyId, ctxtInDir, ctxInId, ctxtOutDir, ctxOutId);
				}
				else if (std::string(argv[1]) == "fusedecode")
				{
					string paramDir = string(argv[2]);
					string contextID = string(argv[3]);
					string ctxtIn1Dir = string(argv[4]);
					string ctxIn1Id = string(argv[5]);
					string ctxtIn2Dir = string(argv[6]);
					string ctxIn2Id = string(argv[7]);
					string plaintextResultDir = string(argv[8]);
					string plaintextResultFileName = string(argv[9]);
					FuseDecode(paramDir, contextID, ctxtIn1Dir, ctxIn1Id, ctxtIn2Dir, ctxIn2Id, plaintextResultDir, plaintextResultFileName);
				}
				else {
					std::cerr << "the argument is invalid";
					return 1;
				}
			}
		}
	}

	//cin.get();

	PackedEncoding::Destroy();

	return 0;
}

static string GenerateUniqueKeyID() {

	size_t intsInID = 128 / (sizeof(uint32_t) * 8);

	std::uniform_int_distribution<uint32_t> distribution(0, std::numeric_limits<uint32_t>::max());
	std::stringstream s;
	s.fill('0');
	s << std::hex;
	for( size_t i = 0; i < intsInID; i++ )
		s << std::setw(8) << distribution(PseudoRandomNumberGenerator::GetPRNG());
	return s.str();
}

void ParamGen(string &paramDir, const string &contextID) {

	for (size_t k = 0; k < SIZE; k++) {

		size_t batchSize = 1024;

		usint init_size = 2;
		usint dcrtBits = 57;
		//usint dcrtBitsBig = 57;

		usint m;
		PlaintextModulus p;

		switch (k) {
		case 0:
			m = 2048;
			p = 40961;
			break;
		case 1:
			m = 2048;
			p = 59393;
			break;
		case 2:
			m = 2048;
			p = 12289;
			break;
		case 3:
			m = 2048;
			p = 18433;
			break;
		}

		BigInteger modulusP(p);

		std::cout << "\nKEY GENERATION AND SERIALIZATION FOR p = " << p << "\n" << std::endl;

		// populate the towers for the small modulus

		vector<NativeInteger> init_moduli(init_size);
		vector<NativeInteger> init_rootsOfUnity(init_size);

		NativeInteger q = FirstPrime<NativeInteger>(dcrtBits, m);
		init_moduli[0] = q;
		init_rootsOfUnity[0] = RootOfUnity(m, init_moduli[0]);

		for (usint i = 1; i < init_size; i++) {
			q = lbcrypto::NextPrime(q, m);
			init_moduli[i] = q;
			init_rootsOfUnity[i] = RootOfUnity(m, init_moduli[i]);
		}

		shared_ptr<ILDCRTParams<BigInteger>> paramsDCRT(new ILDCRTParams<BigInteger>(m, init_moduli, init_rootsOfUnity));

		EncodingParams encodingParams(new EncodingParamsImpl(p));

		PackedEncoding::SetParams(m, encodingParams);
		encodingParams->SetBatchSize(batchSize);

		float stdDev = 4;

		CryptoContext<DCRTPoly> cc =
			CryptoContextFactory<DCRTPoly>::genCryptoContextBGV(paramsDCRT, encodingParams, 30, stdDev);

		cc->Enable(ENCRYPTION);
		cc->Enable(SHE);
		cc->Enable(MULTIPARTY);

		// CryptoContext

		std::cout << "Serializing crypto context...";

		if (!Serial::SerializeToFile(paramDir + "/cryptocontext_" + std::to_string(k) + "_" + contextID + ".txt", cc, SerType::BINARY)) {
			cerr << "Error writing serialization of the crypto context to cryptotext_" + std::to_string(k) + "_" + contextID + ".txt" << endl;
			return;
		}

		std::cout << "Completed" << std::endl;

	}

}

void KeyGen1(const string &paramDir,  const string &contextID, const string &keyDir1, const string &jointKeyId) {

	for (size_t k = 0; k < SIZE; k++) {

		std::cout << "\nKEY GENERATION/SERIALIZATION FOR p #" << std::to_string(k + 1) << "\n" << std::endl;

		string ccFileName = "cryptocontext_" + std::to_string(k) + "_" + contextID + ".txt";

		// Deserialize the crypto context

		CryptoContext<DCRTPoly> cc = DeserializeContext(paramDir + "/" + ccFileName);

		const shared_ptr<LPCryptoParameters<DCRTPoly>> cryptoParams = cc->GetCryptoParameters();
		EncodingParams encodingParams = cryptoParams->GetEncodingParams();
		const shared_ptr<ILDCRTParams<BigInteger>> elementParams = cryptoParams->GetElementParams();
		usint m = elementParams->GetCyclotomicOrder();
		PackedEncoding::SetParams(m, encodingParams);

		////////////////////////////////////////////////////////////
		//Key Generation and Serialization
		////////////////////////////////////////////////////////////

		std::cout << "Generating public and private keys...";
		LPKeyPair<DCRTPoly> kp = cc->KeyGen();

		std::cout << "Completed" << std::endl;

		std::cout << "Serializing public and private keys...";

		if (kp.publicKey && kp.secretKey) {

			if (!Serial::SerializeToFile(keyDir1 + "/" + "key-public-A-" +  jointKeyId + "-" + std::to_string(k) + ".txt", kp.publicKey, SerType::BINARY)) {
				cerr << "Error writing serialization of public key to " << "key-public-A-" + jointKeyId + "-" + std::to_string(k) + ".txt" << endl;
				return;
			}

			if (!Serial::SerializeToFile(keyDir1 + "/" + "key-private-A-" +  jointKeyId + "-" + std::to_string(k) + ".txt", kp.secretKey, SerType::BINARY)) {
				cerr << "Error writing serialization of private key to key-private-A-" + jointKeyId + " - " + std::to_string(k) + ".txt" << endl;
				return;
			}
		}
		else {
			cerr << "Failure in generating private and public keys" << endl;
		}
		std::cout << "Completed" << std::endl;

		// EvalMultKey

		std::cout << "Generating multiplication evaluation key for stage 1 (for A)...";

		auto evalMultKey = cc->KeySwitchGen(kp.secretKey, kp.secretKey);

		std::cout << "Completed" << std::endl;

		std::cout << "Serializing multiplication evaluation key...";

		if (evalMultKey) {

			if (!Serial::SerializeToFile(keyDir1 + "/" + "key-eval-mult-A-" + jointKeyId + "-" + std::to_string(k) + ".txt", evalMultKey, SerType::BINARY)) {
				cerr << "Error writing serialization of multiplication evaluation key to key-eval-mult-A-" + jointKeyId + "-" + std::to_string(k) + ".txt" << endl;
				return;
			}
		}
		else {
			cerr << "Failure in generating multiplication evaluation key" << endl;
		}

		std::cout << "Completed" << std::endl;

		// EvalSumKey

		std::cout << "Generating summation evaluation keys for stage 1...";

		cc->EvalSumKeyGen(kp.secretKey);

		auto evalSumKeys = cc->GetEvalSumKeyMap(kp.secretKey->GetKeyTag());

		std::cout << "Completed" << std::endl;

		std::cout << "Serializing summation evaluation keys...";

		for (std::map<usint, LPEvalKey<DCRTPoly>>::iterator it = evalSumKeys.begin(); it != evalSumKeys.end(); ++it)
		{
			if (it->second) {
				if (!Serial::SerializeToFile(keyDir1 + "/" + "key-eval-sum-A-" + jointKeyId + "-" + std::to_string(k) + "-" + std::to_string(it->first) + ".txt", it->second, SerType::BINARY)) {
					cerr << "Error writing serialization of summation evaluation key to " << "key-eval-sum-A-" + jointKeyId + "-" + std::to_string(k) + "-" + std::to_string(it->first) + ".txt" << endl;
					return;
				}
			}
			else {
				cerr << "Failure in generating summation evaluation key with index " + std::to_string(it->first) << endl;
			}
		}

		std::cout << "Completed" << std::endl;

	}

}

void KeyGen2(const string &paramDir,  const string &contextID, const string &keyDir1, const string &keyDir2, const string &jointKeyId)
{

	for (size_t k = 0; k < SIZE; k++) {

		std::cout << "\nKEY GENERATION/SERIALIZATION FOR p #" << std::to_string(k + 1) << "\n" << std::endl;

		string ccFileName = "cryptocontext_" + std::to_string(k) + "_" + contextID + ".txt";

		// Deserialize the crypto context

		CryptoContext<DCRTPoly> cc = DeserializeContext(paramDir + "/" + ccFileName);

		const shared_ptr<LPCryptoParameters<DCRTPoly>> cryptoParams = cc->GetCryptoParameters();
		EncodingParams encodingParams = cryptoParams->GetEncodingParams();
		const shared_ptr<ILDCRTParams<BigInteger>> elementParams = cryptoParams->GetElementParams();
		usint m = elementParams->GetCyclotomicOrder();
		PackedEncoding::SetParams(m, encodingParams);

		// Deserialize the public key

		std::cout << "Deserializing the public key of party A...";

		LPPublicKey<DCRTPoly> pk;
		if (Serial::DeserializeFromFile(keyDir1 + "/" + "key-public-A-" + jointKeyId + "-" + std::to_string(k) + ".txt", pk, SerType::BINARY) == false) {
			cerr << "Could not read public key of A" << endl;
			return;
		}

		if (!pk) {
			cerr << "Could not deserialize public key of A" << endl;
			return;
		}

		std::cout << "Completed" << std::endl;

		////////////////////////////////////////////////////////////
		//Key Generation and Serialization
		////////////////////////////////////////////////////////////

		std::cout << "Generating private key for B and joint public key...";
		LPKeyPair<DCRTPoly> kp = cc->MultipartyKeyGen(pk);

		kp.publicKey->SetKeyTag( GenerateUniqueKeyID());

		std::cout << "Completed" << std::endl;

		std::cout << "Serializing public and private keys...";

		if (kp.publicKey && kp.secretKey) {

			if (!Serial::SerializeToFile(keyDir2 + "/" + "key-public-J-" + jointKeyId + "-" + std::to_string(k) + ".txt", kp.publicKey, SerType::BINARY)) {
				cerr << "Error writing serialization of public key to " << "key-public-J-" + jointKeyId + "-" + std::to_string(k) + ".txt" << endl;
				return;
			}

			if (!Serial::SerializeToFile(keyDir1 + "/" + "key-private-B-" + jointKeyId + "-" + std::to_string(k) + ".txt", kp.secretKey, SerType::BINARY)) {
				cerr << "Error writing serialization of private key to key-private-B-" + jointKeyId + " - " + std::to_string(k) + ".txt" << endl;
				return;
			}
		}
		else {
			cerr << "Failure in generating private and public keys" << endl;
		}
		std::cout << "Completed" << std::endl;

		
		// EVALMULTKEY

		// Deserialize the eval mult key stage 1 result for A

		std::cout << "Deserializing the stage 1 multiplication evaluation key for A...";

		LPEvalKey<DCRTPoly> em;
		if (Serial::DeserializeFromFile(keyDir1 + "/" + "key-eval-mult-A-" + jointKeyId + "-" + std::to_string(k) + ".txt", em, SerType::BINARY) == false) {
			cerr << "Could not read mulplication evaluation key" << endl;
			return;
		}

		if (!em) {
			cerr << "Could not deserialize multiplication evaluation key" << endl;
			return;
		}

		std::cout << "Completed" << std::endl;

		//Generate stage 1 multiplication evaluation key for B

		std::cout << "Generating stage 1 multiplication evaluation key for B...";

		auto evalMultKey = MultiKeySwitchGen(kp.secretKey, kp.secretKey,em);

		std::cout << "Completed" << std::endl;

		// Stage 2 of eval mult generation: Add two stage 1 results (from A and B)

		std::cout << "Stage 2 of EvalMult key generation: Adding phase 1 evalmult keys of A and B...";

		auto evalMultAdd = AddEvalKeys(em, evalMultKey);

		// tag for the joint key
		evalMultAdd->SetKeyTag(kp.publicKey->GetKeyTag());

		std::cout << "Completed" << std::endl;

		// Serializing the stage 2 eval mult key

		std::cout << "Serializing multiplication evaluation key for stage 2...";

		if (evalMultAdd) {
			if (!Serial::SerializeToFile(keyDir2 + "/" + "key-eval-mult-AB-" + jointKeyId + "-" + std::to_string(k) + ".txt", evalMultAdd, SerType::BINARY)) {
				cerr << "Error writing serialization of multiplication evaluation key to key-eval-mult-AB-" + jointKeyId + "-" + std::to_string(k) + ".txt" << endl;
				return;
			}
		}
		else {
			cerr << "Failure in generating multiplication evaluation key" << endl;
		}

		std::cout << "Completed" << std::endl;

		// Stage 3 of eval mult generation: Joint key is multiplied by key B
		
		std::cout << "Joint key (s_a + s_b) is transformed into s_b*(s_a + s_b)...";

		auto evalMult3 = MultiplyEvalKey(evalMultAdd, kp.secretKey);

		evalMult3->SetKeyTag(kp.publicKey->GetKeyTag());

		std::cout << "Completed" << std::endl;

		std::cout << "Serializing multiplication evaluation key for stage 3...";

		if (evalMult3) {
			if (!Serial::SerializeToFile(keyDir2 + "/" + "key-eval-mult-BAB-" + jointKeyId + "-" + std::to_string(k) + ".txt", evalMult3, SerType::BINARY)) {
				cerr << "Error writing serialization of multiplication evaluation key to key-eval-mult-BAB-" + jointKeyId + "-" + std::to_string(k) + ".txt" << endl;
				return;
			}
		}
		else {
			cerr << "Failure in generating multiplication evaluation key" << endl;
		}

		std::cout << "Completed" << std::endl;


		// EVALSUMKEY

		// Deserialization the summation keys for A

		std::cout << "Deserializing stage 1 summation evaluation keys for A...";

		//const shared_ptr<LPCryptoParameters<DCRTPoly>> cryptoParams = cc.GetCryptoParameters();
		//const EncodingParams encodingParams = cryptoParams->GetEncodingParams();
		//const shared_ptr<ILDCRTParams<BigInteger>> elementParams = cryptoParams->GetElementParams();

		usint batchSize = encodingParams->GetBatchSize();
		usint g = 5;
		//usint m = elementParams->GetCyclotomicOrder();

		shared_ptr<std::map<usint, LPEvalKey<DCRTPoly>>> evalSumKeysA(new std::map<usint, LPEvalKey<DCRTPoly>>());

		for (int i = 0; i < floor(log2(batchSize)); i++)
		{

			if(i == floor(log2(batchSize))-1)
				g = m-1;
			
			LPEvalKey<DCRTPoly> es;
			string tempFileName = keyDir1 + "/" + "key-eval-sum-A-" + jointKeyId + "-" + std::to_string(k) + "-" + std::to_string(g) + ".txt";
			if (Serial::DeserializeFromFile(tempFileName, es, SerType::BINARY) == false) {
				cerr << "Could not read the evaluation key at index " << g << endl;
				return;
			}

			if (!es) {
				cerr << "Could not deserialize summation evaluation key at index " << g << endl;
				return;
			}

			(*evalSumKeysA)[g] = es;

			g = (g * g) % m;
		}

		std::cout << "Completed" << std::endl;


		std::cout << "Generating stage 1 summation evaluation keys for B...";

		auto evalSumKeysB = MultiEvalSumKeyGen(kp.secretKey, evalSumKeysA);

		std::cout << "Completed" << std::endl;



		std::cout << "Generating the joint summation evaluation key...";

		auto evalSumKeysJoin = AddEvalSumKeys(evalSumKeysA,evalSumKeysB);

		std::cout << "Completed" << std::endl;


		std::cout << "Serializing joint summation evaluation keys...";

		for (std::map<usint, LPEvalKey<DCRTPoly>>::iterator it = evalSumKeysJoin->begin(); it != evalSumKeysJoin->end(); ++it)
		{
			if (it->second) {

				// tag for the joint key
				it->second->SetKeyTag(kp.publicKey->GetKeyTag());

				if (!Serial::SerializeToFile(keyDir2 + "/" + "key-eval-sum-AB-" + jointKeyId + "-" + std::to_string(k) + "-" + std::to_string(it->first) + ".txt", it->second, SerType::BINARY)) {
					cerr << "Error writing serialization of summation evaluation key to " << "key-eval-sum-AB-" + jointKeyId + "-" + std::to_string(k) + "-" + std::to_string(it->first) + ".txt" << endl;
					return;
				}
			}
			else {
				cerr << "Failure in generating summation evaluation key with index " + std::to_string(it->first) << endl;
			}
		}

		std::cout << "Completed" << std::endl;

	}

}

void KeyGen3(const string &paramDir,  const string &contextID, const string &keyDir1, const string &keyDir2, const string &keyDir3, const string &jointKeyId) {

	for (size_t k = 0; k < SIZE; k++) {

		std::cout << "\nFINAL STAGE OF EVALMULT KEY GENERATION FOR p #" << std::to_string(k + 1) << "\n" << std::endl;

		string ccFileName = "cryptocontext_" + std::to_string(k) + "_" + contextID + ".txt";

		// Deserialize the crypto context

		CryptoContext<DCRTPoly> cc = DeserializeContext(paramDir + "/" + ccFileName);

		const shared_ptr<LPCryptoParameters<DCRTPoly>> cryptoParams = cc->GetCryptoParameters();
		EncodingParams encodingParams = cryptoParams->GetEncodingParams();
		const shared_ptr<ILDCRTParams<BigInteger>> elementParams = cryptoParams->GetElementParams();
		usint m = elementParams->GetCyclotomicOrder();
		PackedEncoding::SetParams(m, encodingParams);

		// Deserialize the eval mult key stage 2

		std::cout << "Deserializing the stage 2 multiplication evaluation key...";

		LPEvalKey<DCRTPoly> em;
		if (Serial::DeserializeFromFile(keyDir2 + "/" + "key-eval-mult-AB-" + jointKeyId + "-" + std::to_string(k) + ".txt", em, SerType::BINARY) == false) {
			cerr << "Could not read multiplication evaluation key" << endl;
			return;
		}

		if (!em) {
			cerr << "Could not deserialize multiplication evaluation key" << endl;
			return;
		}

		std::cout << "Completed" << std::endl;

		// Deserialize the private key

		std::cout << "Deserializing the private key for A...";

		LPPrivateKey<DCRTPoly> sk;
		if (Serial::DeserializeFromFile(keyDir1 + "/" + "key-private-A-" + jointKeyId + "-" + std::to_string(k) + ".txt", sk, SerType::BINARY) == false) {
			cerr << "Could not read private key" << endl;
			return;
		}

		if (!sk) {
			cerr << "Could not deserialize private key" << endl;
			return;
		}

		std::cout << "Completed" << std::endl;

		// Compute stage 3 joint key

		std::cout << "Joint key (s_a + s_b) is transformed into s_a*(s_a + s_b)...";

		auto evalMultAAB = MultiplyEvalKey(em, sk);

		std::cout << "Completed" << std::endl;

		// Deserialize the eval mult key stage 3 (BAB)

		std::cout << "Deserializing the stage 3 multiplication evaluation key for s_b*(s_a + s_b)...";

		LPEvalKey<DCRTPoly> emBAB;
		if (Serial::DeserializeFromFile(keyDir2 + "/" + "key-eval-mult-BAB-" + jointKeyId + "-" + std::to_string(k) + ".txt", emBAB, SerType::BINARY) == false) {
			cerr << "Could not read mulplication evaluation key" << endl;
			return;
		}

		if (!emBAB) {
			cerr << "Could not deserialize multiplication evaluation key" << endl;
			return;
		}

		std::cout << "Completed" << std::endl;

		// Compute final stage 4 eval mult key

		std::cout << "Computing the final evaluation key...";

		auto evalMult4 = AddEvalMultKeys(evalMultAAB, emBAB);
		evalMult4->SetKeyTag(em->GetKeyTag());

		std::cout << "Completed" << std::endl;

		std::cout << "Serializing final multiplication evaluation key...";

		if (evalMult4) {
			if (!Serial::SerializeToFile(keyDir3 + "/" + "key-eval-mult-ABAB-" + jointKeyId + "-" + std::to_string(k) + ".txt", evalMult4, SerType::BINARY)) {
				cerr << "Error writing serialization of multiplication evaluation key to key-eval-mult-ABAB-" + jointKeyId + "-" + std::to_string(k) + ".txt" << endl;
				return;
			}
		}
		else {
			cerr << "Failure in generating multiplication evaluation key" << endl;
		}

		std::cout << "Completed" << std::endl;
	}
}

void TestEvalKeys(const string &paramDir,  const string &contextID, const string &keyDir1, const string &keyDir2, const string &keyDir3, const string &jointKeyId) {

	for (size_t k = 0; k < SIZE; k++) {

		std::cout << "\nTESTING EVAL KEYS FOR p #" << std::to_string(k + 1) << "\n" << std::endl;

		string ccFileName = "cryptocontext_" + std::to_string(k) + "_" + contextID + ".txt";

		// Deserialize the crypto context

		CryptoContext<DCRTPoly> cc = DeserializeContext(paramDir + "/" + ccFileName);

		const shared_ptr<LPCryptoParameters<DCRTPoly>> cryptoParams = cc->GetCryptoParameters();
		EncodingParams encodingParams = cryptoParams->GetEncodingParams();
		const shared_ptr<ILDCRTParams<BigInteger>> elementParams = cryptoParams->GetElementParams();
		usint m = elementParams->GetCyclotomicOrder();
		PackedEncoding::SetParams(m, encodingParams);

		// Deserialize the joint public key

		std::cout << "Deserializing the joint public key...";

		LPPublicKey<DCRTPoly> pk;
		if (Serial::DeserializeFromFile(keyDir2 + "/" + "key-public-J-" + jointKeyId + "-" + std::to_string(k) + ".txt", pk, SerType::BINARY) == false) {
			cerr << "Could not read joint public key" << endl;
			return;
		}

		if (!pk) {
			cerr << "Could not deserialize joint public key" << endl;
			return;
		}

		std::cout << "Completed" << std::endl;

		// Deserialize the eval mult key stage 3

		std::cout << "Deserializing the joint multiplication evaluation key...";

		LPEvalKey<DCRTPoly> em;
		if (Serial::DeserializeFromFile(keyDir3 + "/" + "key-eval-mult-ABAB-" + jointKeyId + "-" + std::to_string(k) + ".txt", em, SerType::BINARY) == false) {
			cerr << "Could not read mulplication evaluation key" << endl;
			return;
		}

		if (!em) {
			cerr << "Could not deserialize multiplication evaluation key" << endl;
			return;
		}

		vector<LPEvalKey<DCRTPoly>> evalMultKeys;
		evalMultKeys.push_back(em);

		cc->InsertEvalMultKey(evalMultKeys);

		std::cout << "Completed" << std::endl;

		// Deserialize the eval sum keys

		std::cout << "Deserializing the summation evaluation keys...";

		std::map<usint, LPEvalKey<DCRTPoly>>	evalSumKeys;

		//const shared_ptr<LPCryptoParameters<DCRTPoly>> cryptoParams = cc.GetCryptoParameters();
		//const EncodingParams encodingParams = cryptoParams->GetEncodingParams();
		//const shared_ptr<ILDCRTParams<BigInteger>> elementParams = cryptoParams->GetElementParams();

		usint batchSize = encodingParams->GetBatchSize();
		usint g = 5;
		//usint m = elementParams->GetCyclotomicOrder();

		std::map<usint, LPEvalKey<DCRTPoly>> evalKeys;

		for (int i = 0; i < floor(log2(batchSize)); i++)
		{

			if(i == floor(log2(batchSize))-1)
				g = m-1;

			LPEvalKey<DCRTPoly> es;
			string tempFileName = keyDir2 + "/" + "key-eval-sum-AB-" + jointKeyId + "-" + std::to_string(k) + "-" + std::to_string(g) + ".txt";
			if (Serial::DeserializeFromFile(tempFileName, es, SerType::BINARY) == false) {
				cerr << "Could not read the evaluation key at index " << g << endl;
				return;
			}

			if (!es) {
				cerr << "Could not deserialize summation evaluation key at index " << g << endl;
				return;
			}

			evalKeys[g] = es;

			g = (g * g) % m;
		}

		cc->InsertEvalSumKey(shared_ptr<std::map<usint, LPEvalKey<DCRTPoly>>>(new std::map<usint, LPEvalKey<DCRTPoly>>(evalKeys)));

		std::cout << "Completed" << std::endl;

		// Deserialize the private key for A

		std::cout << "Deserializing the private key for A...";

		LPPrivateKey<DCRTPoly> skA;
		if (Serial::DeserializeFromFile(keyDir1 + "/" + "key-private-A-" + jointKeyId + "-" + std::to_string(k) + ".txt", skA, SerType::BINARY) == false) {
			cerr << "Could not read private key" << endl;
			return;
		}

		if (!skA) {
			cerr << "Could not deserialize private key" << endl;
			return;
		}

		std::cout << "Completed" << std::endl;

		// Deserialize the private key for B

		std::cout << "Deserializing the private key for B...";

		LPPrivateKey<DCRTPoly> skB;
		if (Serial::DeserializeFromFile(keyDir1 + "/" + "key-private-B-" + jointKeyId + "-" + std::to_string(k) + ".txt", skB, SerType::BINARY) == false) {
			cerr << "Could not read private key" << endl;
			return;
		}

		if (!skB) {
			cerr << "Could not deserialize private key" << endl;
			return;
		}

		std::cout << "Completed" << std::endl;

		// Encrypting

		std::cout << "Encrypting some test data...";

		std::vector<int64_t> vectorOfInts = { 1,2,3,4,5,6,7,8,0,0 };
		Plaintext intArray = cc->MakePackedPlaintext(vectorOfInts);

		std::vector<int64_t> vectorOfInts2 = { 3,2,3,1,5,6,7,8,0,0 };
		Plaintext intArray2 = cc->MakePackedPlaintext(vectorOfInts2);

		auto ciphertext1 = cc->Encrypt(pk, intArray);

		auto ciphertext2 = cc->Encrypt(pk, intArray2);

		std::cout << "Completed" << std::endl;

		std::cout << "Input array1\n" << intArray << std::endl;

		std::cout << "Input array2\n" << intArray2 << std::endl;

		std::cout << "Decrypting input array 1...";

		auto skSum = AddSecretKeys(skA, skB);

		Plaintext intArrayNew;

		cc->Decrypt(skSum, ciphertext1, &intArrayNew);

		std::cout << "Completed" << std::endl;

		std::cout << "Decrypted array = " << intArrayNew->GetPackedValue() << std::endl;

		std::cout << "Computing product of input arrays...";
		
		auto ciphertextMult = cc->EvalMult(ciphertext1, ciphertext2);

		Plaintext intArrayMult;

		std::cout << "Completed" << std::endl;

		std::cout << "Decrypting the result...";

		cc->Decrypt(skSum, ciphertextMult, &intArrayMult);

		std::cout << "Completed" << std::endl;

		std::cout << "Decrypted result = " << intArrayMult << std::endl;

		std::cout << "Computing automorphism of input array 1...";

		Ciphertext<DCRTPoly> p1;

		p1 = cc->EvalAutomorphism(ciphertext1, 5, evalKeys);

		std::cout << "Completed" << std::endl;

		std::cout << "Decrypting the result...";

		Plaintext intArrayAuto;

		cc->Decrypt(skSum, p1, &intArrayAuto);

		std::cout << "Completed" << std::endl;

		std::cout << "Decrypted permuted array - at index " << encodingParams->GetPlaintextGenerator() << "\n" << intArrayAuto->GetPackedValue() << std::endl;


	}
}

void Encrypt(const string &paramDir,  const string &contextID, const string &keyDir2, const string &jointKeyId, const string &ptxtDir, const string &ptxtId, const string &ctxtDir, const string &ctxId) {

	std::vector<string> headers;
	vector<vector<double>> dataColumns;

	std::cout << "\nLOADING THE DATA\n" << std::endl;

	// Read csv file into a two-dimensional vector

	std::cout << "Reading the CSV file " + ptxtDir + "/" + ptxtId + "...";

	ReadCSVFile(ptxtDir + "/" + ptxtId, headers, dataColumns);

	std::cout << "Completed" << std::endl;
	
	uint32_t numHeaders = headers.size();
	
	ofstream myfile;
    myfile.open(ctxtDir + "/lr_data_" + ctxId);
    myfile << to_string(numHeaders) + "\n";
    vector<double> plaintexts = dataColumns[0];
    myfile << to_string(plaintexts.size());
    for(uint32_t i = 0; i < numHeaders; ++i)
	myfile << "\n" + headers[i];
    myfile.close();

	// Transform the data and store in the Packed Encoding format

	std::cout << "Encoding the data...";

	size_t regressors = headers.size();

	for (size_t i = 0; i < headers.size(); i++)
	{
		if (headers[i] == "id")
		{
			regressors--;
		}
		/*
		if ((headers[i] == "id") || (headers[i] == "log.normalized.cost"))
		{
			regressors--;
		}
		 */
	}

	for (size_t k = 0; k < SIZE; k++) {

		std::cout << "\nENCRYPTING DATA p #" << std::to_string(k + 1) << "\n" << std::endl;

		string ccFileName = "cryptocontext_" + std::to_string(k) + "_" + contextID + ".txt";

		// Deserialize the crypto context

		CryptoContext<DCRTPoly> cc = DeserializeContext(paramDir + "/" + ccFileName);

		const shared_ptr<LPCryptoParameters<DCRTPoly>> cryptoParams = cc->GetCryptoParameters();
		EncodingParams encodingParams = cryptoParams->GetEncodingParams();
		const shared_ptr<ILDCRTParams<BigInteger>> elementParams = cryptoParams->GetElementParams();
		usint m = elementParams->GetCyclotomicOrder();
		PackedEncoding::SetParams(m, encodingParams);

		std::cout << "Number of regressors: " << regressors << std::endl;

		auto zeroAlloc = [=]() { return cc->MakePackedPlaintext({0}); };

		Matrix<Plaintext> xP = Matrix<Plaintext>(zeroAlloc, 1, regressors);
		Plaintext yP;

		EncodeData(cc, headers, dataColumns, xP, yP);


		//std::cout << " xp = " << xP(0,0) << std::endl;
		//std::cout << " yp = " << yP << std::endl;

		std::cout << "Completed" << std::endl;


		// Deserialize the joint public key

		std::cout << "Deserializing the joint public key...";

		LPPublicKey<DCRTPoly> pk;
		if (Serial::DeserializeFromFile(keyDir2 + "/" + "key-public-J-" + jointKeyId + "-" + std::to_string(k) + ".txt", pk, SerType::BINARY) == false) {
			cerr << "Could not read joint public key" << endl;
			return;
		}

		if (!pk) {
			cerr << "Could not deserialize joint public key" << endl;
			return;
		}

		std::cout << "Completed" << std::endl;

		// Packing and encryption

		if (xP.GetCols() > 0)
		{

			std::cout << "Batching/encrypting X...";

			shared_ptr<Matrix<RationalCiphertext<DCRTPoly>>> xC = cc->EncryptMatrix(pk, xP);

			std::cout << "Completed" << std::endl;

			//Serialization of X

			std::cout << "Serializing X...";

			if (!Serial::SerializeToFile(ctxtDir + "/" + "ciphertext-x-" + ctxId + "-" + std::to_string(k) + ".txt", xC, SerType::BINARY)) {
				cerr << "Error writing serialization of ciphertext X to " << "ciphertext-x-" + ctxId + "-" + std::to_string(k) + ".txt" << endl;
				return;
			}

			std::cout << "Completed" << std::endl;
		}

		if (yP->GetLength() > 0)
		{

			std::cout << "Batching/encrypting y...";

			Ciphertext<DCRTPoly> yC = cc->Encrypt(pk, yP);

			std::cout << "Completed" << std::endl;

			std::cout << "Serializing y...";

			if (!Serial::SerializeToFile(ctxtDir + "/" + "ciphertext-y-" + ctxId + "-" + std::to_string(k) + ".txt", yC, SerType::BINARY)) {
				cerr << "Error writing serialization of ciphertext y to " << ctxtDir + "/" + "ciphertext-y-" + ctxId + "-" + std::to_string(k) + ".txt" << endl;
				return;
			}

			std::cout << "Completed" << std::endl;

		}

	}

}

void ComputeMultiparty(const string &paramDir,  const string &contextID, const string &keyDir2, const string &keyDir3, const string &jointKeyId,
	const string &ctxt1Dir, const string &ctx1Id, const string &ctxt2Dir, const string &ctx2Id,
	const string &ctxtOutDir, const string &ctxOutId) {

	
    string readFile1 = ctxt1Dir + "/lr_data_" + ctx1Id;
    string readFile2 = ctxt2Dir + "/lr_data_" + ctx2Id;
    cout << "Loading metadata from " << readFile1 << endl;
	
	vector<string> headers;
	
	ifstream myfile1(readFile1);
    string value;
    getline(myfile1, value);
    cout << value << endl;
    uint32_t numHeaders1 = stoi(value);
    cout << "Number of Columns: " << numHeaders1 << endl; // display value removing the first and the last character from it
    getline(myfile1, value, '\n');
    // cout << value << endl;
    uint32_t numRows1 = stoi(value);
    cout << "Number of Rows:" << numRows1 << endl; // display value removing the first and the last character from it
    while(myfile1.good()) {
	getline(
	    myfile1, value, '\n'); // read a string until next comma: http://www.cplusplus.com/reference/string/getline/
	headers.push_back(value);
	// cout << value << endl; // display value removing the first and the last character from it
    }
    myfile1.close();
		
	ifstream myfile2(readFile2);
    getline(myfile2, value);
    cout << value << endl;
    uint32_t numHeaders2 = stoi(value);
    cout << "Number of Columns: " << numHeaders2 << endl; // display value removing the first and the last character from it
    getline(myfile2, value, '\n');
    // cout << value << endl;
    uint32_t numRows2 = stoi(value);
    cout << "Number of Rows:" << numRows2 << endl; // display value removing the first and the last character from it
	getline(
	    myfile2, value, '\n'); // read a string until next comma: http://www.cplusplus.com/reference/string/getline/
    while(myfile2.good()) {
	getline(
	    myfile2, value, '\n'); // read a string until next comma: http://www.cplusplus.com/reference/string/getline/
	headers.push_back(value);
	// cout << value << endl; // display value removing the first and the last character from it
    }
    myfile2.close();
		
	ofstream myfileOut;
    myfileOut.open(ctxtOutDir + "/lr_data_" + ctxOutId);
    myfileOut << to_string(numHeaders1+numHeaders2) + "\n";
    myfileOut << to_string(numRows1);
    for(uint32_t i = 0; i < headers.size(); ++i)
	myfileOut << "\n" + headers[i];
    myfileOut.close();
		
	for (size_t k = 0; k < SIZE; k++) {

		std::cout << "\nMERGING DATA AND COMPUTING X^T X and X^T y FOR p #" << std::to_string(k + 1) << "\n" << std::endl;

		string ccFileName = "cryptocontext_" + std::to_string(k) + "_" + contextID + ".txt";

		// Deserialize the crypto context

		CryptoContext<DCRTPoly> cc = DeserializeContext(paramDir + "/" + ccFileName);

		const shared_ptr<LPCryptoParameters<DCRTPoly>> cryptoParams = cc->GetCryptoParameters();
		EncodingParams encodingParams = cryptoParams->GetEncodingParams();
		const shared_ptr<ILDCRTParams<BigInteger>> elementParams = cryptoParams->GetElementParams();
		usint m = elementParams->GetCyclotomicOrder();
		PackedEncoding::SetParams(m, encodingParams);

		// Deserialize the eval mult key stage 3

		std::cout << "Deserializing the joint multiplication evaluation key...";

		LPEvalKey<DCRTPoly> em;
		if (Serial::DeserializeFromFile(keyDir3 + "/" + "key-eval-mult-ABAB-" + jointKeyId + "-" + std::to_string(k) + ".txt", em, SerType::BINARY) == false) {
			cerr << "Could not read mulplication evaluation key" << endl;
			return;
		}

		if (!em) {
			cerr << "Could not deserialize multiplication evaluation key" << endl;
			return;
		}

		std::vector<LPEvalKey<DCRTPoly>> evalMultKeys;
		evalMultKeys.push_back(em);

		cc->InsertEvalMultKey(evalMultKeys);

		std::cout << "Completed" << std::endl;

		// Deserialize the eval sum keys

		std::cout << "Deserializing the summation evaluation keys...";

		std::map<usint, LPEvalKey<DCRTPoly>>	evalSumKeys;

		//const shared_ptr<LPCryptoParameters<DCRTPoly>> cryptoParams = cc.GetCryptoParameters();
		//const EncodingParams encodingParams = cryptoParams->GetEncodingParams();
		//const shared_ptr<ILDCRTParams<BigInteger>> elementParams = cryptoParams->GetElementParams();

		usint batchSize = encodingParams->GetBatchSize();
		usint g = 5;
		//usint m = elementParams->GetCyclotomicOrder();

		std::map<usint, LPEvalKey<DCRTPoly>> evalKeys;

		for (int i = 0; i < floor(log2(batchSize)); i++)
		{

			if(i == floor(log2(batchSize))-1)
				g = m-1;

			LPEvalKey<DCRTPoly> es;
			string tempFileName = keyDir2 + "/" + "key-eval-sum-AB-" + jointKeyId + "-" + std::to_string(k) + "-" + std::to_string(g) + ".txt";
			if (Serial::DeserializeFromFile(tempFileName, es, SerType::BINARY) == false) {
				cerr << "Could not read the evaluation key at index " << g << endl;
				return;
			}

			if (!es) {
				cerr << "Could not deserialize summation evaluation key at index " << g << endl;
				return;
			}

			evalKeys[g] = es;

			g = (g * g) % m;
		}

		cc->InsertEvalSumKey(shared_ptr<std::map<usint, LPEvalKey<DCRTPoly>>>(new std::map<usint, LPEvalKey<DCRTPoly>>(evalKeys)));

		std::cout << "Completed" << std::endl;


		// Deserialize X for A

		string xFileName = ctxt1Dir + "/" + "ciphertext-x-" + ctx1Id + "-" + std::to_string(k) + ".txt";

		std::cout << "Deserializing row vector X for A...";

		auto zeroAlloc = [=]() { return RationalCiphertext<DCRTPoly>(cc); };

		shared_ptr<Matrix<RationalCiphertext<DCRTPoly>>> xA;
		if ( !Serial::DeserializeFromFile(xFileName, xA, SerType::BINARY) ) {
			cerr << "Could not deserialize ciphertext x" << endl;
			return;
		}
		xA->SetAllocator(zeroAlloc);

		std::cout << "Completed" << std::endl;

		// Deserialize y for A

		Ciphertext<DCRTPoly> y(new CiphertextImpl<DCRTPoly>(cc));

		string yFileName = ctxt1Dir + "/" + "ciphertext-y-" + ctx1Id + "-" + std::to_string(k) + ".txt";

		std::cout << "Trying to deserialize y...";

		if ( !Serial::DeserializeFromFile(yFileName, y, SerType::BINARY) ) {
			cout << "Could not read ciphertext y. Will attempt to extract y from provider B. " << endl;
		}
		else {
			std::cout << "Completed" << std::endl;
		}

		// Deserialize X for B

		xFileName = ctxt2Dir + "/" + "ciphertext-x-" + ctx2Id + "-" + std::to_string(k) + ".txt";

		std::cout << "Deserializing row vector X for B...";

		shared_ptr<Matrix<RationalCiphertext<DCRTPoly>>> xB;
		if ( !Serial::DeserializeFromFile(xFileName, xB, SerType::BINARY) ) {
			cerr << "Could not deserialize ciphertext x" << endl;
			return;
		}
		xA->SetAllocator(zeroAlloc);

		std::cout << "Completed" << std::endl;

		// Deserialize y for A

		if (y->GetElements().size() == 0) {

			string yFileName = ctxt2Dir + "/" + "ciphertext-y-" + ctx2Id + "-" + std::to_string(k) + ".txt";

			std::cout << "Trying to deserialize y...";

			if (!Serial::DeserializeFromFile(yFileName, y, SerType::BINARY) ) {
				cout << "Could not read ciphertext y." << endl;
				return;
			}
			else {
				std::cout << "Completed" << std::endl;
			}
		}

		
		// Merge XA and XB

		std::cout << "Merging X_A and X_B...";

		auto x(new Matrix<RationalCiphertext<DCRTPoly>>(*xA));

		x->HStack(*xB);

		std::cout << "Completed" << std::endl;


		// Compute X^T X

		std::cout << "Computing X^T X...";

		double start, finish;

		shared_ptr<Matrix<RationalCiphertext<DCRTPoly>>> xTx(new Matrix<RationalCiphertext<DCRTPoly>>(zeroAlloc, x->GetCols(), x->GetCols()));

		start = currentDateTime();

		//forces all inner-product precomputations to take place sequentially
		const Ciphertext<DCRTPoly> x0 = (*x)(0, 0).GetNumerator();
		(*xTx)(0, 0).SetNumerator(cc->EvalInnerProduct(x0, x0, encodingParams->GetBatchSize()));

		for (size_t i = 0; i < x->GetCols(); i++)
		{
#pragma omp parallel for			
			for (size_t k = i; k < x->GetCols(); k++)
			{
				if (i + k > 0)
				{
					const Ciphertext<DCRTPoly> xi = (*x)(0, i).GetNumerator();
					const Ciphertext<DCRTPoly> xk = (*x)(0, k).GetNumerator();
					(*xTx)(i, k).SetNumerator(cc->EvalInnerProduct(xi, xk, encodingParams->GetBatchSize()));
					if (i != k)
						(*xTx)(k, i).SetNumerator((*xTx)(i, k).GetNumerator());
				}
			}
		}

		finish = currentDateTime();

		std::cout << "Completed" << std::endl;

		std::cout << "X^T X computation time: " << "\t" << (finish - start) << " ms" << std::endl;

		// Compute X^T y

		std::cout << "Computing X^T y...";

		shared_ptr<Matrix<RationalCiphertext<DCRTPoly>>> xTy(new Matrix<RationalCiphertext<DCRTPoly>>(zeroAlloc, x->GetCols(), 1));

		start = currentDateTime();

#pragma omp parallel for
		for (size_t i = 0; i < x->GetCols(); i++)
		{
			const Ciphertext<DCRTPoly> xi = (*x)(0, i).GetNumerator();
			(*xTy)(i, 0).SetNumerator(cc->EvalInnerProduct(xi, y, encodingParams->GetBatchSize()));
		}

		finish = currentDateTime();

		std::cout << "Completed" << std::endl;

		std::cout << "X^T y computation time: " << "\t" << (finish - start) << " ms" << std::endl;

		// Serialize X^T X

		std::cout << "Serializing X^T X...";

		if (!Serial::SerializeToFile(ctxtOutDir + "/" + "ciphertext-xtx-" + ctxOutId + "-" + std::to_string(k) + ".txt", xTx, SerType::BINARY)) {
			cerr << "Error writing serialization of ciphertext X^T X to " << ctxtOutDir + "/" + "ciphertext-xtx-" + ctxOutId + "-" + std::to_string(k) + ".txt" << endl;
			return;
		}

		std::cout << "Completed" << std::endl;

		// Serialize X^T y

		std::cout << "Serializing X^T y...";

		if (!Serial::SerializeToFile(ctxtOutDir + "/" + "ciphertext-xty-" + ctxOutId + "-" + std::to_string(k) + ".txt", xTy, SerType::BINARY)) {
			cerr << "Error writing serialization of ciphertext X^T y to " << ctxtOutDir + "/" + "ciphertext-xty-" + ctxOutId + "-" + std::to_string(k) + ".txt" << endl;
			return;
		}

		std::cout << "Completed" << std::endl;

	}

}


void TestLR(const string &paramDir,  const string &contextID, const string &keyDir1, const string &jointKeyId, const string &ctxtDir, const string &ctxId) {

	vector<shared_ptr<Matrix<Plaintext>>> xTxCRT;
	vector<shared_ptr<Matrix<Plaintext>>> xTyCRT;

	for (size_t k = 0; k < SIZE; k++) {

		std::cout << "\nTESTING THE DECRYPTION USING S_A + S_B FOR p #" << std::to_string(k + 1) << "\n" << std::endl;

		string ccFileName = "cryptocontext_" + std::to_string(k) + "_" + contextID + ".txt";

		// Deserialize the crypto context

		CryptoContext<DCRTPoly> cc = DeserializeContext(paramDir + "/" + ccFileName);

		const shared_ptr<LPCryptoParameters<DCRTPoly>> cryptoParams = cc->GetCryptoParameters();
		EncodingParams encodingParams = cryptoParams->GetEncodingParams();
		const shared_ptr<ILDCRTParams<BigInteger>> elementParams = cryptoParams->GetElementParams();
		usint m = elementParams->GetCyclotomicOrder();
		PackedEncoding::SetParams(m, encodingParams);

		// Deserialize the private key for A

		std::cout << "Deserializing the private key for A...";

		LPPrivateKey<DCRTPoly> skA;
		if (Serial::DeserializeFromFile(keyDir1 + "/" + "key-private-A-" + jointKeyId + "-" + std::to_string(k) + ".txt", skA, SerType::BINARY) == false) {
			cerr << "Could not read private key" << endl;
			return;
		}

		if (!skA) {
			cerr << "Could not deserialize private key" << endl;
			return;
		}

		std::cout << "Completed" << std::endl;

		// Deserialize the private key for B

		std::cout << "Deserializing the private key for B...";

		LPPrivateKey<DCRTPoly> skB;
		if (Serial::DeserializeFromFile(keyDir1 + "/" + "key-private-B-" + jointKeyId + "-" + std::to_string(k) + ".txt", skB, SerType::BINARY) == false) {
			cerr << "Could not read private key" << endl;
			return;
		}

		if (!skB) {
			cerr << "Could not deserialize private key" << endl;
			return;
		}

		std::cout << "Completed" << std::endl;


		std::cout << "Computing the joint private key S_A + S_B...";

		auto skSum = AddSecretKeys(skA, skB);

		std::cout << "Completed" << std::endl;


		// Deserialize X^T X

		string xtxFileName = ctxtDir + "/" + "ciphertext-xtx-" + ctxId + "-" + std::to_string(k) + ".txt";

		std::cout << "Deserializing matrix X^T X...";

		auto zeroAlloc = [=]() { return RationalCiphertext<DCRTPoly>(cc); };

		shared_ptr<Matrix<RationalCiphertext<DCRTPoly>>> xtx;
		if ( !Serial::DeserializeFromFile(xtxFileName, xtx, SerType::BINARY) ) {
			cerr << "Could not deserialize ciphertext X^T X" << endl;
			return;
		}
		xtx->SetAllocator(zeroAlloc);

		std::cout << "Completed" << std::endl;

		// Decrypt X^T X

		std::cout << "Decrypting matrix X^T X...";

		auto zeroPackingAlloc = [=]() { return cc->MakePackedPlaintext({0}); };


		shared_ptr<Matrix<Plaintext>> numeratorXTX;

		double start, finish;

		start = currentDateTime();

		cc->DecryptMatrixNumerator(skSum, xtx, &numeratorXTX);

		finish = currentDateTime();

		std::cout << "Completed" << std::endl;

		std::cout << "X^T X decryption time: " << "\t" << (finish - start) << " ms" << std::endl;

		xTxCRT.push_back(numeratorXTX);

		//std::cout << numeratorXTX(0, 0)[0] << std::endl;
		//std::cout << numeratorXTX(0, 1)[0] << std::endl;
		//std::cout << numeratorXTX(1, 0)[0] << std::endl;
		//std::cout << numeratorXTX(18, 18)[0] << std::endl;
		
		// Deserialize X^T y

		string xtyFileName = ctxtDir + "/" + "ciphertext-xty-" + ctxId + "-" + std::to_string(k) + ".txt";

		std::cout << "Deserializing matrix X^T y...";

		shared_ptr<Matrix<RationalCiphertext<DCRTPoly>>> xty;

		if ( !Serial::DeserializeFromFile(xtyFileName, xty, SerType::BINARY) ) {
			cerr << "Could not deserialize ciphertext X^T y" << endl;
			return;
		}
		xty->SetAllocator(zeroAlloc);

		std::cout << "Completed" << std::endl;

		// Decrypt X^T y

		std::cout << "Decrypting matrix X^T y...";

		shared_ptr<Matrix<Plaintext>> numeratorXTY;

		start = currentDateTime();

		cc->DecryptMatrixNumerator(skSum, xty, &numeratorXTY);

		finish = currentDateTime();

		std::cout << "Completed" << std::endl;

		std::cout << "X^T y decryption time: " << "\t" << (finish - start) << " ms" << std::endl;

		xTyCRT.push_back(numeratorXTY);

		//std::cout << numeratorXTY(0, 0)[0] << std::endl;
		//std::cout << numeratorXTY(1, 0)[0] << std::endl;
		//std::cout << numeratorXTY(2, 0)[0] << std::endl;
		//std::cout << numeratorXTY(18, 0)[0] << std::endl;

	}

	// Convert back to large plaintext modulus

	std::cout << "\nCLEARTEXT OPERATIONS\n" << std::endl;

	std::cout << "CRT Interpolation to transform to large plainext modulus...";

	shared_ptr<Matrix<NativeInteger>> XTX(new Matrix<NativeInteger>(NativeInteger::Allocator));
	shared_ptr<Matrix<NativeInteger>> XTY(new Matrix<NativeInteger>(NativeInteger::Allocator));

	CRTInterpolate(xTxCRT, *XTX);
	CRTInterpolate(xTyCRT, *XTY);

	std::cout << "Completed" << std::endl;

	std::cout << "XTX(0,0) = " << (*XTX)(0, 0) << std::endl;
	std::cout << "XTX(0,1) = " << (*XTX)(0, 1) << std::endl;
	std::cout << "XTX(1,0) = " << (*XTX)(1, 0) << std::endl;
	std::cout << "XTX(2,2) = " <<  (*XTX)(2, 2) << std::endl;


	for (size_t i = 0; i < 3; i++)
		std::cout << "XTY(" << std::to_string(i) << ",0) = " << (*XTY)(i, 0) << std::endl;

	//Inversion of X^T X

	std::cout << "\nMatrix inversion (in cleartext)...";

	auto zeroAllocDouble = [=]() { return 0.0; };

	shared_ptr<Matrix<double>> XTXInverse(new Matrix<double>(zeroAllocDouble));

	MatrixInverse(*XTX, *XTXInverse);

	std::cout << "Completed" << std::endl;


	for (size_t i = 0; i < 3; i++)
		std::cout << "XTXInverse(0," << std::to_string(i) << ") = " << (*XTXInverse)(0, i) << std::endl;
	std::cout << "XTXInverse(1,0) = " << (*XTXInverse)(1, 0) << std::endl;
	std::cout << "XTXInverse(2,2) = " << (*XTXInverse)(2, 2) << std::endl;

	//Final computation of (X^T X)^{-1} (X^T y)

	std::cout << "\nComputing (X^T X)^{-1} (X^T y) in cleartext...";

	shared_ptr<Matrix<double>> XTYDouble(new Matrix<double>(zeroAllocDouble,XTY->GetRows(),1));

	for (size_t j = 0; j<XTY->GetRows(); j++)
		(*XTYDouble)(j,0) = (*XTY)(j,0).ConvertToDouble();

	Matrix<double> LR = (*XTXInverse)*(*XTYDouble);

	std::cout << "Completed" << std::endl;

	std::cout << "LR(0,0) = " << LR(0, 0) << std::endl;
	std::cout << "LR(1,0) = " << LR(1, 0) << std::endl;
	std::cout << "LR(2,0) = " << LR(2, 0) << std::endl;
	std::cout << "LR(3,0) = " << LR(3, 0) << std::endl;

	std::vector<double> result;

	DecodeData(LR, *XTX, *XTY, result);

	std::cout << "\nFINAL RESULT\n" << std::endl;

	std::cout << result << std::endl;

}

void PartialDecrypt1(const string &paramDir,  const string &contextID, const string &keyDir1, const string &jointKeyId, const string &ctxtInDir,
	const string &ctxInId, const string &ctxtOutDir, const string &ctxOutId) {

	string readFile = ctxtInDir + "/lr_data_" + ctxInId;
    cout << "Loading metadata from " << readFile << endl;

    vector<string> headers;
	
	ifstream myfile(readFile);
    string value;
    getline(myfile, value);
    cout << value << endl;
    uint32_t numHeaders = stoi(value);
    cout << "Number of Columns: " << numHeaders << endl; // display value removing the first and the last character from it
    getline(myfile, value, '\n');
    // cout << value << endl;
    uint32_t numRows = stoi(value);
    cout << "Number of Rows:" << numRows << endl; // display value removing the first and the last character from it
    while(myfile.good()) {
	getline(
	    myfile, value, '\n'); // read a string until next comma: http://www.cplusplus.com/reference/string/getline/
	headers.push_back(value);
	// cout << value << endl; // display value removing the first and the last character from it
    }
    myfile.close();
	
	ofstream myfileOut;
    myfileOut.open(ctxtOutDir + "/lr_data_" + ctxOutId);
    myfileOut << to_string(numHeaders) + "\n";
    myfileOut << to_string(numRows);
    for(uint32_t i = 0; i < headers.size(); ++i)
	myfileOut << "\n" + headers[i];
    myfileOut.close();
	
		
		
	for (size_t k = 0; k < SIZE; k++) {

		std::cout << "\nPARTIAL DECRYPTION FOR PROVIDER A FOR p #" << std::to_string(k + 1) << "\n" << std::endl;

		string ccFileName = "cryptocontext_" + std::to_string(k) + "_" + contextID + ".txt";

		// Deserialize the crypto context

		CryptoContext<DCRTPoly> cc = DeserializeContext(paramDir + "/" + ccFileName);

		const shared_ptr<LPCryptoParameters<DCRTPoly>> cryptoParams = cc->GetCryptoParameters();
		EncodingParams encodingParams = cryptoParams->GetEncodingParams();
		const shared_ptr<ILDCRTParams<BigInteger>> elementParams = cryptoParams->GetElementParams();
		usint m = elementParams->GetCyclotomicOrder();
		PackedEncoding::SetParams(m, encodingParams);

		// Deserialize the private key for A

		std::cout << "Deserializing the private key for A...";

		LPPrivateKey<DCRTPoly> skA;
		if (Serial::DeserializeFromFile(keyDir1 + "/" + "key-private-A-" + jointKeyId + "-" + std::to_string(k) + ".txt", skA, SerType::BINARY) == false) {
			cerr << "Could not read private key" << endl;
			return;
		}

		if (!skA) {
			cerr << "Could not deserialize private key" << endl;
			return;
		}

		std::cout << "Completed" << std::endl;

		// Deserialize X^T X

		string xFileName = ctxtInDir + "/" + "ciphertext-xtx-" + ctxInId + "-" + std::to_string(k) + ".txt";

		std::cout << "Deserializing X^T X...";

		auto zeroAlloc = [=]() { return RationalCiphertext<DCRTPoly>(cc); };

		shared_ptr<Matrix<RationalCiphertext<DCRTPoly>>> xtx(new Matrix<RationalCiphertext<DCRTPoly>>(zeroAlloc));
		if (Serial::DeserializeFromFile(xFileName, xtx, SerType::BINARY) == false) {
			cerr << "Could not read ciphertext X^T X" << endl;
			return;
		}

		xtx->SetAllocator(zeroAlloc);

		std::cout << "Completed" << std::endl;

		// Deserialize X^T y for A

		string yFileName = ctxtInDir + "/" + "ciphertext-xty-" + ctxInId + "-" + std::to_string(k) + ".txt";

		std::cout << "Deserializing X^T y...";

		shared_ptr<Matrix<RationalCiphertext<DCRTPoly>>> xty(new Matrix<RationalCiphertext<DCRTPoly>>(zeroAlloc));

		if (Serial::DeserializeFromFile(yFileName, xty, SerType::BINARY) == false) {
			cout << "Could not read ciphertext X^T y." << endl;
			return;
		}
		xty->SetAllocator(zeroAlloc);

		std::cout << "Completed" << std::endl;

		std::cout << "Partial decryption of X^T X and X^T y...";

		vector<vector<Ciphertext<DCRTPoly>>> vecXTX;
		vector<vector<Ciphertext<DCRTPoly>>> vecXTY;
		vector<vector<Ciphertext<DCRTPoly>>> vecXTXDecrypted;
		vector<vector<Ciphertext<DCRTPoly>>> vecXTYDecrypted;

		ConvertMatrixInto2DVector(*xtx, vecXTX);
		ConvertMatrixInto2DVector(*xty, vecXTY);

		for (size_t i = 0; i < vecXTX.size(); i++) {
			vecXTXDecrypted.push_back(cc->MultipartyDecryptLead(skA, vecXTX[i]));
			vecXTYDecrypted.push_back(cc->MultipartyDecryptLead(skA, vecXTY[i]));
		}

		shared_ptr<Matrix<RationalCiphertext<DCRTPoly>>> xtxDecrypted(new Matrix<RationalCiphertext<DCRTPoly>>(zeroAlloc));
		shared_ptr<Matrix<RationalCiphertext<DCRTPoly>>> xtyDecrypted(new Matrix<RationalCiphertext<DCRTPoly>>(zeroAlloc));

		Convert2DVectorIntoMatrix(vecXTXDecrypted, *xtxDecrypted);
		Convert2DVectorIntoMatrix(vecXTYDecrypted, *xtyDecrypted);

		std::cout << "Completed" << std::endl;

		// Serialize X^T X

		std::cout << "Serializing X^T X...";

		if (!Serial::SerializeToFile(ctxtOutDir + "/" + "ciphertext-xtx-" + ctxOutId + "-" + std::to_string(k) + ".txt", xtxDecrypted, SerType::BINARY)) {
			cerr << "Error writing serialization of ciphertext X^T X to " << ctxtOutDir + "/" + "ciphertext-xtx-" + ctxOutId + "-" + std::to_string(k) + ".txt" << endl;
			return;
		}

		std::cout << "Completed" << std::endl;

		// Serialize X^T y

		std::cout << "Serializing X^T y...";

		if (!Serial::SerializeToFile(ctxtOutDir + "/" + "ciphertext-xty-" + ctxOutId + "-" + std::to_string(k) + ".txt", xtyDecrypted, SerType::BINARY)) {
			cerr << "Error writing serialization of ciphertext X^T y to " << ctxtOutDir + "/" + "ciphertext-xty-" + ctxOutId + "-" + std::to_string(k) + ".txt" << endl;
			return;
		}

		std::cout << "Completed" << std::endl;


	}

}

void PartialDecrypt2(const string &paramDir,  const string &contextID, const string &keyDir1, const string &jointKeyId, const string &ctxtInDir,
	const string &ctxInId, const string &ctxtOutDir, const string &ctxOutId) {

	for (size_t k = 0; k < SIZE; k++) {

		std::cout << "\nPARTIAL DECRYPTION FOR PROVIDER B FOR p #" << std::to_string(k + 1) << "\n" << std::endl;

		string ccFileName = "cryptocontext_" + std::to_string(k) + "_" + contextID + ".txt";

		// Deserialize the crypto context

		CryptoContext<DCRTPoly> cc = DeserializeContext(paramDir + "/" + ccFileName);

		const shared_ptr<LPCryptoParameters<DCRTPoly>> cryptoParams = cc->GetCryptoParameters();
		EncodingParams encodingParams = cryptoParams->GetEncodingParams();
		const shared_ptr<ILDCRTParams<BigInteger>> elementParams = cryptoParams->GetElementParams();
		usint m = elementParams->GetCyclotomicOrder();
		PackedEncoding::SetParams(m, encodingParams);

		// Deserialize the private key for B

		std::cout << "Deserializing the private key for B...";

		LPPrivateKey<DCRTPoly> skB;
		if (Serial::DeserializeFromFile(keyDir1 + "/" + "key-private-B-" + jointKeyId + "-" + std::to_string(k) + ".txt", skB, SerType::BINARY) == false) {
			cerr << "Could not read private key" << endl;
			return;
		}

		if (!skB) {
			cerr << "Could not deserialize private key" << endl;
			return;
		}

		std::cout << "Completed" << std::endl;

		// Deserialize X^T X

		string xFileName = ctxtInDir + "/" + "ciphertext-xtx-" + ctxInId + "-" + std::to_string(k) + ".txt";

		std::cout << "Deserializing X^T X...";

		auto zeroAlloc = [=]() { return RationalCiphertext<DCRTPoly>(cc); };
		shared_ptr<Matrix<RationalCiphertext<DCRTPoly>>> xtx(new Matrix<RationalCiphertext<DCRTPoly>>(zeroAlloc));
		if (Serial::DeserializeFromFile(xFileName, xtx, SerType::BINARY) == false) {
			cerr << "Could not read ciphertext X^T X" << endl;
			return;
		}
		xtx->SetAllocator(zeroAlloc);

		std::cout << "Completed" << std::endl;

		// Deserialize X^T y for A

		string yFileName = ctxtInDir + "/" + "ciphertext-xty-" + ctxInId + "-" + std::to_string(k) + ".txt";

		std::cout << "Deserializing X^T y...";

		shared_ptr<Matrix<RationalCiphertext<DCRTPoly>>> xty(new Matrix<RationalCiphertext<DCRTPoly>>(zeroAlloc));

		if (Serial::DeserializeFromFile(yFileName, xty, SerType::BINARY) == false) {
			cout << "Could not read ciphertext X^T y." << endl;
			return;
		}
		xty->SetAllocator(zeroAlloc);

		std::cout << "Completed" << std::endl;

		std::cout << "Partial decryption of X^T X and X^T y...";

		vector<vector<Ciphertext<DCRTPoly>>> vecXTX;
		vector<vector<Ciphertext<DCRTPoly>>> vecXTY;
		vector<vector<Ciphertext<DCRTPoly>>> vecXTXDecrypted;
		vector<vector<Ciphertext<DCRTPoly>>> vecXTYDecrypted;

		ConvertMatrixInto2DVector(*xtx, vecXTX);
		ConvertMatrixInto2DVector(*xty, vecXTY);

		for (size_t i = 0; i < vecXTX.size(); i++) {
			vecXTXDecrypted.push_back(cc->MultipartyDecryptMain(skB, vecXTX[i]));
			vecXTYDecrypted.push_back(cc->MultipartyDecryptMain(skB, vecXTY[i]));
		}

		shared_ptr<Matrix<RationalCiphertext<DCRTPoly>>> xtxDecrypted(new Matrix<RationalCiphertext<DCRTPoly>>(zeroAlloc));
		shared_ptr<Matrix<RationalCiphertext<DCRTPoly>>> xtyDecrypted(new Matrix<RationalCiphertext<DCRTPoly>>(zeroAlloc));

		Convert2DVectorIntoMatrix(vecXTXDecrypted, *xtxDecrypted);
		Convert2DVectorIntoMatrix(vecXTYDecrypted, *xtyDecrypted);

		std::cout << "Completed" << std::endl;

		// Serialize X^T X

		std::cout << "Serializing X^T X...";

		if (!Serial::SerializeToFile(ctxtOutDir + "/" + "ciphertext-xtx-" + ctxOutId + "-" + std::to_string(k) + ".txt", xtxDecrypted, SerType::BINARY)) {
			cerr << "Error writing serialization of ciphertext X^T X to " << ctxtOutDir + "/" + "ciphertext-xtx-" + ctxOutId + "-" + std::to_string(k) + ".txt" << endl;
			return;
		}

		std::cout << "Completed" << std::endl;

		// Serialize X^T y

		std::cout << "Serializing X^T y...";

		if (!Serial::SerializeToFile(ctxtOutDir + "/" + "ciphertext-xty-" + ctxOutId + "-" + std::to_string(k) + ".txt", xtyDecrypted, SerType::BINARY)) {
			cerr << "Error writing serialization of ciphertext X^T y to " << ctxtOutDir + "/" + "ciphertext-xty-" + ctxOutId + "-" + std::to_string(k) + ".txt" << endl;
			return;
		}

		std::cout << "Completed" << std::endl;
	}
}


void FuseDecode(const string &paramDir, const string &contextID,
	const string &ctxtIn1Dir, const string &ctxIn1Id, const string &ctxtIn2Dir,
	const string &ctxIn2Id, const string &plaintextResultDir, const string &plaintextResultFileName) {

	string readFile = ctxtIn1Dir + "/lr_data_" + ctxIn1Id;
    cout << "Loading metadata from " << readFile << endl;
	
	vector<string> headers;
	
	ifstream myfile(readFile);
    string value;
    getline(myfile, value);
    cout << value << endl;
    uint32_t numHeaders = stoi(value);
    cout << "Number of Columns: " << numHeaders << endl; // display value removing the first and the last character from it
    getline(myfile, value, '\n');
    // cout << value << endl;
    uint32_t numRows = stoi(value);
    cout << "Number of Rows:" << numRows << endl; // display value removing the first and the last character from it
    while(myfile.good()) {
	getline(
	    myfile, value, '\n'); // read a string until next comma: http://www.cplusplus.com/reference/string/getline/
	headers.push_back(value);
	// cout << value << endl; // display value removing the first and the last character from it
    }
    myfile.close();
	
		
	vector<shared_ptr<Matrix<Plaintext>>> xTxCRT;
	vector<shared_ptr<Matrix<Plaintext>>> xTyCRT;

	for (size_t k = 0; k < SIZE; k++) {

		std::cout << "\nPARTIAL DECRYPTION FOR PROVIDER A FOR p #" << std::to_string(k + 1) << "\n" << std::endl;

		string ccFileName = "cryptocontext_" + std::to_string(k) + "_" + contextID + ".txt";

		// Deserialize the crypto context

		CryptoContext<DCRTPoly> cc = DeserializeContext(paramDir + "/" + ccFileName);

		const shared_ptr<LPCryptoParameters<DCRTPoly>> cryptoParams = cc->GetCryptoParameters();
		EncodingParams encodingParams = cryptoParams->GetEncodingParams();
		const shared_ptr<ILDCRTParams<BigInteger>> elementParams = cryptoParams->GetElementParams();
		usint m = elementParams->GetCyclotomicOrder();
		PackedEncoding::SetParams(m, encodingParams);

		// Deserialize X^T X for A

		string xFileName = ctxtIn1Dir + "/" + "ciphertext-xtx-" + ctxIn1Id + "-" + std::to_string(k) + ".txt";

		std::cout << "Deserializing X^T X...";

		auto zeroAlloc = [=]() { return RationalCiphertext<DCRTPoly>(cc); };
		shared_ptr<Matrix<RationalCiphertext<DCRTPoly>>> xtx1(new Matrix<RationalCiphertext<DCRTPoly>>(zeroAlloc));
		if (Serial::DeserializeFromFile(xFileName, xtx1, SerType::BINARY) == false) {
			cerr << "Could not read ciphertext X^T X" << endl;
			return;
		}
		xtx1->SetAllocator(zeroAlloc);

		std::cout << "Completed" << std::endl;

		// Deserialize X^T y for A

		string yFileName = ctxtIn1Dir + "/" + "ciphertext-xty-" + ctxIn1Id + "-" + std::to_string(k) + ".txt";

		std::cout << "Deserializing X^T y...";

		shared_ptr<Matrix<RationalCiphertext<DCRTPoly>>> xty1(new Matrix<RationalCiphertext<DCRTPoly>>(zeroAlloc));

		if (Serial::DeserializeFromFile(yFileName, xty1, SerType::BINARY) == false) {
			cout << "Could not read ciphertext X^T y." << endl;
			return;
		}
		xty1->SetAllocator(zeroAlloc);

		std::cout << "Completed" << std::endl;

		// Deserialize X^T X for B

		xFileName = ctxtIn2Dir + "/" + "ciphertext-xtx-" + ctxIn2Id + "-" + std::to_string(k) + ".txt";

		std::cout << "Deserializing X^T X...";

		shared_ptr<Matrix<RationalCiphertext<DCRTPoly>>> xtx2(new Matrix<RationalCiphertext<DCRTPoly>>(zeroAlloc));
		if (Serial::DeserializeFromFile(xFileName, xtx2, SerType::BINARY) == false) {
			cerr << "Could not read ciphertext X^T X" << endl;
			return;
		}
		xtx2->SetAllocator(zeroAlloc);

		std::cout << "Completed" << std::endl;

		// Deserialize X^T y for B

		yFileName = ctxtIn2Dir + "/" + "ciphertext-xty-" + ctxIn2Id + "-" + std::to_string(k) + ".txt";

		std::cout << "Deserializing X^T y...";

		shared_ptr<Matrix<RationalCiphertext<DCRTPoly>>> xty2(new Matrix<RationalCiphertext<DCRTPoly>>(zeroAlloc));

		if (Serial::DeserializeFromFile(yFileName, xty2, SerType::BINARY) == false) {
			cout << "Could not read ciphertext X^T y." << endl;
			return;
		}
		xty2->SetAllocator(zeroAlloc);

		std::cout << "Completed" << std::endl;

		std::cout << "Fusion of partial decryptions of X^T X and X^T y...";

		auto zeroAllocPlain = [=]() { return cc->MakePackedPlaintext({0}); };

		shared_ptr<Matrix<Plaintext>> xtxPlain(new Matrix<Plaintext>(zeroAllocPlain, xtx1->GetRows(),xtx1->GetCols()));
		shared_ptr<Matrix<Plaintext>> xtyPlain(new Matrix<Plaintext>(zeroAllocPlain, xty1->GetRows(),xty1->GetCols()));

		for (size_t i = 0; i < xtx1->GetRows(); i++) {
			for (size_t j = 0; j < xtx1->GetCols(); j++) {

				vector<Ciphertext<DCRTPoly>> partialCiphertextVecXTX;
				partialCiphertextVecXTX.push_back( (*xtx1)(i,j).GetNumerator() );
				partialCiphertextVecXTX.push_back( (*xtx2)(i,j).GetNumerator() );

				Plaintext tempxtx;
				cc->MultipartyDecryptFusion(partialCiphertextVecXTX, &tempxtx);

				(*xtxPlain)(i, j) = tempxtx;
			}

		}

		for (size_t i = 0; i < xty1->GetRows(); i++) {

				vector<Ciphertext<DCRTPoly>> partialCiphertextVecXTY;
				partialCiphertextVecXTY.push_back( (*xty1)(i,0).GetNumerator() );
				partialCiphertextVecXTY.push_back( (*xty2)(i,0).GetNumerator() );

				Plaintext tempxty;
				cc->MultipartyDecryptFusion(partialCiphertextVecXTY, &tempxty);

				(*xtyPlain)(i, 0) = tempxty;

		}


		std::cout << "Completed" << std::endl;

		xTxCRT.push_back(xtxPlain);

		xTyCRT.push_back(xtyPlain);
		
	}

	// Convert back to large plaintext modulus

	std::cout << "\nCLEARTEXT OPERATIONS\n" << std::endl;

	std::cout << "CRT Interpolation to transform to large plaintext modulus...";

	shared_ptr<Matrix<NativeInteger>> XTX(new Matrix<NativeInteger>(NativeInteger::Allocator));
	shared_ptr<Matrix<NativeInteger>> XTY(new Matrix<NativeInteger>(NativeInteger::Allocator));

	CRTInterpolate(xTxCRT, *XTX);
	CRTInterpolate(xTyCRT, *XTY);

	std::cout << "Completed" << std::endl;

	std::cout << "XTX(0,0) = " << (*XTX)(0, 0) << std::endl;
	std::cout << "XTX(0,1) = " << (*XTX)(0, 1) << std::endl;
	std::cout << "XTX(1,0) = " << (*XTX)(1, 0) << std::endl;
	std::cout << "XTX(2,2) = " << (*XTX)(2, 2) << std::endl;


	for (size_t i = 0; i < 3; i++)
		std::cout << "XTY(" << std::to_string(i) << ",0) = " << (*XTY)(i, 0) << std::endl;

	//Inversion of X^T X

	std::cout << "\nMatrix inversion (in cleartext)...";

	auto zeroAllocDouble = [=]() { return 0.0; };

	shared_ptr<Matrix<double>> XTXInverse(new Matrix<double>(zeroAllocDouble));

	MatrixInverse(*XTX, *XTXInverse);

	std::cout << "Completed" << std::endl;


	for (size_t i = 0; i < 3; i++)
		std::cout << "XTXInverse(0," << std::to_string(i) << ") = " << (*XTXInverse)(0, i) << std::endl;
	std::cout << "XTXInverse(1,0) = " << (*XTXInverse)(1, 0) << std::endl;
	std::cout << "XTXInverse(2,2) = " << (*XTXInverse)(2, 2) << std::endl;

	//Final computation of (X^T X)^{-1} (X^T y)

	std::cout << "\nComputing (X^T X)^{-1} (X^T y) in cleartext...";

	shared_ptr<Matrix<double>> XTYDouble(new Matrix<double>(zeroAllocDouble, XTY->GetRows(), 1));

	for (size_t j = 0; j<XTY->GetRows(); j++)
		(*XTYDouble)(j, 0) = (*XTY)(j, 0).ConvertToDouble();

	Matrix<double> LR = (*XTXInverse)*(*XTYDouble);

	std::cout << "Completed" << std::endl;

	std::cout << "LR(0,0) = " << LR(0, 0) << std::endl;
	std::cout << "LR(1,0) = " << LR(1, 0) << std::endl;
	std::cout << "LR(2,0) = " << LR(2, 0) << std::endl;
	std::cout << "LR(3,0) = " << LR(3, 0) << std::endl;

	std::vector<double> result;

	DecodeData(LR, *XTX, *XTY, result);

    std::cout << "\nFINAL RESULT\n" << std::endl;
    std::cout << result << std::endl;
	
    std::cout << "/////////////// OLS Linear Regression "<<plaintextResultFileName<<"////////////" << std::endl;
    std::cout << "Total Number of Features: "<< (result.size()-1) << std::endl;
	
	cout << "(Intercept): " + to_string(result[0]) << endl;
    for(uint32_t i = 1; i < result.size(); ++i)
		cout << headers[i+1] + ": " + to_string(result[i]) << endl;
	
	ofstream myfileOut;
    myfileOut.open(plaintextResultDir + "/lr_data_" + plaintextResultFileName);
	
    myfileOut << "/////////////// OLS Linear Regression Output "<<plaintextResultFileName<<"////////////" << "\n";
    myfileOut << "Number of Data Columns: " << to_string(result.size()-1) << "\n";
    myfileOut << "Number of Data Rows: " << to_string(numRows+1) << "\n";
	myfileOut << "(Intercept): " << to_string(result[0]) << "\n";
    for(uint32_t i = 1; i < result.size(); ++i)
	myfileOut << headers[i+1] + ": " + to_string(result[i])  << "\n";
    myfileOut.close();
	

}


CryptoContext<DCRTPoly> DeserializeContext(const string& ccFileName)
{

	std::cout << "Deserializing the crypto context...";

	CryptoContext<DCRTPoly> cc;
	if (Serial::DeserializeFromFile(ccFileName, cc, SerType::BINARY) == false) {
		cerr << "Could not read the cryptocontext file" << endl;
		return 0;
	}

	std::cout << "Completed" << std::endl;

	return cc;
}

void ReadCSVFile(string dataFileName, vector<string>& headers, vector<vector<double> >& dataColumns)
{

	ifstream file(dataFileName);
	string line, value;

	uint32_t cols;

	if (file.good()) {
		getline(file, line);
		cols = std::count(line.begin(), line.end(), ',') + 1;
		//std::cout << "Number of data columns:" << cols << std::endl;
		stringstream ss(line);
		vector<string> result;

		for (uint32_t i = 0; i < cols; i++) {
			string substr;
			getline(ss, substr, ',');
			headers.push_back(substr);
			vector<double> dataCol;
			dataColumns.push_back(dataCol);
		}
	}

	//second line has some text - so we are ignoring this line
	if(file.good())
		getline(file, line);

	while (file.good()) {
		getline(file, line);
		//std::cout << line << std::endl;
		//std::cin.get();
		//terminate if the line has no cols
		if (line.find(",") == std::string::npos)
			break;
		stringstream ss(line);
		for (uint32_t i = 0; i < cols; i++) {
			string substr;
			getline(ss, substr, ',');
			double val = std::stod(substr,nullptr);
			//std::cout << "val = " << val << std::endl;
			//std::cin.get();
			dataColumns[i].push_back(val);
		}
	}

	//std::cout << "Read in data file: " << dataFileName << std::endl;
}

void EncodeData(CryptoContext<DCRTPoly> cc, const std::vector<string> &headers, const vector<vector<double>>& dataColumns,
		Matrix<Plaintext> &x, Plaintext &y) {

	//counter on non-regressors
	size_t counter = 0;
	vector<int64_t> yInts;
	vector<int64_t> xInts;

	// i corresponds to columns
	for (size_t i = 0; i < dataColumns.size(); i++)
	{

		if (headers[i] == "id")
			counter++;
			/*
		if ((headers[i] == "log.normalized.cost") || (headers[i] == "id"))
			counter++;
			*/
		// k corresponds to rows
		for (size_t k = 0; k < dataColumns[i].size(); k++)
		{
			if (headers[i] == "fieldY") {
				yInts.push_back(std::round( (dataColumns[i][k])));
				xInts.push_back(1);
			}
			else if (headers[i] == "id")
				continue;
			else
			{
				uint32_t value = dataColumns[i][k];
				xInts.push_back(value);
			}

		}

		if( xInts.size() ) {
			x(0, i-counter) = cc->MakePackedPlaintext(xInts);
			xInts.clear();
		}
	}

	y = cc->MakePackedPlaintext(yInts);

	//std::cout << x(0, 2) << std::endl;
	//std::cout << x(0, 7) << std::endl;

}

void CRTInterpolate(const vector<shared_ptr<Matrix<Plaintext>>>& crtVector,
		Matrix<NativeInteger>& result)
{

	result.SetSize(crtVector[0]->GetRows(), crtVector[0]->GetCols());

	std::vector<NativeInteger> q = { 40961, 59393 };

	NativeInteger Q(2432796673);

	std::vector<NativeInteger> qInverse;

	for(size_t i = 0; i < crtVector.size(); i++) {

		qInverse.push_back((Q / q[i]).ModInverse(q[i]));
		// std::cout << qInverse[i];
	}

	for(size_t k = 0; k < result.GetRows(); k++) {
		for(size_t j = 0; j < result.GetCols(); j++) {
			NativeInteger value = 0;
			for(size_t i = 0; i < crtVector.size(); i++) {
				NativeInteger tempValue;
				if ((*crtVector[i])(k, j)->GetPackedValue()[0] < 0)
					tempValue = NativeInteger(q[i]-NativeInteger((uint64_t)std::llabs((*crtVector[i])(k, j)->GetPackedValue()[0])));
				else
					tempValue = NativeInteger((*crtVector[i])(k, j)->GetPackedValue()[0]);

				value += ((tempValue * qInverse[i]).Mod(q[i]) * Q / q[i]).Mod(Q);
			}
			result(k, j) = value.Mod(Q);
		}
	}

}

void MatrixInverse(const Matrix<NativeInteger> &in, Matrix<double> &out)
{
	matrix <double> M(in.GetRows(), in.GetCols());

	for (int i = 0; i < M.getactualsize(); i++)  
		for (int j = 0; j<M.getactualsize(); j++)
			M.setvalue(i, j, in(i,j).ConvertToDouble());

	M.invert();

	out.SetSize(in.GetRows(), in.GetCols());

	bool flag;

	for (int i = 0; i < M.getactualsize(); i++)
		for (int j = 0; j<M.getactualsize(); j++)
			M.getvalue(i,j,out(i,j),flag);

}

void DecodeData(const Matrix<double> &lr, const Matrix<NativeInteger>& XTX, const Matrix<NativeInteger>& XTY, std::vector<double> &result)
{	
	//constant term
	/*
	result.push_back(3.32);
	for (size_t k = 1; k < lr.GetRows(); k++)
	{
		result.push_back(lr(k, 0) / 100);
		//result[0] -=  lr(k, 0) / 100 * 14;
	}
	*/
	double n = (XTX(0,0).ConvertToDouble());
	double yMean = ((XTY(0,0).ConvertToDouble()))/n;
	cout << "y Mean: " << yMean << endl;
	result.push_back(yMean);
	
    // constant term
    //result.push_back(0);
    for(size_t k = 1; k < lr.GetRows(); k++) {
	result.push_back(lr(k, 0));
	
	double xMean = ((XTX(0,k).ConvertToDouble()))/n;
	cout << "X"<<k<<" Mean: " << xMean << endl;
	
	result[0] -= result[k] * (xMean);
	}
}

template <class Element>
LPEvalKey<Element> AddEvalKeys(LPEvalKey<Element> evalKey1, LPEvalKey<Element> evalKey2)
{
	LPEvalKey<Element> evalKeySum(new LPEvalKeyRelinImpl<Element>(evalKey1->GetCryptoContext()));

	const std::vector<Element> &a = evalKey1->GetAVector();

	const std::vector<Element> &b1 = evalKey1->GetBVector();
	const std::vector<Element> &b2 = evalKey2->GetBVector();

	std::vector<Element> b;

	for (usint i = 0; i < a.size(); i++)
	{
		b.push_back(b1[i] + b2[i]);
	}

	evalKeySum->SetAVector(std::move(a));

	evalKeySum->SetBVector(std::move(b));

	return evalKeySum;

}

template <class Element>
LPEvalKey<Element> AddEvalMultKeys(LPEvalKey<Element> evalKey1, LPEvalKey<Element> evalKey2)
{
	LPEvalKey<Element> evalKeySum(new LPEvalKeyRelinImpl<Element>(evalKey1->GetCryptoContext()));

	const std::vector<Element> &a1 = evalKey1->GetAVector();
	const std::vector<Element> &a2 = evalKey2->GetAVector();

	const std::vector<Element> &b1 = evalKey1->GetBVector();
	const std::vector<Element> &b2 = evalKey2->GetBVector();

	std::vector<Element> a;
	std::vector<Element> b;

	for (usint i = 0; i < a1.size(); i++)
	{
		a.push_back(a1[i] + a2[i]);
		b.push_back(b1[i] + b2[i]);
	}

	evalKeySum->SetAVector(std::move(a));

	evalKeySum->SetBVector(std::move(b));

	return evalKeySum;

}

template <class Element>
LPEvalKey<Element> MultiplyEvalKey(LPEvalKey<Element> evalKey, LPPrivateKey<Element> sk)
{
	const shared_ptr<LPCryptoParametersBGV<Element>> cryptoParams = std::static_pointer_cast<LPCryptoParametersBGV<Element>>(evalKey->GetCryptoContext()->GetCryptoParameters());
	const typename Element::DggType &dgg = cryptoParams->GetDiscreteGaussianGenerator();
	const shared_ptr<typename Element::Params> elementParams = cryptoParams->GetElementParams();

	auto p = cryptoParams->GetPlaintextModulus();

	LPEvalKey<Element> evalKeyResult(new LPEvalKeyRelinImpl<Element>(evalKey->GetCryptoContext()));

	const std::vector<Element> &a0 = evalKey->GetAVector();
	const std::vector<Element> &b0 = evalKey->GetBVector();

	const Element &s = sk->GetPrivateElement();

	std::vector<Element> a;
	std::vector<Element> b;

	for (usint i = 0; i < a0.size(); i++)
	{
		Element f1(dgg, elementParams, Format::COEFFICIENT);
		f1.SwitchFormat();

		Element f2(dgg, elementParams, Format::COEFFICIENT);
		f2.SwitchFormat();

		a.push_back(a0[i] * s + p*f1);
		b.push_back(b0[i] * s + p*f2);
	}

	evalKeyResult->SetAVector(std::move(a));

	evalKeyResult->SetBVector(std::move(b));

	return evalKeyResult;

}

template <class Element>
LPEvalKey<Element> MultiKeySwitchGen(const LPPrivateKey<Element> originalPrivateKey, const LPPrivateKey<Element> newPrivateKey, 
		const LPEvalKey<DCRTPoly> ek) {

	const shared_ptr<LPCryptoParametersBGV<Element>> cryptoParams = std::dynamic_pointer_cast<LPCryptoParametersBGV<Element>>(originalPrivateKey->GetCryptoParameters());

	const shared_ptr<typename Element::Params> originalKeyParams = cryptoParams->GetElementParams();

	auto p = cryptoParams->GetPlaintextModulus();

	LPEvalKey<Element> keySwitchHintRelin(new LPEvalKeyRelinImpl<Element>(originalPrivateKey->GetCryptoContext()));

	//Getting a reference to the polynomials of new private key.
	const Element &sNew = newPrivateKey->GetPrivateElement();

	//Getting a reference to the polynomials of original private key.
	const Element &s = originalPrivateKey->GetPrivateElement();

	//Getting a refernce to discrete gaussian distribution generator.
	const typename Element::DggType &dgg = cryptoParams->GetDiscreteGaussianGenerator();

	//Relinearization window is used to calculate the base exponent.
	usint relinWindow = cryptoParams->GetRelinWindow();

	//Pushes the powers of base exponent of original key polynomial onto evalKeyElements.
	std::vector<Element> evalKeyElements(s.PowersOfBase(relinWindow));

	//evalKeyElementsGenerated hold the generated noise distribution.
	std::vector<Element> evalKeyElementsGenerated;

	const std::vector<Element> &a = ek->GetAVector();

	for (usint i = 0; i < (evalKeyElements.size()); i++)
	{

		evalKeyElementsGenerated.push_back(a[i]); //alpha's of i

		// Generate a_i * newSK + p * e - PowerOfBase(oldSK)
		Element e(dgg, originalKeyParams, Format::EVALUATION);

		evalKeyElements.at(i) = (a[i]*sNew + p*e) - evalKeyElements.at(i);

	}

	keySwitchHintRelin->SetAVector(std::move(evalKeyElementsGenerated));

	keySwitchHintRelin->SetBVector(std::move(evalKeyElements));

	return keySwitchHintRelin;
}

template <class Element>
shared_ptr<std::map<usint, LPEvalKey<Element>>> MultiEvalAutomorphismKeyGen(const LPPrivateKey<Element> privateKey,
	const shared_ptr<std::map<usint, LPEvalKey<Element>>> eAuto,
	const std::vector<usint> &indexList)
{

	const Element &privateKeyElement = privateKey->GetPrivateElement();

	usint n = privateKeyElement.GetRingDimension();

	LPPrivateKey<Element> tempPrivateKey(new LPPrivateKeyImpl<Element>(privateKey->GetCryptoContext()));

	shared_ptr<std::map<usint, LPEvalKey<Element>>> evalKeys(new std::map<usint, LPEvalKey<Element>>());

	if (indexList.size() > n - 1)
		throw std::runtime_error("size exceeds the ring dimension");
	else {

		for (usint i = 0; i < indexList.size(); i++)
		{
			Element permutedPrivateKeyElement = privateKeyElement.AutomorphismTransform(indexList[i]);

			tempPrivateKey->SetPrivateElement(permutedPrivateKeyElement);

			(*evalKeys)[indexList[i]] = MultiKeySwitchGen(tempPrivateKey, privateKey, eAuto->find(indexList[i])->second);

		}

	}

	return evalKeys;

}

template <class Element>
shared_ptr<std::map<usint, LPEvalKey<Element>>> MultiEvalSumKeyGen(const LPPrivateKey<Element> privateKey,
	const shared_ptr<std::map<usint, LPEvalKey<Element>>> eSum)
{

	const shared_ptr<LPCryptoParameters<Element>> cryptoParams = privateKey->GetCryptoParameters();
	const EncodingParams encodingParams = cryptoParams->GetEncodingParams();
	const shared_ptr<typename Element::Params> elementParams = cryptoParams->GetElementParams();

	usint batchSize = encodingParams->GetBatchSize();
	usint g = 5;
	usint m = elementParams->GetCyclotomicOrder();

	// stores automorphism indices needed for EvalSum
	std::vector<usint> indices;

	for (int i = 0; i < floor(log2(batchSize)); i++)
	{
		if(i == floor(log2(batchSize))-1)
			g = m-1;

		indices.push_back(g);
		g = (g * g) % m;
	}

	return MultiEvalAutomorphismKeyGen(privateKey, eSum, indices);

}

template <class Element>
shared_ptr<std::map<usint, LPEvalKey<Element>>> AddEvalSumKeys(const shared_ptr<std::map<usint, LPEvalKey<Element>>> es1,
	const shared_ptr<std::map<usint, LPEvalKey<Element>>> es2)
{

	shared_ptr<std::map<usint, LPEvalKey<DCRTPoly>>> evalSumKeys(new std::map<usint, LPEvalKey<DCRTPoly>>());

	for (std::map<usint, LPEvalKey<DCRTPoly>>::iterator it = es1->begin(); it != es1->end(); ++it)
	{
		(*evalSumKeys)[it->first] = AddEvalKeys(it->second, es2->find(it->first)->second);
	}

	return evalSumKeys;
}

template <class Element>
LPPrivateKey<Element> AddSecretKeys(LPPrivateKey<Element> a, LPPrivateKey<Element> b) {

	LPPrivateKey<Element> sum(new LPPrivateKeyImpl<Element>(a->GetCryptoContext()));

	sum->SetPrivateElement(a->GetPrivateElement() + b->GetPrivateElement());

	return sum;

}

void ConvertMatrixInto2DVector(const Matrix<RationalCiphertext<DCRTPoly>> &matrix, vector<vector<Ciphertext<DCRTPoly>>> &vec)
{
	vec.clear();

	for (size_t i = 0; i < matrix.GetRows(); i++) {
        std::vector<Ciphertext<DCRTPoly>> temp;
		for (size_t j = 0; j < matrix.GetCols(); j++)
		{
			temp.push_back(matrix(i, j).GetNumerator());
		}
        vec.push_back(temp);
	}
}

void Convert2DVectorIntoMatrix(const vector<vector<Ciphertext<DCRTPoly>>> &vector, Matrix<RationalCiphertext<DCRTPoly>> &matrix) {

	matrix.SetSize(vector.size(), vector[0].size());

	for (size_t i = 0; i < vector.size(); i++) {
		for (size_t j = 0; j < vector[0].size(); j++)
		{
			matrix(i, j).SetNumerator(vector[i][j]);
		}
	}

}
