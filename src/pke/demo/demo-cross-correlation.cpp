/*

Single provider linear regression demo

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

void KeyGen();
void Encrypt();
void Compute();
void Decrypt();
bool DeserializeContext(const string& ccFileName, CryptoContext<DCRTPoly> &cc);
void ReadCSVFile(string dataFileName, vector<string>& headers, vector<vector<double> >& dataColumns);
void EncodeData(const vector<vector<double>>& dataColumns, Matrix<PackedIntPlaintextEncoding> &x, PackedIntPlaintextEncoding &y);
void CRTInterpolate(const std::vector<Matrix<PackedIntPlaintextEncoding>> &crtVector, Matrix<native_int::BigInteger> &result);
void DecodeData(const Matrix<double> &lr, std::vector<double> &result);
template<typename T> ostream& operator<<(ostream& output, const vector<T>& vector);

// number of primitive prime plaintext moduli in the CRT representation of plaintext
const size_t SIZE = 3;
const size_t ROWS = 19;


int main(int argc, char* argv[]) {

	if (argc < 2) { // called with no arguments
		std::cout << "Usage is `" << argv[0] << " arg1 ' where: " << std::endl;
		std::cout << "  arg1 can be one of the following: keygen, encrypt, compute, or decrypt" << std::endl;
	}

	if (argc == 2) {

		if (std::string(argv[1]) == "keygen")
			KeyGen();
		else if (std::string(argv[1]) == "encrypt")
			Encrypt();
		else if (std::string(argv[1]) == "compute")
			Compute();
		else if (std::string(argv[1]) == "decrypt")
			Decrypt();
		else {
			std::cerr << "the argument is invalid";
			return 1;
		}

	}

	//cin.get();

	PackedIntPlaintextEncoding::Destroy();

	return 0;
}


void KeyGen()
{

	for (size_t k = 0; k < SIZE; k++) {

		size_t batchSize = 1024;

#if defined(_MSC_VER)

		usint init_size = 7;
		usint dcrtBits = 12;
		usint dcrtBitsBig = 31;

#else

		usint init_size = 3;
		usint dcrtBits = 23;
		usint dcrtBitsBig = 57;
#endif

		usint m;

		switch (k) {
		case 0:
			m = 1811;
			break;
		case 1:
			m = 1889;
			break;
		case 2:
			m = 1901;
			break;
		case 3:
			m = 1931;
			break;
		}

		usint p = 2 * m + 1;
		BigInteger modulusP(p);

		std::cout << "\nKEY GENERATION AND SERIALIZATION FOR p = " << p << "\n" << std::endl;

		usint mArb = 2 * m;
		usint mNTT = pow(2, ceil(log2(2 * m - 1)));

		// populate the towers for the small modulus

		vector<native_int::BigInteger> init_moduli(init_size);
		vector<native_int::BigInteger> init_rootsOfUnity(init_size);

		native_int::BigInteger q = FirstPrime<native_int::BigInteger>(dcrtBits, mArb);
		init_moduli[0] = q;
		init_rootsOfUnity[0] = RootOfUnity(mArb, init_moduli[0]);

		for (usint i = 1; i < init_size; i++) {
			q = lbcrypto::NextPrime(q, mArb);
			init_moduli[i] = q;
			init_rootsOfUnity[i] = RootOfUnity(mArb, init_moduli[i]);
			//auto cycloPoly = GetCyclotomicPolynomial<native_int::BinaryVector, native_int::BigInteger>(m, q);
			//ChineseRemainderTransformArb<native_int::BigInteger, native_int::BinaryVector>::GetInstance().SetCylotomicPolynomial(cycloPoly, q);
		}

		// populate the towers for the big modulus

		vector<native_int::BigInteger> init_moduli_NTT(init_size);
		vector<native_int::BigInteger> init_rootsOfUnity_NTT(init_size);

		q = FirstPrime<native_int::BigInteger>(dcrtBitsBig, mNTT);
		init_moduli_NTT[0] = q;
		init_rootsOfUnity_NTT[0] = RootOfUnity(mNTT, init_moduli_NTT[0]);

		for (usint i = 1; i < init_size; i++) {
			q = lbcrypto::NextPrime(q, mNTT);
			init_moduli_NTT[i] = q;
			init_rootsOfUnity_NTT[i] = RootOfUnity(mNTT, init_moduli_NTT[i]);
			//auto cycloPoly = GetCyclotomicPolynomial<native_int::BinaryVector, native_int::BigInteger>(m, q);
			//ChineseRemainderTransformArb<native_int::BigInteger, native_int::BinaryVector>::GetInstance().SetCylotomicPolynomial(cycloPoly, q);
		}

		shared_ptr<ILDCRTParams<BigInteger>> paramsDCRT(new ILDCRTParams<BigInteger>(m, init_moduli, init_rootsOfUnity, init_moduli_NTT, init_rootsOfUnity_NTT));

		std::cout << "generated parameters" << std::endl;

		PackedIntPlaintextEncoding::SetParams(modulusP, m);

		std::cout << "setting parameters" << std::endl;

		shared_ptr<EncodingParams> encodingParams(new EncodingParams(modulusP, PackedIntPlaintextEncoding::GetAutomorphismGenerator(modulusP), batchSize));

		float stdDev = 4;

		shared_ptr<CryptoContext<DCRTPoly>> cc = CryptoContextFactory<DCRTPoly>::genCryptoContextBV(paramsDCRT, encodingParams, 24, stdDev);

		cc->Enable(ENCRYPTION);
		cc->Enable(SHE);

		////////////////////////////////////////////////////////////
		//Key Generation and Serialization
		////////////////////////////////////////////////////////////

		std::cout << "Generating public and private keys...";
		LPKeyPair<DCRTPoly> kp = cc->KeyGen();

		std::cout << "Completed" << std::endl;

		std::cout << "Serializing public and private keys...";

		if (kp.publicKey && kp.secretKey) {
			Serialized pubK, privK;

			if (kp.publicKey->Serialize(&pubK)) {
				if (!SerializableHelper::WriteSerializationToFile(pubK, "key-public" + std::to_string(k) + ".txt")) {
					cerr << "Error writing serialization of public key to " << "key-public" + std::to_string(k) + ".txt" << endl;
					return;
				}
			}
			else {
				cerr << "Error serializing public key" << endl;
				return;
			}

			if (kp.secretKey->Serialize(&privK)) {
				if (!SerializableHelper::WriteSerializationToFile(privK, "key-private" + std::to_string(k) + ".txt")) {
					cerr << "Error writing serialization of private key to key-private" + std::to_string(k) + ".txt" << endl;
					return;
				}
			}
			else {
				cerr << "Error serializing private key" << endl;
				return;
			}
		}
		else {
			cerr << "Failure in generating private and public keys" << endl;
		}
		std::cout << "Completed" << std::endl;

		// EvalMultKey

		std::cout << "Generating multiplication evaluation key...";

		cc->EvalMultKeyGen(kp.secretKey);

		std::cout << "Completed" << std::endl;

		const auto evalMultKey = cc->GetEvalMultKey();

		std::cout << "Serializing multiplication evaluation key...";

		if (evalMultKey) {
			Serialized evalKey;

			if (evalMultKey->Serialize(&evalKey)) {
				if (!SerializableHelper::WriteSerializationToFile(evalKey, "key-eval-mult" + std::to_string(k) + ".txt")) {
					cerr << "Error writing serialization of multiplication evaluation key to key-eval-mult" + std::to_string(k) + ".txt" << endl;
					return;
				}
			}
			else {
				cerr << "Error serializing multiplication evaluation key" << endl;
				return;
			}

		}
		else {
			cerr << "Failure in generating multiplication evaluation key" << endl;
		}

		std::cout << "Completed" << std::endl;

		// EvalSumKey

		std::cout << "Generating summation evaluation keys...";

		cc->EvalSumKeyGen(kp.secretKey);

		std::cout << "Completed" << std::endl;

		auto evalSumKeys = cc->GetEvalSumKey();

		std::cout << "Serializing summation evaluation keys...";

		for (std::map<usint, shared_ptr<LPEvalKey<DCRTPoly>>>::iterator it = evalSumKeys.begin(); it != evalSumKeys.end(); ++it)
		{
			if (it->second) {
				Serialized evalKey;

				if (it->second->Serialize(&evalKey)) {
					if (!SerializableHelper::WriteSerializationToFile(evalKey, "key-eval-sum-" + std::to_string(k) + "-" + std::to_string(it->first) + ".txt")) {
						cerr << "Error writing serialization of summation evaluation key to " << "key-eval-sum-" + std::to_string(k) + "-" + std::to_string(it->first) + ".txt" << endl;
						return;
					}
				}
				else {
					cerr << "Error serializing summation evaluation key with index " + std::to_string(it->first) << endl;
					return;
				}

			}
			else {
				cerr << "Failure in generating summation evaluation key with index " + std::to_string(it->first) << endl;
			}
		}

		std::cout << "Completed" << std::endl;

		// CryptoContext

		std::cout << "Serializing crypto context...";

		Serialized ctxt;

		if (cc->Serialize(&ctxt)) {
			if (!SerializableHelper::WriteSerializationToFile(ctxt, "cryptocontext" + std::to_string(k) + ".txt")) {
				cerr << "Error writing serialization of the crypto context to cryptotext" + std::to_string(k) + ".txt" << endl;
				return;
			}
		}
		else {
			cerr << "Error serializing the crypto context" << endl;
			return;
		}

		std::cout << "Completed" << std::endl;

	}

}

void Encrypt() {

	string dataFileName = "data.csv";

	std::vector<string> headers;
	vector<vector<double>> dataColumns;

	std::cout << "\nLOADING THE DATA\n" << std::endl;

	// Read csv file into a two-dimensional vector

	std::cout << "Reading the CSV file...";

	ReadCSVFile(dataFileName, headers, dataColumns);

	std::cout << "Completed" << std::endl;

	// Transform the data and store in the Packed Encoding format

	std::cout << "Encoding the data...";

	auto zeroAlloc = [=]() { return lbcrypto::make_unique<PackedIntPlaintextEncoding>(); };

	Matrix<PackedIntPlaintextEncoding> xP = Matrix<PackedIntPlaintextEncoding>(zeroAlloc, 1, ROWS);
	PackedIntPlaintextEncoding yP;

	EncodeData(dataColumns, xP, yP);

	//std::cout << " xp = " << xP(0,0) << std::endl;
	//std::cout << " yp = " << yP << std::endl;

	std::cout << "Completed" << std::endl;

	// Key deserialization is done here

	for (size_t k = 0; k < SIZE; k++) {

		std::cout << "\nDESERIALIZATION/ENCRYPTION FOR p #" << std::to_string(k + 1) << "\n" << std::endl;

		string ccFileName = "cryptocontext" + std::to_string(k) + ".txt";
		string pkFileName = "key-public" + std::to_string(k) + ".txt";

		// Deserialize the crypto context

		CryptoContext<DCRTPoly> cc;

		if (!DeserializeContext(ccFileName, cc))
			return;

		const shared_ptr<LPCryptoParameters<DCRTPoly>> cryptoParams = cc.GetCryptoParameters();
		const shared_ptr<EncodingParams> encodingParams = cryptoParams->GetEncodingParams();
		const shared_ptr<ILDCRTParams<BigInteger>> elementParams = cryptoParams->GetElementParams();
		;
		usint m = elementParams->GetCyclotomicOrder();

		PackedIntPlaintextEncoding::SetParams(encodingParams->GetPlaintextModulus(), m);

		cc.Enable(ENCRYPTION);
		cc.Enable(SHE);

		//std::cout << "plaintext modulus = " << cc.GetCryptoParameters()->GetPlaintextModulus() << std::endl;

		// Deserialize the public key

		std::cout << "Deserializing the public key...";

		Serialized	pkSer;
		if (SerializableHelper::ReadSerializationFromFile(pkFileName, &pkSer) == false) {
			cerr << "Could not read public key" << endl;
			return;
		}

		shared_ptr<LPPublicKey<DCRTPoly>> pk = cc.deserializePublicKey(pkSer);

		if (!pk) {
			cerr << "Could not deserialize public key" << endl;
			return;
		}

		std::cout << "Completed" << std::endl;

		// Packing and encryption

		std::cout << "Batching/encrypting X...";

		shared_ptr<Matrix<RationalCiphertext<DCRTPoly>>> xC = cc.EncryptMatrix(pk, xP);

		std::cout << "Completed" << std::endl;

		std::cout << "Batching/encrypting Y...";

		std::vector<shared_ptr<Ciphertext<DCRTPoly>>> yC = cc.Encrypt(pk, yP);

		std::cout << "Completed" << std::endl;

		//Serialization

		Serialized ctxtSer;
		ctxtSer.SetObject();

		std::cout << "Serializing X...";

		if (xC->Serialize(&ctxtSer)) {
			if (!SerializableHelper::WriteSerializationToFile(ctxtSer, "ciphertext-x-" + std::to_string(k) + ".txt")) {
				cerr << "Error writing serialization of ciphertext X to " << "ciphertext-x-" + std::to_string(k) + ".txt" << endl;
				return;
			}
		}
		else {
			cerr << "Error serializing ciphertext X" << endl;
			return;
		}

		std::cout << "Completed" << std::endl;

		std::cout << "Serializing y...";

		if (yC[0]->Serialize(&ctxtSer)) {
			if (!SerializableHelper::WriteSerializationToFile(ctxtSer, "ciphertext-y-" + std::to_string(k) + ".txt")) {
				cerr << "Error writing serialization of ciphertext y to " << "ciphertext-y-" + std::to_string(k) + ".txt" << endl;
				return;
			}
		}
		else {
			cerr << "Error serializing ciphertext y" << endl;
			return;
		}

		std::cout << "Completed" << std::endl;

	}


}

void Compute() {

	for (size_t k = 0; k < SIZE; k++) {

		std::cout << "\nCOMPUTATION FOR p #" << std::to_string(k + 1) << "\n" << std::endl;

		string ccFileName = "cryptocontext" + std::to_string(k) + ".txt";
		string emFileName = "key-eval-mult" + std::to_string(k) + ".txt";
		string esFileName = "key-eval-sum-" + std::to_string(k);

		// Deserialize the crypto context

		shared_ptr<CryptoContext<DCRTPoly>> cc;

		if (!DeserializeContext(ccFileName, *cc))
			return;

		const shared_ptr<LPCryptoParameters<DCRTPoly>> cryptoParams = cc->GetCryptoParameters();
		const shared_ptr<EncodingParams> encodingParams = cryptoParams->GetEncodingParams();
		const shared_ptr<ILDCRTParams<BigInteger>> elementParams = cryptoParams->GetElementParams();
		;
		usint m = elementParams->GetCyclotomicOrder();

		PackedIntPlaintextEncoding::SetParams(encodingParams->GetPlaintextModulus(), m);

		cc->Enable(ENCRYPTION);
		cc->Enable(SHE);

		// Deserialize the eval mult key

		std::cout << "Deserializing the multiplication evaluation key...";

		Serialized	emSer;
		if (SerializableHelper::ReadSerializationFromFile(emFileName, &emSer) == false) {
			cerr << "Could not read mulplication evaluation key" << endl;
			return;
		}

		shared_ptr<LPEvalKey<DCRTPoly>> em = cc->deserializeEvalKey(emSer);

		if (!em) {
			cerr << "Could not deserialize multiplication evaluation key" << endl;
			return;
		}

		vector<shared_ptr<LPEvalKey<DCRTPoly>>> evalMultKeys;
		evalMultKeys.push_back(em);

		cc->SetEvalMultKeys(evalMultKeys);

		std::cout << "Completed" << std::endl;


		// Deserialize the eval sum keys

		std::cout << "Deserializing the summation evaluation keys...";

		std::map<usint, shared_ptr<LPEvalKey<DCRTPoly>>>	evalSumKeys;

		//const shared_ptr<LPCryptoParameters<DCRTPoly>> cryptoParams = cc.GetCryptoParameters();
		//const shared_ptr<EncodingParams> encodingParams = cryptoParams->GetEncodingParams();
		//const shared_ptr<ILDCRTParams<BigInteger>> elementParams = cryptoParams->GetElementParams();

		usint batchSize = encodingParams->GetBatchSize();
		usint g = encodingParams->GetPlaintextGenerator();
		//usint m = elementParams->GetCyclotomicOrder();

		std::map<usint, shared_ptr<LPEvalKey<DCRTPoly>>> evalKeys;

		for (int i = 0; i < floor(log2(batchSize)); i++)
		{

			Serialized	esSer;
			string tempFileName = esFileName + "-" + std::to_string(g) + ".txt";
			if (SerializableHelper::ReadSerializationFromFile(tempFileName, &esSer) == false) {
				cerr << "Could not read the evaluation key at index " << g << endl;
				return;
			}

			shared_ptr<LPEvalKey<DCRTPoly>> es = cc->deserializeEvalKey(esSer);

			if (!es) {
				cerr << "Could not deserialize summation evaluation key at index " << g << endl;
				return;
			}

			evalKeys[g] = es;

			g = (g * g) % m;
		}

		cc->SetEvalSumKeys(evalKeys);

		std::cout << "Completed" << std::endl;

		// Deserialize X

		string xFileName = "ciphertext-x-" + std::to_string(k) + ".txt";

		std::cout << "Deserializing row vector X...";

		Serialized	xSer;
		if (SerializableHelper::ReadSerializationFromFile(xFileName, &xSer) == false) {
			cerr << "Could not read ciphertext X" << endl;
			return;
		}

		auto zeroAlloc = [=]() { return lbcrypto::make_unique<RationalCiphertext<DCRTPoly>>(cc); };

		shared_ptr<Matrix<RationalCiphertext<DCRTPoly>>> x(new Matrix<RationalCiphertext<DCRTPoly>>(zeroAlloc));

		if (!x->Deserialize(xSer)) {
			cerr << "Could not deserialize ciphertext x" << endl;
			return;
		}

		std::cout << "Completed" << std::endl;

		// Deserialize y

		string yFileName = "ciphertext-y-" + std::to_string(k) + ".txt";

		std::cout << "Deserializing y...";

		Serialized	ySer;
		if (SerializableHelper::ReadSerializationFromFile(yFileName, &ySer) == false) {
			cerr << "Could not read ciphertext y" << endl;
			return;
		}

		shared_ptr<Ciphertext<DCRTPoly>> y(new Ciphertext<DCRTPoly>(cc));

		if (!y->Deserialize(ySer)) {
			cerr << "Could not deserialize ciphertext y" << endl;
			return;
		}

		std::cout << "Completed" << std::endl;

		// Compute X^T X

		std::cout << "Computing X^T X...";

		double start, finish;

		shared_ptr<Matrix<RationalCiphertext<DCRTPoly>>> xTx(new Matrix<RationalCiphertext<DCRTPoly>>(zeroAlloc, ROWS, ROWS));

		start = currentDateTime();

		//forces all inner-product precomputations to take place sequentially
		const shared_ptr<Ciphertext<DCRTPoly>> x0 = (*x)(0, 0).GetNumerator();
		(*xTx)(0, 0).SetNumerator(*cc->EvalInnerProduct(x0, x0, encodingParams->GetBatchSize()));

		for (size_t i = 0; i < ROWS; i++)
		{
#pragma omp parallel for			
			for (size_t k = i; k < ROWS; k++)
			{
				if (i + k > 0)
				{
					const shared_ptr<Ciphertext<DCRTPoly>> xi = (*x)(0, i).GetNumerator();
					const shared_ptr<Ciphertext<DCRTPoly>> xk = (*x)(0, k).GetNumerator();
					(*xTx)(i, k).SetNumerator(*cc->EvalInnerProduct(xi, xk, encodingParams->GetBatchSize()));
					if (i != k)
						(*xTx)(k, i).SetNumerator(*(*xTx)(i, k).GetNumerator());
				}
			}
		}

		finish = currentDateTime();

		std::cout << "Completed" << std::endl;

		std::cout << "X^T X computation time: " << "\t" << (finish - start) << " ms" << std::endl;

		// Compute X^T y

		std::cout << "Computing X^T Y...";

		shared_ptr<Matrix<RationalCiphertext<DCRTPoly>>> xTy(new Matrix<RationalCiphertext<DCRTPoly>>(zeroAlloc, ROWS, 1));

		start = currentDateTime();

#pragma omp parallel for
		for (size_t i = 0; i < ROWS; i++)
		{
			const shared_ptr<Ciphertext<DCRTPoly>> xi = (*x)(0, i).GetNumerator();
			(*xTy)(i, 0).SetNumerator(*cc->EvalInnerProduct(xi, y, encodingParams->GetBatchSize()));
		}

		finish = currentDateTime();

		std::cout << "Completed" << std::endl;

		std::cout << "X^T y computation time: " << "\t" << (finish - start) << " ms" << std::endl;

		// Serialize X^T X

		Serialized xTxSer;
		xTxSer.SetObject();

		std::cout << "Serializing X^T X...";

		if (xTx->Serialize(&xTxSer)) {
			if (!SerializableHelper::WriteSerializationToFile(xTxSer, "ciphertext-xtx-" + std::to_string(k) + ".txt")) {
				cerr << "Error writing serialization of ciphertext X^T X to " << "ciphertext-xtx-" + std::to_string(k) + ".txt" << endl;
				return;
			}
		}
		else {
			cerr << "Error serializing ciphertext X^T X" << endl;
			return;
		}

		std::cout << "Completed" << std::endl;

		// Serialize X^T y

		Serialized xTySer;
		xTySer.SetObject();

		std::cout << "Serializing X^T y...";

		if (xTy->Serialize(&xTySer)) {
			if (!SerializableHelper::WriteSerializationToFile(xTySer, "ciphertext-xty-" + std::to_string(k) + ".txt")) {
				cerr << "Error writing serialization of ciphertext X^T y to " << "ciphertext-xty-" + std::to_string(k) + ".txt" << endl;
				return;
			}
		}
		else {
			cerr << "Error serializing ciphertext X^T y" << endl;
			return;
		}

		std::cout << "Completed" << std::endl;

	}

}

void Decrypt() {

	std::vector<Matrix<PackedIntPlaintextEncoding>> xTxCRT;
	std::vector<Matrix<PackedIntPlaintextEncoding>> xTyCRT;

	for (size_t k = 0; k < SIZE; k++) {

		std::cout << "\nDESERIALIZATION/DECRYPTION FOR p #" << std::to_string(k + 1) << "\n" << std::endl;

		string ccFileName = "cryptocontext" + std::to_string(k) + ".txt";
		string skFileName = "key-private" + std::to_string(k) + ".txt";

		// Deserialize the crypto context

		shared_ptr<CryptoContext<DCRTPoly>> cc;

		if (!DeserializeContext(ccFileName, *cc))
			return;

		const shared_ptr<LPCryptoParameters<DCRTPoly>> cryptoParams = cc->GetCryptoParameters();
		const shared_ptr<EncodingParams> encodingParams = cryptoParams->GetEncodingParams();
		const shared_ptr<ILDCRTParams<BigInteger>> elementParams = cryptoParams->GetElementParams();
		;
		usint m = elementParams->GetCyclotomicOrder();

		PackedIntPlaintextEncoding::SetParams(encodingParams->GetPlaintextModulus(), m);

		cc->Enable(ENCRYPTION);
		cc->Enable(SHE);

		// Deserialize the private key

		std::cout << "Deserializing the private key...";

		Serialized	skSer;
		if (SerializableHelper::ReadSerializationFromFile(skFileName, &skSer) == false) {
			cerr << "Could not read private key" << endl;
			return;
		}

		shared_ptr<LPPrivateKey<DCRTPoly>> sk = cc->deserializeSecretKey(skSer);

		if (!sk) {
			cerr << "Could not deserialize private key" << endl;
			return;
		}

		std::cout << "Completed" << std::endl;

		// Deserialize X^T X

		string xtxFileName = "ciphertext-xtx-" + std::to_string(k) + ".txt";

		std::cout << "Deserializing matrix X^T X...";

		Serialized	xtxSer;
		if (SerializableHelper::ReadSerializationFromFile(xtxFileName, &xtxSer) == false) {
			cerr << "Could not read ciphertext X^T X" << endl;
			return;
		}

		auto zeroAlloc = [=]() { return lbcrypto::make_unique<RationalCiphertext<DCRTPoly>>(cc); };

		shared_ptr<Matrix<RationalCiphertext<DCRTPoly>>> xtx(new Matrix<RationalCiphertext<DCRTPoly>>(zeroAlloc));

		if (!xtx->Deserialize(xtxSer)) {
			cerr << "Could not deserialize ciphertext X^T X" << endl;
			return;
		}

		std::cout << "Completed" << std::endl;

		// Decrypt X^T X

		std::cout << "Decrypting matrix X^T X...";

		auto zeroPackingAlloc = [=]() { return lbcrypto::make_unique<PackedIntPlaintextEncoding>(); };

		Matrix<PackedIntPlaintextEncoding> numeratorXTX = Matrix<PackedIntPlaintextEncoding>(zeroPackingAlloc, ROWS, ROWS);

		double start, finish;

		start = currentDateTime();

		cc->DecryptMatrixNumerator(sk, xtx, &numeratorXTX);

		finish = currentDateTime();

		std::cout << "Completed" << std::endl;

		std::cout << "X^T X decryption time: " << "\t" << (finish - start) << " ms" << std::endl;

		xTxCRT.push_back(numeratorXTX);

		//std::cout << numeratorXTX(0, 0)[0] << std::endl;
		//std::cout << numeratorXTX(0, 1)[0] << std::endl;
		//std::cout << numeratorXTX(1, 0)[0] << std::endl;
		//std::cout << numeratorXTX(18, 18)[0] << std::endl;

		// Deserialize X^T y

		string xtyFileName = "ciphertext-xty-" + std::to_string(k) + ".txt";

		std::cout << "Deserializing matrix X^T y...";

		Serialized	xtySer;
		if (SerializableHelper::ReadSerializationFromFile(xtyFileName, &xtySer) == false) {
			cerr << "Could not read ciphertext X^T y" << endl;
			return;
		}

		shared_ptr<Matrix<RationalCiphertext<DCRTPoly>>> xty(new Matrix<RationalCiphertext<DCRTPoly>>(zeroAlloc));

		if (!xty->Deserialize(xtySer)) {
			cerr << "Could not deserialize ciphertext X^T y" << endl;
			return;
		}

		std::cout << "Completed" << std::endl;

		// Decrypt X^T y

		std::cout << "Decrypting matrix X^T y...";

		Matrix<PackedIntPlaintextEncoding> numeratorXTY = Matrix<PackedIntPlaintextEncoding>(zeroPackingAlloc, ROWS, 1);

		start = currentDateTime();

		cc->DecryptMatrixNumerator(sk, xty, &numeratorXTY);

		finish = currentDateTime();

		std::cout << "Completed" << std::endl;

		std::cout << "X^T y decryption time: " << "\t" << (finish - start) << " ms" << std::endl;

		xTyCRT.push_back(numeratorXTY);

		//std::cout << numeratorXTY(0, 0)[0] << std::endl;
		//std::cout << numeratorXTY(1, 0)[0] << std::endl;
		//std::cout << numeratorXTY(2, 0)[0] << std::endl;
		//std::cout << numeratorXTY(18, 0)[0] << std::endl;

	}

	auto zeroAlloc64 = [=]() { return lbcrypto::make_unique<native_int::BigInteger>(); };

	// Convert back to large plaintext modulus

	std::cout << "\nCLEARTEXT OPERATIONS\n" << std::endl;

	std::cout << "CRT Interpolation to transform to large plainext modulus...";

	shared_ptr<Matrix<native_int::BigInteger>> XTX(new Matrix<native_int::BigInteger>(zeroAlloc64));
	shared_ptr<Matrix<native_int::BigInteger>> XTY(new Matrix<native_int::BigInteger>(zeroAlloc64));

	CRTInterpolate(xTxCRT, *XTX);
	CRTInterpolate(xTyCRT, *XTY);

	std::cout << "Completed" << std::endl;

	std::cout << "XTX(0,0) = " << (*XTX)(0, 0) << std::endl;
	std::cout << "XTX(0,1) = " << (*XTX)(0, 1) << std::endl;
	std::cout << "XTX(1,0) = " << (*XTX)(1, 0) << std::endl;
	std::cout << "XTX(18,18) = " << (*XTX)(18, 18) << std::endl;


	for (size_t i = 0; i < 3; i++)
		std::cout << "XTY(" << std::to_string(i) << ",0) = " << (*XTY)(i, 0) << std::endl;
	std::cout << "XTY(18,0) = " << (*XTY)(18, 0) << std::endl;

}

bool DeserializeContext(const string& ccFileName, CryptoContext<DCRTPoly> &cc)
{

	std::cout << "Deserializing the crypto context...";

	Serialized	ccSer;
	if (SerializableHelper::ReadSerializationFromFile(ccFileName, &ccSer) == false) {
		cerr << "Could not read the cryptocontext file" << endl;
		return false;
	}

	if (!cc.Deserialize(ccSer)) {
		cerr << "Error deserializing the crypto context" << endl;
		return false;
	}

	std::cout << "Completed" << std::endl;

	return true;
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
	if (file.good())
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
			double val = std::stod(substr, nullptr);
			//std::cout << "val = " << val << std::endl;
			//std::cin.get();
			dataColumns[i].push_back(val);
		}
	}

	//std::cout << "Read in data file: " << dataFileName << std::endl;
}

void EncodeData(const vector<vector<double>>& dataColumns, Matrix<PackedIntPlaintextEncoding> &x, PackedIntPlaintextEncoding &y) {

	// i corresponds to columns
	for (size_t i = 0; i < dataColumns.size(); i++)
	{
		// k corresponds to rows, i.e., patients
		for (size_t k = 0; k < dataColumns[i].size(); k++)
		{
			int32_t value = dataColumns[i][k];
			x(0, i).push_back(value);
		}

	}

}

void CRTInterpolate(const std::vector<Matrix<PackedIntPlaintextEncoding>> &crtVector, Matrix<native_int::BigInteger> &result) {

	result.SetSize(crtVector[0].GetRows(), crtVector[0].GetCols());

	std::vector<native_int::BigInteger> q = { 3623,3779,3803 };

	native_int::BigInteger Q(52068078551);

	std::vector<native_int::BigInteger> qInverse;

	for (size_t i = 0; i < crtVector.size(); i++) {

		qInverse.push_back((Q / q[i]).ModInverse(q[i]));
		//std::cout << qInverse[i];
	}

	for (size_t k = 0; k < result.GetRows(); k++)
	{
		for (size_t j = 0; j < result.GetCols(); j++)
		{
			native_int::BigInteger value = 0;
			for (size_t i = 0; i < crtVector.size(); i++) {
				//std::cout << crtVector[i](k,j)[0] <<std::endl;
				value += ((native_int::BigInteger(crtVector[i](k, j)[0])*qInverse[i]).Mod(q[i])*Q / q[i]).Mod(Q);
			}
			result(k, j) = value.Mod(Q);
		}
	}

}

template<typename T> ostream& operator<<(ostream& output, const vector<T>& vector) {

	output << "[";

	for (unsigned int i = 0; i < vector.size(); i++) {

		if (i > 0) {
			output << ", ";
		}

		output << vector[i];
	}

	output << "]";
	return output;
}