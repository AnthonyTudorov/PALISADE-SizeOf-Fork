/*

Single provider linear regression demo

Commands to run the demo:

bin/demo/pke/Temp-lr-ols keygen demoData ccLR keyFileLinReg
bin/demo/pke/Temp-lr-ols encrypt demoData ccLR keyFileLinReg demoData lr-data.csv demoData lr-data
bin/demo/pke/Temp-lr-ols compute demoData ccLR keyFileLinReg demoData lr-data demoData lr-data-result
bin/demo/pke/Temp-lr-ols decrypt demoData ccLR keyFileLinReg demoData lr-data-result demoData lr-data-plaintext-result

FINAL RESULT SHOULD MATCH THE FOLLOWING

[ 4.04444 1.80401 1.80034 -0.000435569 0.533758 0.583101 0.49063 0.542215 3.07148e-005 -0.00043295 0.000183213 0.000224717 -3.4364e-005 0.000354201 -9.17058e-005 -3.47916e-005 0.000129189 -0.000309232 0.000112229 0.000259837 ]
/////////////// OLS Linear Regression lr-data-plaintext-result////////////
Total Number of Features: 19
(Intercept): 4.044438
field2: 1.804011
field3: 1.800341
field4: -0.000436
field5: 0.533758
field6: 0.583101
field7: 0.490630
field8: 0.542215
field9: 0.000031
field10: -0.000433
field11: 0.000183
field12: 0.000225
field13: -0.000034
field14: 0.000354
field15: -0.000092
field16: -0.000035
field17: 0.000129
field18: -0.000309
field19: 0.000112
field20: 0.000260

 */

#include <iostream>
#include <fstream>

#include "palisade.h"

#include "cryptocontexthelper.h"

#include "encoding/encodings.h"

#include "utils/debug.h"
#include "utils/serial.h"
#include <random>

#include "math/nbtheory.h"
#include "math/matrix.h"
#include "math/matrix.cpp"

#include "Temp-matrixinverse.h"

using namespace std;
using namespace lbcrypto;

#include <iterator>

void KeyGen(string keyDir, string contextId, string keyfileName);
void Encrypt(string keyDir,
		string contextId,
		string keyfileName,
		string plaintextDataDir,
		string plaintextDataFileName,
		string ciphertextDataDir,
		string ciphertextDataFileName);
void Compute(string keyDir,
		string contextId,
		string keyFileName,
		string ciphertextDataDir,
		string ciphertextDataFileName,
		string ciphertextResultDir,
		string ciphertextResultFileName);
void Decrypt(string keyDir,
		string contextId,
		string keyfileName,
		string ciphertextResultDir,
		string ciphertextResultFileName,
		string plaintextResultDir,
		string plaintextResultFileName);
CryptoContext<DCRTPoly> DeserializeContext(const string& ccFileName);
CryptoContext<DCRTPoly> DeserializeContextWithEvalKeys(const string& ccFileName, const string& emFileName, const string& esFileName);
void ReadCSVFile(string dataFileName, vector<string>& headers, vector<vector<double> >& dataColumns);
void EncodeData(CryptoContext<DCRTPoly> cc, const vector<vector<double> >& dataColumns,
		Matrix<Plaintext>& x,
		Plaintext* y);
void CRTInterpolate(const vector<shared_ptr<Matrix<Plaintext>>>& crtVector,
		Matrix<NativeInteger>& result);
void MatrixInverse(const Matrix<NativeInteger>& in, Matrix<double>& out, uint32_t numRegressors);
void DecodeData(const Matrix<double>& lr, const Matrix<NativeInteger>& XTX, const Matrix<NativeInteger>& XTY, std::vector<double>& result);

// number of primitive prime plaintext moduli in the CRT representation of plaintext
const size_t SIZE = 2;
const size_t REGRESSORS = 19;

int main(int argc, char* argv[])
{

	if(argc < 2) { // called with no arguments
		std::cout << "Usage is `" << argv[0] << " arg1 ' where: " << std::endl;
		std::cout << "  arg1 can be one of the following: keygen, encrypt, compute, or decrypt" << std::endl;
	}

	if(argc >= 2) {

		if(std::string(argv[1]) == "keygen") {
			string keyDir = string(argv[2]);
			string contextID = string(argv[3]);
			string keyfileName = string(argv[4]);
			KeyGen(keyDir, contextID, keyfileName);
		}
		else {
			//Serial::DisableKeysInSerializedContext();

			if (std::string(argv[1]) == "encrypt") {
				string keyDir = string(argv[2]);
				string contextID = string(argv[3]);
				string keyfileName = string(argv[4]);
				string plaintextDataDir = string(argv[5]);
				string dataFileName = string(argv[6]);
				string ciphertextDataDir = string(argv[7]);
				string ciphertextDataFileName = string(argv[8]);
				Encrypt(keyDir, contextID, keyfileName, plaintextDataDir, dataFileName, ciphertextDataDir, ciphertextDataFileName);
			}
			else if (std::string(argv[1]) == "compute") {
				string keyDir = string(argv[2]);
				string contextID = string(argv[3]);
				string keyfileName = string(argv[4]);
				string ciphertextDataDir = string(argv[5]);
				string ciphertextDataFileName = string(argv[6]);
				string ciphertextResultDir = string(argv[7]);
				string ciphertextResultFileName = string(argv[8]);
				Compute(keyDir,
						contextID,
						keyfileName,
						ciphertextDataDir,
						ciphertextDataFileName,
						ciphertextResultDir,
						ciphertextResultFileName);
			}
			else if (std::string(argv[1]) == "decrypt") {
				string keyDir = string(argv[2]);
				string contextID = string(argv[3]);
				string keyfileName = string(argv[4]);
				string ciphertextResultDir = string(argv[5]);
				string ciphertextResultFileName = string(argv[6]);
				string plaintextResultDir = string(argv[7]);
				string plaintextResultFileName = string(argv[8]);
				Decrypt(keyDir,
						contextID,
						keyfileName,
						ciphertextResultDir,
						ciphertextResultFileName,
						plaintextResultDir,
						plaintextResultFileName);
			}
			else {
				std::cerr << "the argument is invalid";
				return 1;
			}
		}
	}
	// cin.get();

	PackedEncoding::Destroy();

	return 0;
}

void KeyGen(string keyDir, string contextID, string keyfileName)
{

	for(size_t k = 0; k < SIZE; k++) {

		size_t batchSize = 1024;

		usint init_size = 2;
		usint dcrtBits = 57;
		//usint dcrtBitsBig = 57;

		usint m;
		PlaintextModulus p;

		switch(k) {
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

		////////////////////////////////////////////////////////////
		// Key Generation and Serialization
		////////////////////////////////////////////////////////////

		std::cout << "Generating public and private keys...";
		LPKeyPair<DCRTPoly> kp = cc->KeyGen();

		std::cout << "Completed" << std::endl;

		std::cout << "Serializing public and private keys...";

		if(kp.publicKey && kp.secretKey) {
			if(!Serial::SerializeToFile(keyDir+"/"+keyfileName+"-public" + std::to_string(k) + ".txt", kp.publicKey, SerType::BINARY)) {
				cerr << "Error writing serialization of public key to "
						<< keyDir+"/"+keyfileName+"-public" + std::to_string(k) + ".txt" << endl;
				return;
			}

			if(!Serial::SerializeToFile(keyDir+"/"+keyfileName+"-private" + std::to_string(k) + ".txt", kp.secretKey, SerType::BINARY)) {
				cerr << "Error writing serialization of private key to key-private" + std::to_string(k) + ".txt"
						<< endl;
				return;
			}
		} else {
			cerr << "Failure in generating private and public keys" << endl;
		}
		std::cout << "Completed" << std::endl;

		// EvalMultKey

		std::cout << "Generating multiplication evaluation key...";

		cc->EvalMultKeyGen(kp.secretKey);

		std::cout << "Completed" << std::endl;

		// EvalSumKey

		std::cout << "Generating summation evaluation keys...";

		cc->EvalSumKeyGen(kp.secretKey);

		std::cout << "Completed" << std::endl;

		// CryptoContext

		std::cout << "Serializing crypto context...";

		if(!Serial::SerializeToFile(keyDir+"/"+keyfileName+"-cryptocontext_" + std::to_string(k) + "_" + contextID + ".txt", cc, SerType::BINARY)) {
			cerr << "Error writing serialization of the crypto context to cryptotext" + std::to_string(k) + "_" + contextID + ".txt"
					<< endl;
			return;
		}

		std::cout << "Completed" << std::endl;

		std::cout << "Serializing evaluation keys...";

		ofstream emkeyfile(keyDir+"/"+keyfileName+"-cryptocontext_" + std::to_string(k) + "_" + contextID + "_EVALMULT.txt", std::ios::out|std::ios::binary);
		if( emkeyfile.is_open() ) {
			if( cc->SerializeEvalMultKey(emkeyfile, SerType::BINARY) == false ) {
				cerr << "Error writing serialization of the eval mult keys to " + keyfileName+"-cryptocontext_" + std::to_string(k) + "_" + contextID + "_EVALMULT.txt" << endl;
				return;
			}
			emkeyfile.close();
		}
		else {
			cerr << "Error serializing eval mult keys" << endl;
			return;
		}

		ofstream eskeyfile(keyDir+"/"+ keyfileName + "-cryptocontext_" + std::to_string(k) + "_" + contextID + "_EVALSUM.txt", std::ios::out|std::ios::binary);
		if( eskeyfile.is_open() ) {
			if( cc->SerializeEvalSumKey(eskeyfile, SerType::BINARY) == false ) {
				cerr << "Error writing serialization of the eval sum keys to " + keyfileName + "-cryptocontext_" + std::to_string(k) + "_" + contextID + "_EVALSUM.txt" << endl;
				return;
			}
			eskeyfile.close();
		}
		else {
			cerr << "Error serializing eval sum keys" << endl;
			return;
		}

		std::cout << "Completed" << std::endl;
	}
}

void Encrypt(string keyDir,
		string contextID,
		string keyfileName,
		string plaintextDataDir,
		string plaintextDataFileName,
		string ciphertextDataDir,
		string ciphertextDataFileName)
{
	string dataFileName = plaintextDataDir+"/"+plaintextDataFileName;

	std::vector<string> headers;
	vector<vector<double> > dataColumns;

	std::cout << "\nLOADING THE DATA\n" << std::endl;

	// Read csv file into a two-dimensional vector

	std::cout << "Reading the CSV file...";

	ReadCSVFile(dataFileName, headers, dataColumns);
	uint32_t numHeaders = headers.size();

	ofstream myfile;
	myfile.open(ciphertextDataDir + "/lr_data_" + ciphertextDataFileName);
	myfile << to_string(numHeaders) + "\n";
	vector<double> plaintexts = dataColumns[0];
	myfile << to_string(plaintexts.size());
	for(uint32_t i = 0; i < numHeaders; ++i)
		myfile << "\n" + headers[i];
	myfile.close();

	std::cout << "Completed" << std::endl;

	uint32_t numRegressors = numHeaders-1;
	cout<<"Num Headers: " << numHeaders << endl;
	cout<<"Num Regressors: " << numRegressors << endl;
	cout<<"REGRESSORS: " << REGRESSORS << endl;

	// Key deserialization is done here

	for(size_t k = 0; k < SIZE; k++) {

		std::cout << "\nDESERIALIZATION/ENCRYPTION FOR p #" << std::to_string(k + 1) << "\n" << std::endl;

		string ccFileName = keyDir+"/"+keyfileName+"-cryptocontext_" + std::to_string(k) + "_" + contextID + ".txt";
		string pkFileName = keyDir+"/"+keyfileName+"-public" + std::to_string(k) + ".txt";

		// Deserialize the crypto context

		CryptoContext<DCRTPoly> cc = DeserializeContext(ccFileName);

		const shared_ptr<LPCryptoParameters<DCRTPoly>> cryptoParams = cc->GetCryptoParameters();
		EncodingParams encodingParams = cryptoParams->GetEncodingParams();
		const shared_ptr<ILDCRTParams<BigInteger>> elementParams = cryptoParams->GetElementParams();
		usint m = elementParams->GetCyclotomicOrder();
		PackedEncoding::SetParams(m, encodingParams);

		// std::cout << "plaintext modulus = " << cc.GetCryptoParameters()->GetPlaintextModulus() << std::endl;

		// Deserialize the public key

		std::cout << "Deserializing the public key...";

		LPPublicKey<DCRTPoly> pk;
		if(Serial::DeserializeFromFile(pkFileName, pk, SerType::BINARY) == false) {
			cerr << "Could not read public key" << endl;
			return;
		}

		if(!pk) {
			cerr << "Could not deserialize public key" << endl;
			return;
		}

		std::cout << "Completed" << std::endl;

		// Transform the data and store in the Packed Encoding format

		std::cout << "Encoding the data...";

		auto zeroAlloc = [=]() { return cc->MakePackedPlaintext({0}); };

		Matrix<Plaintext> xP = Matrix<Plaintext>(zeroAlloc, 1, numRegressors);
		Plaintext yP;

		EncodeData(cc, dataColumns, xP, &yP);

		// std::cout << " xp = " << xP(0,0) << std::endl;
		// std::cout << " yp = " << yP << std::endl;

		std::cout << "Completed" << std::endl;

		// Packing and encryption

		std::cout << "Batching/encrypting X...";

		shared_ptr<Matrix<RationalCiphertext<DCRTPoly> > > xC = cc->EncryptMatrix(pk, xP);

		std::cout << "Completed" << std::endl;

		std::cout << "Batching/encrypting y...";

		Ciphertext<DCRTPoly> yC = cc->Encrypt(pk, yP);

		std::cout << "Completed" << std::endl;

		// Serialization

		std::cout << "Serializing X...";

		if(!Serial::SerializeToFile(ciphertextDataDir+"/"+ciphertextDataFileName+"-ciphertext-x-" + std::to_string(k) + ".txt", xC, SerType::BINARY)) {
			cerr << "Error writing serialization of ciphertext X to "
					<< ciphertextDataDir+"/"+ciphertextDataFileName+"-ciphertext-x-" + std::to_string(k) + ".txt" << endl;
			return;
		}

		std::cout << "Completed" << std::endl;

		std::cout << "Serializing y...";

		if(!Serial::SerializeToFile(ciphertextDataDir+"/"+ciphertextDataFileName+"-ciphertext-y-" + std::to_string(k) + ".txt", yC, SerType::BINARY)) {
			cerr << "Error writing serialization of ciphertext y to "
					<< ciphertextDataDir+"/"+ciphertextDataFileName+"-ciphertext-y-" + std::to_string(k) + ".txt" << endl;
			return;
		}

		std::cout << "Completed" << std::endl;
	}
}

void Compute(string keyDir,
		string contextID,
		string keyfileName,
		string ciphertextDataDir,
		string ciphertextDataFileName,
		string ciphertextResultDir,
		string ciphertextResultFileName)
{


	string readFile = ciphertextDataDir + "/lr_data_" + ciphertextDataFileName;
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

	uint32_t numRegressors = numHeaders-1;
	cout<<"Num Headers: " << numHeaders << endl;
	cout<<"Num Regressors: " << numRegressors << endl;
	cout<<"REGRESSORS: " << REGRESSORS << endl;

	ofstream myfileOut;
	myfileOut.open(ciphertextResultDir + "/lr_data_" + ciphertextResultFileName);
	myfileOut << to_string(numHeaders) + "\n";
	myfileOut << to_string(numRows);
	for(uint32_t i = 0; i < headers.size(); ++i)
		myfileOut << "\n" + headers[i];
	myfileOut.close();

	for(size_t k = 0; k < SIZE; k++) {

		std::cout << "\nCOMPUTATION FOR p #" << std::to_string(k + 1) << "\n" << std::endl;

		string ccFileName = keyDir+"/"+keyfileName+"-cryptocontext_" + std::to_string(k) + "_" + contextID + ".txt";
		string emFileName = keyDir+"/"+keyfileName+"-cryptocontext_" + std::to_string(k) + "_" + contextID + "_EVALMULT.txt";
		string esFileName = keyDir+"/"+keyfileName+"-cryptocontext_" + std::to_string(k) + "_" + contextID + "_EVALSUM.txt";

		// Deserialize the crypto context

		CryptoContext<DCRTPoly> cc = DeserializeContextWithEvalKeys(ccFileName, emFileName, esFileName);

		const shared_ptr<LPCryptoParameters<DCRTPoly>> cryptoParams = cc->GetCryptoParameters();
		EncodingParams encodingParams = cryptoParams->GetEncodingParams();
		const shared_ptr<ILDCRTParams<BigInteger>> elementParams = cryptoParams->GetElementParams();
		usint m = elementParams->GetCyclotomicOrder();
		PackedEncoding::SetParams(m, encodingParams);

		// Deserialize X

		string xFileName = ciphertextDataDir+"/"+ciphertextDataFileName+"-ciphertext-x-" + std::to_string(k) + ".txt";

		std::cout << "Deserializing row vector X...";

		auto zeroAlloc = [=]() { return RationalCiphertext<DCRTPoly>(cc); };

		shared_ptr<Matrix<RationalCiphertext<DCRTPoly> > > x(new Matrix<RationalCiphertext<DCRTPoly> >(zeroAlloc));

		if(Serial::DeserializeFromFile(xFileName, x, SerType::BINARY) == false) {
			cerr << "Could not read ciphertext X" << endl;
			return;
		}
		x->SetAllocator(zeroAlloc);

		std::cout << "Completed" << std::endl;

		// Deserialize y

		string yFileName = ciphertextDataDir+"/"+ciphertextDataFileName+"-ciphertext-y-" + std::to_string(k) + ".txt";

		std::cout << "Deserializing y...";

		Ciphertext<DCRTPoly> y;
		if(Serial::DeserializeFromFile(yFileName, y, SerType::BINARY) == false) {
			cerr << "Could not read ciphertext y" << endl;
			return;
		}

		std::cout << "Completed" << std::endl;

		// Compute X^T X

		std::cout << "Computing X^T X...";

		double start, finish;

		shared_ptr<Matrix<RationalCiphertext<DCRTPoly> > > xTx(
				new Matrix<RationalCiphertext<DCRTPoly> >(zeroAlloc, numRegressors, numRegressors));

		start = currentDateTime();

		// forces all inner-product precomputations to take place sequentially
		const Ciphertext<DCRTPoly> x0 = (*x)(0, 0).GetNumerator();
		(*xTx)(0, 0).SetNumerator(cc->EvalInnerProduct(x0, x0, encodingParams->GetBatchSize()));

		for(size_t i = 0; i < numRegressors; i++) {
#pragma omp parallel for
			for(size_t k = i; k < numRegressors; k++) {
				if(i + k > 0) {
					const Ciphertext<DCRTPoly> xi = (*x)(0, i).GetNumerator();
					const Ciphertext<DCRTPoly> xk = (*x)(0, k).GetNumerator();
					(*xTx)(i, k).SetNumerator(cc->EvalInnerProduct(xi, xk, encodingParams->GetBatchSize()));
					if(i != k)
						(*xTx)(k, i).SetNumerator((*xTx)(i, k).GetNumerator());
				}
			}
		}

		finish = currentDateTime();

		std::cout << "Completed" << std::endl;

		std::cout << "X^T X computation time: "
				<< "\t" << (finish - start) << " ms" << std::endl;

		// Compute X^T y

		std::cout << "Computing X^T y...";

		shared_ptr<Matrix<RationalCiphertext<DCRTPoly> > > xTy(
				new Matrix<RationalCiphertext<DCRTPoly> >(zeroAlloc, numRegressors, 1));

		start = currentDateTime();

#pragma omp parallel for
		for(size_t i = 0; i < numRegressors; i++) {
			const Ciphertext<DCRTPoly> xi = (*x)(0, i).GetNumerator();
			(*xTy)(i, 0).SetNumerator(cc->EvalInnerProduct(xi, y, encodingParams->GetBatchSize()));
		}

		finish = currentDateTime();

		std::cout << "Completed" << std::endl;

		std::cout << "X^T y computation time: "
				<< "\t" << (finish - start) << " ms" << std::endl;

		// Serialize X^T X

		std::cout << "Serializing X^T X...";

		if(!Serial::SerializeToFile(ciphertextResultDir+"/"+ciphertextResultFileName+"-ciphertext-xtx-" + std::to_string(k) + ".txt", xTx, SerType::BINARY)) {
			cerr << "Error writing serialization of ciphertext X^T X to "
					<< "ciphertext-xtx-" + std::to_string(k) + ".txt" << endl;
			return;
		}

		std::cout << "Completed" << std::endl;

		// Serialize X^T y

		std::cout << "Serializing X^T y...";

		if(!Serial::SerializeToFile(ciphertextResultDir+"/"+ciphertextResultFileName+"-ciphertext-xty-" + std::to_string(k) + ".txt", xTy, SerType::BINARY)) {
			cerr << "Error writing serialization of ciphertext X^T y to "
					<< "ciphertext-xty-" + std::to_string(k) + ".txt" << endl;
			return;
		}

		std::cout << "Completed" << std::endl;
	}
}

void Decrypt(string keyDir,
		string contextID,
		string keyfileName,
		string ciphertextResultDir,
		string ciphertextResultFileName,
		string plaintextResultDir,
		string plaintextResultFileName)
{

	string readFile = ciphertextResultDir + "/lr_data_" + ciphertextResultFileName;
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

	uint32_t numRegressors = numHeaders-1;
	cout<<"Num Headers: " << numHeaders << endl;
	cout<<"Num Regressors: " << numRegressors << endl;
	cout<<"REGRESSORS: " << REGRESSORS << endl;

	vector<shared_ptr<Matrix<Plaintext>>> xTxCRT;
	vector<shared_ptr<Matrix<Plaintext>>> xTyCRT;

	for(size_t k = 0; k < SIZE; k++) {

		std::cout << "\nDESERIALIZATION/DECRYPTION FOR p #" << std::to_string(k + 1) << "\n" << std::endl;

		string ccFileName = keyDir+"/"+keyfileName+"-cryptocontext_" + std::to_string(k) + "_" + contextID + ".txt";
		string skFileName = keyDir+"/"+keyfileName+"-private" + std::to_string(k) + ".txt";

		// Deserialize the crypto context

		CryptoContext<DCRTPoly> cc = DeserializeContext(ccFileName);

		const shared_ptr<LPCryptoParameters<DCRTPoly>> cryptoParams = cc->GetCryptoParameters();
		EncodingParams encodingParams = cryptoParams->GetEncodingParams();
		const shared_ptr<ILDCRTParams<BigInteger>> elementParams = cryptoParams->GetElementParams();
		usint m = elementParams->GetCyclotomicOrder();
		PackedEncoding::SetParams(m, encodingParams);

		// Deserialize the private key

		std::cout << "Deserializing the private key...";

		LPPrivateKey<DCRTPoly> sk;
		if(Serial::DeserializeFromFile(skFileName, sk, SerType::BINARY) == false) {
			cerr << "Could not read private key" << endl;
			return;
		}

		if(!sk) {
			cerr << "Could not deserialize private key" << endl;
			return;
		}

		std::cout << "Completed" << std::endl;

		// Deserialize X^T X

		string xtxFileName = ciphertextResultDir+"/"+ciphertextResultFileName+"-ciphertext-xtx-" + std::to_string(k) + ".txt";

		std::cout << "Deserializing matrix X^T X...";

		auto zeroAlloc = [=]() { return RationalCiphertext<DCRTPoly>(cc); };

		shared_ptr<Matrix<RationalCiphertext<DCRTPoly> > > xtx(new Matrix<RationalCiphertext<DCRTPoly> >(zeroAlloc));

		if(Serial::DeserializeFromFile(xtxFileName, xtx, SerType::BINARY) == false) {
			cerr << "Could not read ciphertext X^T X" << endl;
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

		cc->DecryptMatrixNumerator(sk, xtx, &numeratorXTX);

		finish = currentDateTime();

		std::cout << "Completed" << std::endl;

		std::cout << "X^T X decryption time: "
				<< "\t" << (finish - start) << " ms" << std::endl;

		xTxCRT.push_back(numeratorXTX);

		// std::cout << numeratorXTX(0, 0)[0] << std::endl;
		// std::cout << numeratorXTX(0, 1)[0] << std::endl;
		// std::cout << numeratorXTX(1, 0)[0] << std::endl;
		// std::cout << numeratorXTX(18, 18)[0] << std::endl;

		// Deserialize X^T y

		string xtyFileName = ciphertextResultDir+"/"+ciphertextResultFileName+"-ciphertext-xty-" + std::to_string(k) + ".txt";

		std::cout << "Deserializing matrix X^T y...";

		shared_ptr<Matrix<RationalCiphertext<DCRTPoly> > > xty(new Matrix<RationalCiphertext<DCRTPoly> >(zeroAlloc));
		if(Serial::DeserializeFromFile(xtyFileName, xty, SerType::BINARY) == false) {
			cerr << "Could not read ciphertext X^T y" << endl;
			return;
		}
		xty->SetAllocator(zeroAlloc);

		std::cout << "Completed" << std::endl;

		// Decrypt X^T y

		std::cout << "Decrypting matrix X^T y...";

		shared_ptr<Matrix<Plaintext>> numeratorXTY;

		start = currentDateTime();

		cc->DecryptMatrixNumerator(sk, xty, &numeratorXTY);

		finish = currentDateTime();

		std::cout << "Completed" << std::endl;

		std::cout << "X^T y decryption time: "
				<< "\t" << (finish - start) << " ms" << std::endl;

		xTyCRT.push_back(numeratorXTY);

		// std::cout << numeratorXTY(0, 0)[0] << std::endl;
		// std::cout << numeratorXTY(1, 0)[0] << std::endl;
		// std::cout << numeratorXTY(2, 0)[0] << std::endl;
		// std::cout << numeratorXTY(18, 0)[0] << std::endl;
	}

	// Convert back to large plaintext modulus

	std::cout << "\nCLEARTEXT OPERATIONS\n" << std::endl;

	std::cout << "CRT Interpolation to transform to large plaintext modulus...";

	shared_ptr<Matrix<NativeInteger> > XTX(new Matrix<NativeInteger>(NativeInteger::Allocator));
	shared_ptr<Matrix<NativeInteger> > XTY(new Matrix<NativeInteger>(NativeInteger::Allocator));

	CRTInterpolate(xTxCRT, *XTX);
	CRTInterpolate(xTyCRT, *XTY);

	std::cout << "Completed" << std::endl;

	for(size_t i = 0; i < numRegressors; i++)
		std::cout << "XTX(0,"<<i<<") = " << (*XTX)(0, i) << std::endl;
	//std::cout << "XTX(0,1) = " << (*XTX)(0, 1) << std::endl;
	//std::cout << "XTX(1,0) = " << (*XTX)(1, 0) << std::endl;
	//std::cout << "XTX("<<numRegressors-1<<","<<numRegressors-1<<") = " << (*XTX)(numRegressors-1, numRegressors-1) << std::endl;

	for(size_t i = 0; i < 2; i++)
		std::cout << "XTY(" << std::to_string(i) << ",0) = " << (*XTY)(i, 0) << std::endl;
	std::cout << "XTY("<<numRegressors-1<<",0) = " << (*XTY)(numRegressors-1, 0) << std::endl;

	// Inversion of X^T X

	std::cout << "\nMatrix inversion (in cleartext)...";

	auto zeroAllocDouble = [=]() { return 0.0; };

	shared_ptr<Matrix<double> > XTXInverse(new Matrix<double>(zeroAllocDouble));

	MatrixInverse(*XTX, *XTXInverse, numRegressors);

	std::cout << "Completed" << std::endl;

	for(size_t i = 0; i < 2; i++)
		std::cout << "XTXInverse(0," << std::to_string(i) << ") = " << (*XTXInverse)(0, i) << std::endl;
	std::cout << "XTXInverse(1,0) = " << (*XTXInverse)(1, 0) << std::endl;
	std::cout << "XTXInverse("<<numRegressors-1<<","<<numRegressors-1<<") = " << (*XTXInverse)(numRegressors-1, numRegressors-1) << std::endl;

	// Final computation of (X^T X)^{-1} (X^T y)

	std::cout << "\nComputing (X^T X)^{-1} (X^T y) in cleartext...";

	shared_ptr<Matrix<double> > XTYDouble(new Matrix<double>(zeroAllocDouble, numRegressors, 1));

	for(size_t j = 0; j < XTY->GetRows(); j++)
		(*XTYDouble)(j, 0) = (*XTY)(j, 0).ConvertToDouble();

	Matrix<double> LR = (*XTXInverse) * (*XTYDouble);

	std::cout << "Completed" << std::endl;

	std::cout << "LR(0,0) = " << LR(0, 0) << std::endl;
	std::cout << "LR(1,0) = " << LR(1, 0) << std::endl;
	//std::cout << "LR(2,0) = " << LR(2, 0) << std::endl;
	std::cout << "LR("<<numRegressors-1<<",0) = " << LR(numRegressors-1, 0) << std::endl;

	std::vector<double> result;

	DecodeData(LR,*XTX,*XTY, result);

	std::cout << "\nFINAL RESULT\n" << std::endl;
	std::cout << result << std::endl;

	std::cout << "/////////////// OLS Linear Regression "<<plaintextResultFileName<<"////////////" << std::endl;
	std::cout << "Total Number of Features: "<< (result.size()-1) << std::endl;

	cout << "(Intercept): " + to_string(result[0]) << endl;

	for(uint32_t i = 1; i < result.size(); ++i)
	{
		cout << headers[i+1] + ": " + to_string(result[i]) << endl;
	}

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

CryptoContext<DCRTPoly> DeserializeContext(const string& ccFileName) {

	std::cout << "Deserializing the crypto context...";

	CryptoContext<DCRTPoly> cc;
	if (Serial::DeserializeFromFile(ccFileName, cc, SerType::BINARY) == false) {
		cerr << "Could not read the cryptocontext file" << endl;
		return 0;
	}

	std::cout << "Completed" << std::endl;

	return cc;
}

CryptoContext<DCRTPoly> DeserializeContextWithEvalKeys(const string& ccFileName, const string& emFileName, const string& esFileName) {

	std::cout << "Deserializing the crypto context...";

	CryptoContext<DCRTPoly> cc;
	if (Serial::DeserializeFromFile(ccFileName, cc, SerType::BINARY) == false) {
		cerr << "Could not read the cryptocontext file" << endl;
		return 0;
	}

	std::ifstream emkeys(emFileName, std::ios::in|std::ios::binary);
	if( !emkeys.is_open() ) {
		cerr << "Could not read the eval mult key file " << endl;
		return 0;
	}

	std::ifstream eskeys(esFileName, std::ios::in|std::ios::binary);
	if( !eskeys.is_open() ) {
		cerr << "Could not read the eval sum key file" << endl;
		return 0;
	}

	if( cc->DeserializeEvalMultKey(emkeys, SerType::BINARY) == false ) {
		cerr << "Could not deserialize the eval mult key file" << endl;
		return 0;
	}

	if( cc->DeserializeEvalSumKey(eskeys, SerType::BINARY) == false ) {
		cerr << "Could not deserialize the eval sum key file" << endl;
		return 0;
	}

	emkeys.close();
	eskeys.close();

	std::cout << "Completed" << std::endl;

	return cc;
}


void ReadCSVFile(string dataFileName, vector<string>& headers, vector<vector<double> >& dataColumns)
{

	ifstream file(dataFileName);
	string line, value;

	uint32_t cols;

	if(file.good()) {
		getline(file, line);
		cols = std::count(line.begin(), line.end(), ',') + 1;
		// std::cout << "Number of data columns:" << cols << std::endl;
		stringstream ss(line);
		vector<string> result;

		for(uint32_t i = 0; i < cols; i++) {
			string substr;
			getline(ss, substr, ',');
			headers.push_back(substr);
			vector<double> dataCol;
			dataColumns.push_back(dataCol);
		}
	}

	// second line has some text - so we are ignoring this line
	if(file.good())
		getline(file, line);

	while(file.good()) {
		getline(file, line);
		// std::cout << line << std::endl;
		// std::cin.get();
		// terminate if the line has no cols
		if(line.find(",") == std::string::npos)
			break;
		stringstream ss(line);
		for(uint32_t i = 0; i < cols; i++) {
			string substr;
			getline(ss, substr, ',');
			double val = std::stod(substr, nullptr);
			// std::cout << "val = " << val << std::endl;
			// std::cin.get();
			dataColumns[i].push_back(val);
		}
	}

	// std::cout << "Read in data file: " << dataFileName << std::endl;
}

void EncodeData(CryptoContext<DCRTPoly> cc,
		const vector<vector<double> >& dataColumns,
		Matrix<Plaintext>& x,
		Plaintext* y)
{
	Plaintext ptx;
	vector<vector<int64_t>> xmat;
	vector<int64_t> yvec;

	for(size_t i = 0; i < dataColumns.size(); i++)
		xmat.push_back({});

	// i corresponds to columns
	for(size_t i = 0; i < dataColumns.size(); i++) {
		// k corresponds to rows
		for(size_t k = 0; k < dataColumns[i].size(); k++) {
			switch(i) {
			case 0:
				xmat[i].push_back(1);
				break;

			case 1:
				yvec.push_back(dataColumns[i][k]);
				break;

			default:
				xmat[i - 1].push_back(dataColumns[i][k]);
				break;
			}
		}
	}

	*y = cc->MakePackedPlaintext(yvec);
	for(size_t i=0; i < dataColumns.size()-1; i++ )
		x(0,i) = cc->MakePackedPlaintext(xmat[i]);

	// std::cout << x(0, 2) << std::endl;
	// std::cout << x(0, 7) << std::endl;
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

void MatrixInverse(const Matrix<NativeInteger>& in, Matrix<double>& out, uint32_t numRegressors)
{
	matrix<double> M(numRegressors, numRegressors);

	for(int i = 0; i < M.getactualsize(); i++)
		for(int j = 0; j < M.getactualsize(); j++)
			M.setvalue(i, j, in(i, j).ConvertToDouble());

	M.invert();

	out.SetSize(in.GetRows(), in.GetCols());

	bool flag;

	for(int i = 0; i < M.getactualsize(); i++)
		for(int j = 0; j < M.getactualsize(); j++)
			M.getvalue(i, j, out(i, j), flag);
}

void DecodeData(const Matrix<double>& lr, const Matrix<NativeInteger>& XTX, const Matrix<NativeInteger>& XTY, std::vector<double>& result)
{


	double n = (XTX(0,0).ConvertToDouble());
	double yMean = XTY(0,0).ConvertToDouble()/n;
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

template <typename T> ostream& operator<<(ostream& output, const vector<T>& vector)
{

	output << "[";

	for(unsigned int i = 0; i < vector.size(); i++) {

		if(i > 0) {
			output << ", ";
		}

		output << vector[i];
	}

	output << "]";
	return output;
}
