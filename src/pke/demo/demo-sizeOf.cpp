#include "palisade.h"
#include <typeinfo>

using namespace std;
using namespace lbcrypto;

	int main() {
    //Generate parameters.
	double diff, start, finish;

	int plaintextModulus = 256;
	double sigma = 4;
	double rootHermiteFactor = 1.006;

	//Set Crypto Parameters
	CryptoContext<DCRTPoly> cryptoContext1 = CryptoContextFactory<DCRTPoly>::genCryptoContextBFVrns(
			plaintextModulus, rootHermiteFactor, sigma, 5, 0, 0, OPTIMIZED, 6);

    // enable features that you wish to use
	cryptoContext1->Enable(ENCRYPTION);
	cryptoContext1->Enable(SHE);

    // Initialize Public Key Containers
	LPKeyPair<DCRTPoly> keyPair1;

	////////////////////////////////////////////////////////////
	// Perform Key Generation Operation
	////////////////////////////////////////////////////////////

	std::cout << "Running key generation (used for source data)..." << std::endl;

	start = currentDateTime();

	keyPair1 = cryptoContext1->KeyGen();

	//Create evaluation key vector to be used in keyswitching
	cryptoContext1->EvalMultKeysGen(keyPair1.secretKey);

	finish = currentDateTime();
	diff = finish - start;
	cout << "Key generation time: " << "\t" << diff << " ms" << endl;

	if( !keyPair1.good() ) {
		std::cout << "Key generation failed!" << std::endl;
		exit(1);
	}

	////////////////////////////////////////////////////////////
	// Encode source data
	////////////////////////////////////////////////////////////

	std::vector<int64_t> vectorOfInts1 = {5,4,3,2,1,0,5,4,3,2,1,0};

	Plaintext plaintext1 = cryptoContext1->MakeCoefPackedPlaintext(vectorOfInts1);

	////////////////////////////////////////////////////////////
	// Encryption
	////////////////////////////////////////////////////////////


	Ciphertext<DCRTPoly> ciphertext1;

	start = currentDateTime();

	ciphertext1 = cryptoContext1->Encrypt(keyPair1.publicKey, plaintext1);

	finish = currentDateTime();
	diff = finish - start;
	cout << "Encryption time: " << "\t" << diff << " ms" << endl;


    //for(int i=0;i<6;i++) {
        cout << "Size of Plaintext1" << 1 << ": " << sizeof(plaintext1) << endl;
        cout << "Size of Ciphertext1" << 1 << ": " << ciphertext1->SizeOf() << endl;
    //}
	

	//////////////

	//Set Crypto Parameters
	int relWindow = 1;
	CryptoContext<Poly> cryptoContext2 = CryptoContextFactory<Poly>::genCryptoContextBFV(
			plaintextModulus, rootHermiteFactor, relWindow, sigma, 5, 0, 0, OPTIMIZED, 6);

    // enable features that you wish to use
	cryptoContext2->Enable(ENCRYPTION);
	cryptoContext2->Enable(SHE);

    // Initialize Public Key Containers
	LPKeyPair<Poly> keyPair2;

	////////////////////////////////////////////////////////////
	// Perform Key Generation Operation
	////////////////////////////////////////////////////////////

	std::cout << "Running key generation (used for source data)..." << std::endl;

	start = currentDateTime();

	keyPair2 = cryptoContext2->KeyGen();

	//Create evaluation key vector to be used in keyswitching
	cryptoContext2->EvalMultKeysGen(keyPair2.secretKey);

	finish = currentDateTime();
	diff = finish - start;
	cout << "Key generation time: " << "\t" << diff << " ms" << endl;

	if( !keyPair2.good() ) {
		std::cout << "Key generation failed!" << std::endl;
		exit(1);
	}

	////////////////////////////////////////////////////////////
	// Encode source data
	////////////////////////////////////////////////////////////

	std::vector<int64_t> vectorOfInts2 = {5,4,3,2,1,0,5,4,3,2,1,0};

	Plaintext plaintext2 = cryptoContext2->MakeCoefPackedPlaintext(vectorOfInts2);

	////////////////////////////////////////////////////////////
	// Encryption
	////////////////////////////////////////////////////////////


	Ciphertext<Poly> ciphertext2;

	start = currentDateTime();

	ciphertext2 = cryptoContext2->Encrypt(keyPair2.publicKey, plaintext2);

	finish = currentDateTime();
	diff = finish - start;
	cout << "Encryption time: " << "\t" << diff << " ms" << endl;


    //for(int i=0;i<6;i++) {
        cout << "Size of Plaintext2" << 1 << ": " << sizeof(plaintext2) << endl;
        cout << "Size of Ciphertext2" << 1 << ": " << ciphertext2->SizeOf() << endl;
    //}


	//////////////

	//Set Crypto Parameters
	CryptoContext<NativePoly> cryptoContext3 = CryptoContextFactory<NativePoly>::genCryptoContextBFV(
			plaintextModulus, rootHermiteFactor, relWindow, sigma, 5, 0, 0, OPTIMIZED,6);

    // enable features that you wish to use
	cryptoContext3->Enable(ENCRYPTION);
	cryptoContext3->Enable(SHE);

    // Initialize Public Key Containers
	LPKeyPair<NativePoly> keyPair3;

	////////////////////////////////////////////////////////////
	// Perform Key Generation Operation
	////////////////////////////////////////////////////////////

	std::cout << "Running key generation (used for source data)..." << std::endl;

	start = currentDateTime();

	keyPair3 = cryptoContext3->KeyGen();

	//Create evaluation key vector to be used in keyswitching
	cryptoContext3->EvalMultKeysGen(keyPair3.secretKey);

	finish = currentDateTime();
	diff = finish - start;
	cout << "Key generation time: " << "\t" << diff << " ms" << endl;

	if( !keyPair3.good() ) {
		std::cout << "Key generation failed!" << std::endl;
		exit(1);
	}

	////////////////////////////////////////////////////////////
	// Encode source data
	////////////////////////////////////////////////////////////

	std::vector<int64_t> vectorOfInts3 = {5,4,3,2,1,0,5,4,3,2,1,0};

	Plaintext plaintext3 = cryptoContext3->MakeCoefPackedPlaintext(vectorOfInts3);

	////////////////////////////////////////////////////////////
	// Encryption
	////////////////////////////////////////////////////////////


	Ciphertext<NativePoly> ciphertext3;

	start = currentDateTime();

	ciphertext3 = cryptoContext3->Encrypt(keyPair3.publicKey, plaintext3);

	finish = currentDateTime();
	diff = finish - start;
	cout << "Encryption time: " << "\t" << diff << " ms" << endl;


    //for(int i=0;i<6;i++) {
        cout << "Size of Plaintext3" << 1 << ": " << sizeof(plaintext3) << endl;
        cout << "Size of Ciphertext2" << 1 << ": " << ciphertext3->SizeOf() << endl;
    //}

}
