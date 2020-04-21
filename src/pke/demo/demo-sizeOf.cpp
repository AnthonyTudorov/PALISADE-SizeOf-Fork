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
	CryptoContext<DCRTPoly> cryptoContext = CryptoContextFactory<DCRTPoly>::genCryptoContextBFVrns(
			plaintextModulus, rootHermiteFactor, sigma, 0, 5, 0, OPTIMIZED,6);

    // enable features that you wish to use
	cryptoContext->Enable(ENCRYPTION);
	cryptoContext->Enable(SHE);

    // Initialize Public Key Containers
	LPKeyPair<DCRTPoly> keyPair;

	////////////////////////////////////////////////////////////
	// Perform Key Generation Operation
	////////////////////////////////////////////////////////////

	std::cout << "Running key generation (used for source data)..." << std::endl;

	start = currentDateTime();

	keyPair = cryptoContext->KeyGen();

	//Create evaluation key vector to be used in keyswitching
	cryptoContext->EvalMultKeysGen(keyPair.secretKey);

	finish = currentDateTime();
	diff = finish - start;
	cout << "Key generation time: " << "\t" << diff << " ms" << endl;

	if( !keyPair.good() ) {
		std::cout << "Key generation failed!" << std::endl;
		exit(1);
	}

	////////////////////////////////////////////////////////////
	// Encode source data
	////////////////////////////////////////////////////////////

	std::vector<int64_t> vectorOfInts1 = {5,4,3,2,1,0,5,4,3,2,1,0};
	std::vector<int64_t> vectorOfInts2 = {2,0,0,0,0,0,0,0,0,0,0,0};
	std::vector<int64_t> vectorOfInts3 = {2,0,0,0,0,0,0,0,0,0,0,0};
	std::vector<int64_t> vectorOfInts4 = {2,0,0,0,0,0,0,0,0,0,0,0};
	std::vector<int64_t> vectorOfInts5 = {2,0,0,0,0,0,0,0,0,0,0,0};
	std::vector<int64_t> vectorOfInts6 = {1,0,0,0,0,0,0,0,0,0,0,0};

	Plaintext plaintext1 = cryptoContext->MakeCoefPackedPlaintext(vectorOfInts1);
	Plaintext plaintext2 = cryptoContext->MakeCoefPackedPlaintext(vectorOfInts2);
	Plaintext plaintext3 = cryptoContext->MakeCoefPackedPlaintext(vectorOfInts3);
	Plaintext plaintext4 = cryptoContext->MakeCoefPackedPlaintext(vectorOfInts4);
	Plaintext plaintext5 = cryptoContext->MakeCoefPackedPlaintext(vectorOfInts5);
	Plaintext plaintext6 = cryptoContext->MakeCoefPackedPlaintext(vectorOfInts6);

	////////////////////////////////////////////////////////////
	// Encryption
	////////////////////////////////////////////////////////////


	Ciphertext<DCRTPoly> ciphertext1;
	Ciphertext<DCRTPoly> ciphertext2;
	Ciphertext<DCRTPoly> ciphertext3;
	Ciphertext<DCRTPoly> ciphertext4;
	Ciphertext<DCRTPoly> ciphertext5;
	Ciphertext<DCRTPoly> ciphertext6;

	start = currentDateTime();

	ciphertext1 = cryptoContext->Encrypt(keyPair.publicKey, plaintext1);
	ciphertext2 = cryptoContext->Encrypt(keyPair.publicKey, plaintext2);
	ciphertext3 = cryptoContext->Encrypt(keyPair.publicKey, plaintext3);
	ciphertext4 = cryptoContext->Encrypt(keyPair.publicKey, plaintext4);
	ciphertext5 = cryptoContext->Encrypt(keyPair.publicKey, plaintext5);
	ciphertext6 = cryptoContext->Encrypt(keyPair.publicKey, plaintext6);

	finish = currentDateTime();
	diff = finish - start;
	cout << "Encryption time: " << "\t" << diff << " ms" << endl;


    //for(int i=0;i<6;i++) {
        cout << "Size of Plaintext" << 1 << ": " << sizeof(plaintext1) << endl;
        cout << "Size of Ciphertext" << 1 << ": " << sizeof(ciphertext1) << endl;
		int size = 0;
		int num = 0;
		for( auto i: ciphertext1->GetElements()) {
			size += sizeof(i);
			num++;
		}
        cout << "Number of elements: " << num << " Total size of elements: " << size << endl; 

    //}
	
	
}
