// memory leak tester

#include <iostream>
#include <fstream>
#include <iterator>

#include "../lib/palisade.h"
#include "../lib/palisadespace.h"

#include "../../lib/utils/cryptocontexthelper.h"
#include "../../lib/crypto/cryptocontext.cpp"
#include "../../lib/utils/cryptocontexthelper.cpp"

#include "../../lib/utils/debug.h"

#include "../../lib/utils/serializablehelper.h"
#include "../../lib/encoding/byteplaintextencoding.h"
#include "../../lib/encoding/intplaintextencoding.h"
#include "../../lib/utils/cryptoutility.h"

using namespace std;
using namespace lbcrypto;

void runOneRound(CryptoContext<ILVector2n>& ctx, const BytePlaintextEncoding& plaintext, bool doPadding = true);


int
main(int argc, char *argv[])
{
	string filename = "src/demo/pre/PalisadeCryptoContext.parms";
	string parmset;

	if( argc == 2 )
		filename = string(*++argv);

	std::cout << "Choose parameter set: ";
	CryptoContextHelper<ILVector2n>::printAllParmSetNames(std::cout, filename);

	string input; // = "StSt6";
	std::cin >> input;

	CryptoContext<ILVector2n> ctx = CryptoContextHelper<ILVector2n>::getNewContext(filename, input);
	if( ctx == 0 ) {
		cout << "Error on " << input << endl;
		return 0;
	}

	ctx.Enable(ENCRYPTION);
	ctx.Enable(PRE);

	BytePlaintextEncoding plaintext1("NJIT_CRYPTOGRAPHY_LABORATORY_IS_DEVELOPING_NEW-NTRU_LIKE_PROXY_REENCRYPTION_SCHEME_USING_LATTICE_BASED_CRYPTOGRAPHY_ABCDEFGHIJKL");
	BytePlaintextEncoding plaintext2(
			"1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
			"1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
			"1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
			"1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
			"1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
			"1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
			"1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
			"1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
			"1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
			"1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
			"1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
			"1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
			"1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
			"1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
			"1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
			"1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
			"1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
			"1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
			"1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
			"1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
			"1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
			"1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
			"1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
			"1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
			"1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
			"1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
			"1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
			"1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
			"1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
			"1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
			"1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
			"1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
			"1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
			"1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
			"1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
			"1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
			"1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
			"1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
			"1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
			"1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
			"1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
			"1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
			"1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
			"1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
			"1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
			"1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
			"1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
			"1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
			"1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
			"1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
			"1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
			"1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
			"1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
			"1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
			"1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
			"1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
			"1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
			"1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
			"1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
			"1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
	);

	BytePlaintextEncoding plaintext3 = { 9,0,8,0 };

	BytePlaintextEncoding plaintext4;
	size_t chunksize = plaintext4.GetChunksize(ctx.GetCryptoParameters().GetElementParams().GetCyclotomicOrder(), ctx.GetCryptoParameters().GetPlaintextModulus());

	plaintext4.resize(chunksize,0); // make sure this comes out in 2 chunks

	if( false ) {
		BytePlaintextEncoding ptz = "hello";
		runOneRound(ctx, ptz);
		try {
			runOneRound(ctx, ptz, false);
		} catch (std::logic_error& e) {
			cout << "Exception thrown" << endl;
		}

		ptz.resize(chunksize, 'x');
		runOneRound(ctx, ptz);
		try {
			runOneRound(ctx, ptz, false);
		} catch (std::logic_error& e) {
			cout << "Exception thrown" << endl;
		}

		ptz.resize(chunksize+1, 'x');
		runOneRound(ctx, ptz);
		try {
			runOneRound(ctx, ptz, false);
		} catch (std::logic_error& e) {
			cout << "Exception thrown" << endl;
		}

		return 0;
	}


	bool tryPad = true;
	for( int i=0; i<2; i++ ) {
		cout << "Try padding value: " << tryPad << endl;

		cout << "test 1 - small plaintext" << endl;
		try {
			runOneRound(ctx, plaintext1, tryPad);
		} catch (std::logic_error& e) {
			cout << "Exception thrown: " << e.what() << endl;
		}
		continue;

		cout << "test 2 - large plaintext" << endl;
		try {
			runOneRound(ctx, plaintext2, tryPad);
		} catch (std::logic_error& e) {
			cout << "Exception thrown: " << e.what() << endl;
		}

		cout << "test 3 - very small plaintext" << endl;
		try {
			runOneRound(ctx, plaintext3, tryPad);
		} catch (std::logic_error& e) {
			cout << "Exception thrown: " << e.what() << endl;
		}
		cout << "test 4 - full block of 0s" << endl;
		try {
			runOneRound(ctx, plaintext4, tryPad);
		} catch (std::logic_error& e) {
			cout << "Exception thrown: " << e.what() << endl;
		}

		tryPad = !tryPad;
	}

	ILVector2n::DestroyPreComputedSamples();

	//	ChineseRemainderTransformFTT::GetInstance().Destroy();
	//	NumberTheoreticTransform::GetInstance().Destroy();

	return 0;
}

//////////////////////////////////////////////////////////////////////
//	runOneRound runs one round of:
//		- Generate a key pair.
//		- Encrypt a string of data.
//		- Decrypt the data.
//		- Generate a new key pair.
//		- Generate a proxy re-encryption key.
//		- Re-Encrypt the encrypted data.
//		- Decrypt the re-encrypted data.

void
runOneRound(CryptoContext<ILVector2n>& ctx, const BytePlaintextEncoding& plaintext, bool doPadding)
{
	//Perform the key generation operation.

	LPKeyPair<ILVector2n> kp = ctx.KeyGen();
	if( !kp.good() ) {
		cout << "First key generation failed" << endl;
		exit(1);
	}

	size_t chunksize = plaintext.GetChunksize(kp.publicKey->GetCryptoParameters().GetElementParams().GetCyclotomicOrder(), kp.publicKey->GetCryptoParameters().GetPlaintextModulus());
	cout << "Chunk size is: " << chunksize << endl;

	//Encryption
	vector<shared_ptr<Ciphertext<ILVector2n>>> ciphertext =
			ctx.Encrypt(kp.publicKey, plaintext, doPadding);

	if (ciphertext.size() == 0) {
		cout << "Encryption failed!" << endl;
		exit(1);
	}

	cout << "I encrypted " << plaintext.size() << " bytes, chunksize " << chunksize << " into " << ciphertext.size() << " parts" << endl;

	//Decryption
	BytePlaintextEncoding plaintextNew;
	DecryptResult dResult = ctx.Decrypt(kp.secretKey, ciphertext, &plaintextNew, doPadding);

	if (!dResult.isValid) {
		cout << "Decryption failed!" << endl;
		exit(1);
	}

	if( plaintext != plaintextNew ) {
		cout << "Decryption mismatch!" << endl;
		exit(1);
	}

	if( false ) {
		cout << "Trying int encoding" << endl;
		IntPlaintextEncoding inInt = { 2, 128, 129, 255, 252, 8 };
//		size_t chunkSize;
//		cout << (chunkSize = inInt.GetChunksize(pk.GetCryptoParameters().GetElementParams().GetCyclotomicOrder(), pk.GetCryptoParameters().GetPlaintextModulus())) << endl;
//		ILVector2n pt(pk.GetCryptoParameters().GetElementParams());
//		inInt.Encode(pk.GetCryptoParameters().GetPlaintextModulus(), &pt, 0, chunkSize);
//		cout << pt.GetLength() << endl;

		vector<shared_ptr<Ciphertext<ILVector2n>>> intCiphertext;
		IntPlaintextEncoding outInt;
		intCiphertext = ctx.Encrypt(kp.publicKey, inInt, doPadding);
		DecryptResult dResult = ctx.Decrypt(kp.secretKey, ciphertext, &plaintextNew, doPadding);
		if( inInt.size() != outInt.size() ) {
			cout << "eResult " << intCiphertext.size() << endl;
			cout << "dResult " << dResult.isValid << ":" << dResult.messageLength << endl;
			cout << "Output is size " << outInt.GetLength() << endl;
			cout << endl;
		} else for( int i=0; i<inInt.size(); i++ ) {
			if( inInt.at(i) != outInt.at(i) ) {
				cout << "integers at position " << i << " don't match" << endl;
				break;
			}
		}

		return;
	}

	//PRE SCHEME

	LPKeyPair<ILVector2n> newKp = ctx.KeyGen();
	if( false ) {
		cout << "Second keygen failed!" << endl;
		exit(1);
	}

	//Perform the proxy re-encryption key generation operation.

	shared_ptr<LPEvalKey<ILVector2n>> evalKey = ctx.ReKeyGen(newKp.publicKey, kp.secretKey);

	//Perform the proxy re-encryption operation.

	vector<shared_ptr<Ciphertext<ILVector2n>>> newCiphertext;

	CryptoUtility<ILVector2n>::ReEncrypt(ctx.GetEncryptionAlgorithm(), *evalKey, ciphertext, &newCiphertext);

	//Decryption

	BytePlaintextEncoding plaintextNew2;

	DecryptResult result1 = ctx.Decrypt(newKp.secretKey, newCiphertext, &plaintextNew2, doPadding);


	if (!result1.isValid) {
		cout << "Second decryption failed!" << endl;
		exit(1);
	}

	if( plaintext != plaintextNew2 ) {
		cout << "Re-encryption mismatch!" << endl;
		exit(1);
	}
}


