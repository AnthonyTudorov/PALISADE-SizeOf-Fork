// memory leak tester

#include <iostream>
#include <fstream>
#include <iterator>

#include "../../lib/crypto/cryptocontext.h"
#include "../../lib/utils/cryptocontexthelper.h"
#include "../../lib/crypto/cryptocontext.cpp"
#include "../../lib/utils/cryptocontexthelper.cpp"

#include "../../lib/utils/debug.h"

void runOneRound(CryptoContext<ILVector2n> *ctx);

#include "../../lib/utils/serializablehelper.h"

using namespace std;
using namespace lbcrypto;

int
main(int argc, char *argv[])
{
	string filename = "src/demo/pre/PalisadeCryptoContext.parms";
	string parmset;

	if( argc == 2 )
		filename = string(*++argv);

	//DiscreteUniformGenerator gen(BigBinaryInteger("100000"));
	//auto v = gen.GenerateVector(10000);

	//std::cout << "Choose parameter set: ";
	//CryptoContextHelper<ILVector2n>::printAllParmSetNames(std::cout, filename);

	string input = "StSt6";
	//std::cin >> input;

	CryptoContext<ILVector2n> *ctx = CryptoContextHelper<ILVector2n>::getNewContext(filename, input);
	if( ctx == 0 ) {
		cout << "Error on " << input << endl;
		return 0;
	}

	for( int i = 1; i <= 1; i++ ) {
		runOneRound(ctx);
		if( i%10 == 0 ) cout << i << "... " << flush;
	}
	cout << endl;

	delete ctx;

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
runOneRound(CryptoContext<ILVector2n> *ctx)
{
	ByteArray plaintext("NJIT_CRYPTOGRAPHY_LABORATORY_IS_DEVELOPING_NEW-NTRU_LIKE_PROXY_REENCRYPTION_SCHEME_USING_LATTICE_BASED_CRYPTOGRAPHY_ABCDEFGHIJKL");

	// Initialize the public key containers.
	LPPublicKeyLTV<ILVector2n> pk(*ctx->getParams());
	LPPrivateKeyLTV<ILVector2n> sk(*ctx->getParams());

	//Perform the key generation operation.

	if( ! ctx->getAlgorithm()->KeyGen(&pk,&sk) ) {
		cout << "First key generation failed" << endl;
		exit(1);
	}

	//Encryption

	Ciphertext<ILVector2n> ciphertext;
	ByteArrayPlaintextEncoding ptxt(plaintext);
	ptxt.Pad<ZeroPad>(ctx->getPadAmount());

	ctx->getAlgorithm()->Encrypt(pk,ptxt,&ciphertext);

	//Decryption

	ByteArrayPlaintextEncoding plaintextNew;

	DecodingResult result = ctx->getAlgorithm()->Decrypt(sk,ciphertext,&plaintextNew);
	plaintextNew.Unpad<ZeroPad>();

	if (!result.isValidCoding) {
		cout << "Decryption failed!" << endl;
		exit(1);
	}

	ptxt.Unpad<ZeroPad>();
	if( ptxt != plaintextNew ) {
		cout << "Decryption mismatch!" << endl;
		exit(1);
	}

	//PRE SCHEME

	LPPublicKeyLTV<ILVector2n> newPK(*ctx->getParams());
	LPPrivateKeyLTV<ILVector2n> newSK(*ctx->getParams());

	if( ! ctx->getAlgorithm()->KeyGen(&newPK,&newSK) ) {
		cout << "Second keygen failed!" << endl;
		exit(1);
	}

	//Perform the proxy re-encryption key generation operation.

	LPEvalKeyLTV<ILVector2n> evalKey(*ctx->getParams());

	ctx->getAlgorithm()->EvalKeyGen(newPK, sk, &evalKey);

	//Perform the proxy re-encryption operation.

	Ciphertext<ILVector2n> newCiphertext;

	ctx->getAlgorithm()->ReEncrypt(evalKey, ciphertext, &newCiphertext);

	//Decryption

	ByteArrayPlaintextEncoding plaintextNew2;

	DecodingResult result1 = ctx->getAlgorithm()->Decrypt(newSK,newCiphertext,&plaintextNew2);  // This is the core decryption operation.
	plaintextNew2.Unpad<ZeroPad>();

	if (!result1.isValidCoding) {
		cout << "Second decryption failed!" << endl;
		exit(1);
	}

	if( ptxt != plaintextNew2 ) {
		cout << "Re-encryption mismatch!" << endl;
		exit(1);
	}
}


