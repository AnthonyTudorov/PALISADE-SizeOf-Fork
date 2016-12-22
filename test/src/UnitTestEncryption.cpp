
#include "../include/gtest/gtest.h"
#include <iostream>
#include <vector>

#include "../../src/lib/math/backend.h"
#include "../../src/lib/utils/inttypes.h"
#include "../../src/lib/lattice/ilparams.h"
#include "../../src/lib/lattice/ildcrtparams.h"
#include "../../src/lib/math/distrgen.h"
#include "../../src/lib/lattice/ilvector2n.h"
#include "../../src/lib/lattice/ilvectorarray2n.h"


#include "../../src/lib/crypto/cryptocontext.h"
#include "../../src/lib/utils/cryptocontexthelper.h"
#include "../../src/lib/crypto/cryptocontext.cpp"
#include "../../src/lib/utils/cryptocontexthelper.cpp"

#include "../../src/lib/encoding/byteplaintextencoding.h"
#include "../../src/lib/encoding/intplaintextencoding.h"


#include "../../src/lib/utils/debug.h"

using namespace std;
using namespace lbcrypto;

#ifdef OUT
BytePlaintextEncoding plaintext("NJIT_CRYPTOGRAPHY_LABORATORY_IS_DEVELOPING_NEW-NTRU_LIKE_PROXY_REENCRYPTION_SCHEME_USING_LATTICE_BASED_CRYPTOGRAPHY_ABCDEFGHIJKL");
std::vector<usint> vectorOfInts1 = { 1,0,1,0 };

IntPlaintextEncoding intArray1(vectorOfInts1);
#endif

template <class Element, class Ptxt>
void
UnitTestEncryption(const CryptoContext<Element>& cc, const Ptxt& plaintext) {

	////////////////////////////////////////////////////////////
	//Perform the key generation operation.
	////////////////////////////////////////////////////////////

	// Initialize the key containers.
	LPKeyPair<Element> kp = cc.KeyGen();

	if (!kp.good()) {
		std::cout << "Key generation failed!" << std::endl;
		exit(1);
	}

	////////////////////////////////////////////////////////////
	//Encryption
	////////////////////////////////////////////////////////////

	vector<shared_ptr<Ciphertext<Element>>> ciphertext = cc.Encrypt(kp.publicKey, plaintext, false);

	////////////////////////////////////////////////////////////
	//Decryption
	////////////////////////////////////////////////////////////

	Ptxt plaintextNew;

	DecryptResult result = cc.Decrypt(kp.secretKey, ciphertext, &plaintextNew, false);

	EXPECT_EQ(plaintextNew, plaintext);

	//PRE SCHEME

	////////////////////////////////////////////////////////////
	//Perform the second key generation operation.
	// This generates the keys which should be able to decrypt the ciphertext after the re-encryption operation.
	////////////////////////////////////////////////////////////

	LPKeyPair<Element> newKp = cc.KeyGen();


	////////////////////////////////////////////////////////////
	//Perform the proxy re-encryption key generation operation.
	// This generates the keys which are used to perform the key switching.
	////////////////////////////////////////////////////////////

	shared_ptr<LPEvalKey<Element>> evalKey = cc.KeySwitchGen( kp.secretKey, newKp.secretKey );

	////////////////////////////////////////////////////////////
	//Perform the proxy re-encryption operation.
	// This switches the keys which are used to perform the key switching.
	////////////////////////////////////////////////////////////

	vector<shared_ptr<Ciphertext<Element>>> newCiphertext = cc.ReEncrypt(evalKey, ciphertext);

	////////////////////////////////////////////////////////////
	//Decryption
	////////////////////////////////////////////////////////////

	Ptxt plaintextNew2;

	result = cc.Decrypt(newKp.secretKey, newCiphertext, &plaintextNew2, false);

	EXPECT_EQ(plaintextNew2, plaintext);
}

template void UnitTestEncryption<ILVector2n>(const CryptoContext<ILVector2n>& cc, const BytePlaintextEncoding& plaintext);
template void UnitTestEncryption<ILVectorArray2n>(const CryptoContext<ILVectorArray2n>& cc, const BytePlaintextEncoding& plaintext);
template void UnitTestEncryption<ILVector2n>(const CryptoContext<ILVector2n>& cc, const IntPlaintextEncoding& plaintext);
template void UnitTestEncryption<ILVectorArray2n>(const CryptoContext<ILVectorArray2n>& cc, const IntPlaintextEncoding& plaintext);


