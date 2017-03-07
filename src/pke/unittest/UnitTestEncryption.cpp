
#include "include/gtest/gtest.h"
#include <iostream>
#include <vector>

#include "math/backend.h"
#include "utils/inttypes.h"
#include "lattice/ilparams.h"
#include "lattice/ildcrtparams.h"
#include "math/distrgen.h"
#include "lattice/ilvector2n.h"
#include "lattice/ilvectorarray2n.h"


#include "../lib/cryptocontext.h"

#include "encoding/byteplaintextencoding.h"
#include "encoding/intplaintextencoding.h"


#include "utils/debug.h"

using namespace std;
using namespace lbcrypto;

static void initialize(int cyclotomicOrder, const BigBinaryInteger& ptm,
	BytePlaintextEncoding& plaintextShort,
	BytePlaintextEncoding& plaintextFull,
	BytePlaintextEncoding& plaintextLong) {
	size_t strSize = plaintextShort.GetChunksize(cyclotomicOrder, ptm);

	auto randchar = []() -> char {
        const char charset[] =
        "0123456789"
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz";
        const size_t max_index = (sizeof(charset) - 1);
        return charset[ rand() % max_index ];
	};

	string shortStr(strSize/2,0);
	std::generate_n(shortStr.begin(), strSize/2, randchar);
	plaintextShort = shortStr;

	string fullStr(strSize,0);
	std::generate_n(fullStr.begin(), strSize, randchar);
	plaintextFull = fullStr;

	string longStr(strSize*2,0);
	std::generate_n(longStr.begin(), strSize*2, randchar);
	plaintextLong = longStr;
}


template <class Element>
void
UnitTestEncryption(const CryptoContext<Element>& cc) {
	BytePlaintextEncoding plaintextShort;
	BytePlaintextEncoding plaintextFull;
	BytePlaintextEncoding plaintextLong;

	initialize(cc.GetCryptoParameters()->GetElementParams()->GetCyclotomicOrder(),
			cc.GetCryptoParameters()->GetPlaintextModulus(),
			plaintextShort, plaintextFull, plaintextLong);

	size_t intSize = cc.GetCryptoParameters()->GetElementParams()->GetCyclotomicOrder() / 2;
	auto ptm = cc.GetCryptoParameters()->GetPlaintextModulus().ConvertToInt();

	vector<uint32_t> intvec;
	for( int ii=0; ii<intSize; ii++)
		intvec.push_back( rand() % ptm );
	IntPlaintextEncoding plaintextInt(intvec);

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
	//Encrypt and decrypt short, with padding, full, and long
	////////////////////////////////////////////////////////////

	vector<shared_ptr<Ciphertext<Element>>> ciphertext = cc.Encrypt(kp.publicKey, plaintextShort, true);
	BytePlaintextEncoding plaintextShortNew;
	DecryptResult result = cc.Decrypt(kp.secretKey, ciphertext, &plaintextShortNew, true);
	EXPECT_EQ(plaintextShortNew, plaintextShort) << "Encrypt short plaintext with padding";

	vector<shared_ptr<Ciphertext<Element>>> ciphertext2 = cc.Encrypt(kp.publicKey, plaintextFull, false);
	BytePlaintextEncoding plaintextFullNew;
	DecryptResult result2 = cc.Decrypt(kp.secretKey, ciphertext2, &plaintextFullNew, false);
	EXPECT_EQ(plaintextFullNew, plaintextFull) << "Encrypt regular plaintext";

	vector<shared_ptr<Ciphertext<Element>>> ciphertext3 = cc.Encrypt(kp.publicKey, plaintextLong, false);
	BytePlaintextEncoding plaintextLongNew;
	DecryptResult result3 = cc.Decrypt(kp.secretKey, ciphertext3, &plaintextLongNew, false);
	EXPECT_EQ(plaintextLongNew, plaintextLong) << "Encrypt long plaintext";

	vector<shared_ptr<Ciphertext<Element>>> ciphertext4 = cc.Encrypt(kp.publicKey, plaintextInt, false);
	IntPlaintextEncoding plaintextIntNew;
	DecryptResult result4 = cc.Decrypt(kp.secretKey, ciphertext4, &plaintextIntNew, false);
	EXPECT_EQ(plaintextIntNew, plaintextInt) << "Encrypt integer plaintext";
}

template <class Element>
void
UnitTestReEncryption(const CryptoContext<Element>& cc) {
	BytePlaintextEncoding plaintextShort;
	BytePlaintextEncoding plaintextFull;
	BytePlaintextEncoding plaintextLong;

	initialize(cc.GetCryptoParameters()->GetElementParams()->GetCyclotomicOrder(),
			cc.GetCryptoParameters()->GetPlaintextModulus(),
			plaintextShort, plaintextFull, plaintextLong);

	size_t intSize = cc.GetCryptoParameters()->GetElementParams()->GetCyclotomicOrder() / 2;
	auto ptm = cc.GetCryptoParameters()->GetPlaintextModulus().ConvertToInt();

	vector<uint32_t> intvec;
	for( int ii=0; ii<intSize; ii++)
		intvec.push_back( rand() % ptm );
	IntPlaintextEncoding plaintextInt(intvec);

	////////////////////////////////////////////////////////////
	//Perform the key generation operations
	////////////////////////////////////////////////////////////

	// Initialize the key containers.
	LPKeyPair<Element> kp = cc.KeyGen();

	if (!kp.good()) {
		std::cout << "Key generation failed!" << std::endl;
		exit(1);
	}

	////////////////////////////////////////////////////////////
	//Perform the second key generation operation.
	// This generates the keys which should be able to decrypt the ciphertext after the re-encryption operation.
	////////////////////////////////////////////////////////////

	LPKeyPair<Element> newKp = cc.KeyGen();

	////////////////////////////////////////////////////////////
	//Perform the proxy re-encryption key generation operation.
	// This generates the keys which are used to perform the key switching.
	////////////////////////////////////////////////////////////

	shared_ptr<LPEvalKey<Element>> evalKey = cc.ReKeyGen( newKp.publicKey, kp.secretKey );

	vector<shared_ptr<Ciphertext<Element>>> ciphertext = cc.Encrypt(kp.publicKey, plaintextShort, true);
	BytePlaintextEncoding plaintextShortNew;
	vector<shared_ptr<Ciphertext<Element>>> reCiphertext = cc.ReEncrypt(evalKey, ciphertext);
	DecryptResult result = cc.Decrypt(newKp.secretKey, reCiphertext, &plaintextShortNew, true);
	EXPECT_EQ(plaintextShortNew, plaintextShort) << "ReEncrypt short plaintext with padding";

	vector<shared_ptr<Ciphertext<Element>>> ciphertext2 = cc.Encrypt(kp.publicKey, plaintextFull, false);
	BytePlaintextEncoding plaintextFullNew;
	vector<shared_ptr<Ciphertext<Element>>> reCiphertext2 = cc.ReEncrypt(evalKey, ciphertext2);
	result = cc.Decrypt(newKp.secretKey, reCiphertext2, &plaintextFullNew, false);
	EXPECT_EQ(plaintextFullNew, plaintextFull) << "ReEncrypt regular plaintext";

	vector<shared_ptr<Ciphertext<Element>>> ciphertext3 = cc.Encrypt(kp.publicKey, plaintextLong, false);
	BytePlaintextEncoding plaintextLongNew;
	vector<shared_ptr<Ciphertext<Element>>> reCiphertext3 = cc.ReEncrypt(evalKey, ciphertext3);
	result = cc.Decrypt(newKp.secretKey, reCiphertext3, &plaintextLongNew, false);
	EXPECT_EQ(plaintextLongNew, plaintextLong) << "ReEncrypt long plaintext";

	vector<shared_ptr<Ciphertext<Element>>> ciphertext4 = cc.Encrypt(kp.publicKey, plaintextInt, false);
	IntPlaintextEncoding plaintextIntNew;
	vector<shared_ptr<Ciphertext<Element>>> reCiphertext4 = cc.ReEncrypt(evalKey, ciphertext4);
	result = cc.Decrypt(newKp.secretKey, reCiphertext4, &plaintextIntNew, false);
	EXPECT_EQ(plaintextIntNew, plaintextInt) << "ReEncrypt integer plaintext";
}

template void UnitTestReEncryption<ILVector2n>(const CryptoContext<ILVector2n>& cc);
template void UnitTestReEncryption<ILVectorArray2n>(const CryptoContext<ILVectorArray2n>& cc);
template void UnitTestEncryption<ILVector2n>(const CryptoContext<ILVector2n>& cc);
template void UnitTestEncryption<ILVectorArray2n>(const CryptoContext<ILVectorArray2n>& cc);
