
#include "include/gtest/gtest.h"
#include <iostream>
#include <vector>

#include "palisade.h"
#include "cryptolayertests.h"
#include "cryptocontexthelper.h"
#include "cryptocontextgen.h"

using namespace std;
using namespace lbcrypto;

class UnitTestPRE : public ::testing::Test {
protected:
	virtual void SetUp() {}

	virtual void TearDown() {}

public:
};

// NOTE the PRE tests are all based on these
static const usint ORDER = 2048;
static const usint PTM = 256;
static const usint TOWERS = 3;

template <class Element>
void
UnitTestReEncrypt(const CryptoContext<Element>& cc, bool publicVersion) {
	BytePlaintextEncoding plaintextShort;
	BytePlaintextEncoding plaintextFull;
	BytePlaintextEncoding plaintextLong;

	GenerateTestPlaintext(cc.GetCryptoParameters()->GetElementParams()->GetCyclotomicOrder(),
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


	if (!newKp.good()) {
		std::cout << "Key generation 2 failed!" << std::endl;
		exit(1);
	}
	////////////////////////////////////////////////////////////
	//Perform the proxy re-encryption key generation operation.
	// This generates the keys which are used to perform the key switching.
	////////////////////////////////////////////////////////////

	shared_ptr<LPEvalKey<Element>> evalKey;
	if( publicVersion )
		evalKey = cc.ReKeyGen(newKp.publicKey, kp.secretKey);
	else
		evalKey = cc.ReKeyGen(newKp.secretKey, kp.secretKey);


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

TEST(UTPRE, LTV_ILVector2n_ReEncrypt_pub) {
	CryptoContext<ILVector2n> cc = GenCryptoContextElementLTV(ORDER, PTM);
	UnitTestReEncrypt<ILVector2n>(cc, true);
}

//TEST(UTPRE, LTV_ILVectorArray2n_ReEncrypt_pub) {
//	CryptoContext<ILVectorArray2n> cc = GenCryptoContextElementArrayLTV(ORDER, TOWERS, PTM);
//	UnitTestReEncrypt<ILVectorArray2n>(cc, true);
//}

//TEST(UTPRE, StSt_ILVector2n_ReEncrypt_pub) {
//	CryptoContext<ILVector2n> cc = GenCryptoContextElementStSt(ORDER, PTM);
//	UnitTestReEncrypt<ILVector2n>(cc, true);
//}
//
//TEST(UTPRE, StSt_ILVectorArray2n_ReEncrypt_pub) {
//	CryptoContext<ILVectorArray2n> cc = GenCryptoContextElementArrayStSt(ORDER, TOWERS, PTM);
//	UnitTestReEncrypt<ILVectorArray2n>(cc, true);
//}

TEST(UTPRE, Null_ILVector2n_ReEncrypt_pub) {
	CryptoContext<ILVector2n> cc = GenCryptoContextElementNull(ORDER, PTM);
	UnitTestReEncrypt<ILVector2n>(cc, true);
}

TEST(UTPRE, Null_ILVectorArray2n_ReEncrypt_pub) {
	CryptoContext<ILVectorArray2n> cc = GenCryptoContextElementArrayNull(ORDER, TOWERS, PTM);
	UnitTestReEncrypt<ILVectorArray2n>(cc, true);
}

TEST(UTPRE, BV_ILVector2n_ReEncrypt_pri) {
	CryptoContext<ILVector2n> cc = GenCryptoContextElementBV(ORDER, PTM);
	UnitTestReEncrypt<ILVector2n>(cc, false);
}

TEST(UTPRE, BV_ILVectorArray2n_ReEncrypt_pri) {
	CryptoContext<ILVectorArray2n> cc = GenCryptoContextElementArrayBV(ORDER, TOWERS, PTM);
	UnitTestReEncrypt<ILVectorArray2n>(cc, false);
}

TEST(UTPRE, FV_ILVector2n_ReEncrypt_pri) {
	CryptoContext<ILVector2n> cc = GenCryptoContextElementFV(ORDER, PTM);
	UnitTestReEncrypt<ILVector2n>(cc, false);
}

TEST(UTPRE, FV_ILVectorArray2n_ReEncrypt_pri) {
	CryptoContext<ILVectorArray2n> cc = GenCryptoContextElementArrayFV(ORDER, TOWERS, PTM);
	UnitTestReEncrypt<ILVectorArray2n>(cc, false);
}
