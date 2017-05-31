
#include "include/gtest/gtest.h"
#include <iostream>
#include <vector>

#include "palisade.h"
#include "cryptolayertests.h"
#include "cryptocontexthelper.h"
#include "cryptocontextgen.h"

using namespace std;
using namespace lbcrypto;

class UnitTestMultiparty : public ::testing::Test {
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
UnitTestMultiparty(const CryptoContext<Element>& cc, bool publicVersion) {
	
	// Initialize Public Key Containers
	LPKeyPair<ILVector2n> kp1;
	LPKeyPair<ILVector2n> kp2;
	LPKeyPair<ILVector2n> kp3;

	LPKeyPair<ILVector2n> kpMultiparty;

	shared_ptr<LPEvalKey<ILVector2n>> evalKey1;
	shared_ptr<LPEvalKey<ILVector2n>> evalKey2;
	shared_ptr<LPEvalKey<ILVector2n>> evalKey3;
	
	////////////////////////////////////////////////////////////
	// Perform Key Generation Operation
	////////////////////////////////////////////////////////////

	kp1 = cc.KeyGen();
	kp2 = cc.MultipartyKeyGen(kp1.publicKey);
	kp3 = cc.MultipartyKeyGen(kp1.publicKey);

	if( !kp1.good() ) {
		std::cout << "Key generation failed!" << std::endl;
		exit(1);
	}
	if( !kp2.good() ) {
		std::cout << "Key generation failed!" << std::endl;
		exit(1);
	}
	if( !kp3.good() ) {
		std::cout << "Key generation failed!" << std::endl;
		exit(1);
	}

	//std::cout << "Press any key to continue." << std::endl;
	//std::cin.get();

	////////////////////////////////////////////////////////////
	//Perform the second key generation operation.
	// This generates the keys which should be able to decrypt the ciphertext after the re-encryption operation.
	////////////////////////////////////////////////////////////

	vector<shared_ptr<LPPrivateKey<ILVector2n>>> secretKeys;
	secretKeys.push_back(kp1.secretKey);
	secretKeys.push_back(kp2.secretKey);
	secretKeys.push_back(kp3.secretKey);

	kpMultiparty = cc.MultipartyKeyGen(secretKeys);	// This is the same core key generation operation.

	if( !kpMultiparty.good() ) {
		std::cout << "Key generation failed!" << std::endl;
		exit(1);
	}

	//std::cout << "Press any key to continue." << std::endl;
	//std::cin.get();	

	////////////////////////////////////////////////////////////
	//Perform the proxy re-encryption key generation operation.
	// This generates the keys which are used to perform the key switching.
	////////////////////////////////////////////////////////////

	evalKey1 = cc.ReKeyGen(kpMultiparty.secretKey, kp1.secretKey);
	evalKey2 = cc.ReKeyGen(kpMultiparty.secretKey, kp2.secretKey);
	evalKey3 = cc.ReKeyGen(kpMultiparty.secretKey, kp3.secretKey);

	//std::cout << "Press any key to continue." << std::endl;
	//std::cin.get();	


	////////////////////////////////////////////////////////////
	// Encode source data
	////////////////////////////////////////////////////////////

	std::vector<uint32_t> vectorOfInts1 = {2,2,2,2,2,2,0,0,0,0,0,0};
	std::vector<uint32_t> vectorOfInts2 = {3,3,3,3,3,0,0,0,0,0,0,0};
	std::vector<uint32_t> vectorOfInts3 = {1,1,1,1,0,0,0,0,0,0,0,0};
	IntPlaintextEncoding plaintext1(vectorOfInts1);
	IntPlaintextEncoding plaintext2(vectorOfInts2);
	IntPlaintextEncoding plaintext3(vectorOfInts3);

	//std::vector<uint32_t> vectorOfIntsAdd = { 2, 1, 1, 3, 0, 0, 0, 0, 3, 0, 3, 3, 3, 3 };
	//IntPlaintextEncoding plaintextAdd(vectorOfIntsAdd);

	////////////////////////////////////////////////////////////
	// Encryption
	////////////////////////////////////////////////////////////

	vector<shared_ptr<Ciphertext<ILVector2n>>> ciphertext1;
	vector<shared_ptr<Ciphertext<ILVector2n>>> ciphertext2;
	vector<shared_ptr<Ciphertext<ILVector2n>>> ciphertext3;

	ciphertext1 = cc.Encrypt(kp1.publicKey, plaintext1, true);
	ciphertext2 = cc.Encrypt(kp2.publicKey, plaintext2, true);
	ciphertext3 = cc.Encrypt(kp3.publicKey, plaintext3, true);
	
	////////////////////////////////////////////////////////////
	// Re-Encryption
	////////////////////////////////////////////////////////////

	vector<shared_ptr<Ciphertext<ILVector2n>>> ciphertext1New;
	vector<shared_ptr<Ciphertext<ILVector2n>>> ciphertext2New;
	vector<shared_ptr<Ciphertext<ILVector2n>>> ciphertext3New;

	ciphertext1New = cc.ReEncrypt(evalKey1, ciphertext1);
	ciphertext2New = cc.ReEncrypt(evalKey2, ciphertext2);
	ciphertext3New = cc.ReEncrypt(evalKey3, ciphertext3);

	////////////////////////////////////////////////////////////
	// EvalAdd Operation on Re-Encrypted Data
	////////////////////////////////////////////////////////////

	shared_ptr<Ciphertext<ILVector2n>> ciphertextAddNew12;
	shared_ptr<Ciphertext<ILVector2n>> ciphertextAddNew123;

	vector<shared_ptr<Ciphertext<ILVector2n>>> ciphertextAddVectNew;

	ciphertextAddNew12 = cc.EvalAdd(ciphertext1New[0],ciphertext2New[0]);
	ciphertextAddNew123 = cc.EvalAdd(ciphertextAddNew12,ciphertext3New[0]);

	ciphertextAddVectNew.push_back(ciphertextAddNew123);

	//std::cout << "Press any key to continue." << std::endl;
	//std::cin.get();

	////////////////////////////////////////////////////////////
	//Decryption after Accumulation Operation on Re-Encrypted Data
	////////////////////////////////////////////////////////////

	IntPlaintextEncoding plaintextAddNew;

	cc.Decrypt(kpMultiparty.secretKey, ciphertextAddVectNew, &plaintextAddNew, true);

	//std::cin.get();

	plaintextAddNew.resize(plaintext1.size());

//	cout << "\n Resulting Added Plaintext with Re-Encryption: \n";
//	cout << plaintextAddNew << endl;

	////////////////////////////////////////////////////////////
	//Decryption after Accumulation Operation on Re-Encrypted Data with Multiparty
	////////////////////////////////////////////////////////////

	IntPlaintextEncoding plaintextAddNew1;
	IntPlaintextEncoding plaintextAddNew2;
	IntPlaintextEncoding plaintextAddNew3;

	ILVector2n partialPlaintext1;
	ILVector2n partialPlaintext2;
	ILVector2n partialPlaintext3;
	//IntPlaintextEncoding plaintextAddNewFinal;

	vector<shared_ptr<Ciphertext<ILVector2n>>> ciphertextPartial1;
	vector<shared_ptr<Ciphertext<ILVector2n>>> ciphertextPartial2;
	vector<shared_ptr<Ciphertext<ILVector2n>>> ciphertextPartial3;

	IntPlaintextEncoding plaintextMultipartyNew;

	const shared_ptr<LPCryptoParameters<ILVector2n>> cryptoParams = kp1.secretKey->GetCryptoParameters();
	const shared_ptr<typename ILVector2n::Params> elementParams = cryptoParams->GetElementParams();

	ciphertextPartial1 = cc.MultipartyDecryptLead(kp1.secretKey, ciphertextAddVectNew);
	ciphertextPartial2 = cc.MultipartyDecryptMain(kp2.secretKey, ciphertextAddVectNew);
	ciphertextPartial3 = cc.MultipartyDecryptMain(kp3.secretKey, ciphertextAddVectNew);

	vector<vector<shared_ptr<Ciphertext<ILVector2n>>>> partialCiphertextVec;
	partialCiphertextVec.push_back(ciphertextPartial1);
	partialCiphertextVec.push_back(ciphertextPartial2);
	partialCiphertextVec.push_back(ciphertextPartial3);

	cc.MultipartyDecryptFusion(partialCiphertextVec, &plaintextMultipartyNew, true);

	plaintextMultipartyNew.resize(plaintext1.size());

//	cout << "\n Resulting Fused Plaintext with Re-Encryption: \n";
//	cout << plaintextMultipartyNew << endl;

	EXPECT_EQ(plaintextAddNew, plaintextMultipartyNew) << "Multiparty integer plaintext";
}

//TEST(UTMultiparty, LTV_ILVector2n_Multiparty_pub) {
//	CryptoContext<ILVector2n> cc = GenCryptoContextElementLTV(ORDER, PTM);
//	UnitTestMultiparty<ILVector2n>(cc, true);
//}
//
//TEST(UTMultiparty, LTV_ILVectorArray2n_Multiparty_pub) {
//	CryptoContext<ILVectorArray2n> cc = GenCryptoContextElementArrayLTV(ORDER, TOWERS, PTM);
//	UnitTestMultiparty<ILVectorArray2n>(cc, true);
//}

//TEST(UTMultiparty, StSt_ILVector2n_Multiparty_pub) {
//	CryptoContext<ILVector2n> cc = GenCryptoContextElementStSt(ORDER, PTM);
//	UnitTestMultiparty<ILVector2n>(cc, true);
//}
//
//TEST(UTMultiparty, StSt_ILVectorArray2n_Multiparty_pub) {
//	CryptoContext<ILVectorArray2n> cc = GenCryptoContextElementArrayStSt(ORDER, TOWERS, PTM);
//	UnitTestMultiparty<ILVectorArray2n>(cc, true);
//}

//TEST(UTMultiparty, Null_ILVector2n_Multiparty_pri) {
//	string input = "NULL";
	//CryptoContext<ILVector2n> cc = CryptoContextHelper::getNewContext(input);
	//cc.Enable(ENCRYPTION);
	//cc.Enable(SHE);
	//cc.Enable(PRE);
	//cc.Enable(MULTIPARTY);
	//UnitTestMultiparty<ILVector2n>(cc, true);
//}

//TEST(UTMultiparty, Null_ILVectorArray2n_Multiparty_pri) {
//	CryptoContext<ILVectorArray2n> cc = GenCryptoContextElementArrayNull(ORDER, TOWERS, PTM, 30);
//	UnitTestMultiparty<ILVectorArray2n>(cc, true);
//}

//TEST(UTMultiparty, BV_ILVector2n_Multiparty_pri) {
//	CryptoContext<ILVector2n> cc = GenCryptoContextElementBV(ORDER, PTM);
//	UnitTestMultiparty<ILVector2n>(cc, false);
//}

//TEST(UTMultiparty, BV_ILVectorArray2n_Multiparty_pri) {
//	CryptoContext<ILVectorArray2n> cc = GenCryptoContextElementArrayBV(ORDER, TOWERS, PTM);
//	UnitTestMultiparty<ILVectorArray2n>(cc, false);
//}

TEST(UTMultiparty, FV1_ILVector2n_Multiparty_pri) {
	string input = "FV1";
	CryptoContext<ILVector2n> cc = CryptoContextHelper::getNewContext(input);
	cc.Enable(ENCRYPTION);
	cc.Enable(SHE);
	cc.Enable(PRE);
	cc.Enable(MULTIPARTY);
	UnitTestMultiparty<ILVector2n>(cc, true);
}

TEST(UTMultiparty, FV2_ILVector2n_Multiparty_pri) {
	string input = "FV2";
	CryptoContext<ILVector2n> cc = CryptoContextHelper::getNewContext(input);
	cc.Enable(ENCRYPTION);
	cc.Enable(SHE);
	cc.Enable(PRE);
	cc.Enable(MULTIPARTY);
	UnitTestMultiparty<ILVector2n>(cc, true);
}

TEST(UTMultiparty, Null_ILVector2n_Multiparty_pri) {
	string input = "Null";
	CryptoContext<ILVector2n> cc = CryptoContextHelper::getNewContext(input);
	cc.Enable(ENCRYPTION);
	cc.Enable(SHE);
	cc.Enable(PRE);
	cc.Enable(MULTIPARTY);
	UnitTestMultiparty<ILVector2n>(cc, true);
}

TEST(UTMultiparty, Null2_ILVector2n_Multiparty_pri) {
	string input = "Null2";
	CryptoContext<ILVector2n> cc = CryptoContextHelper::getNewContext(input);
	cc.Enable(ENCRYPTION);
	cc.Enable(SHE);
	cc.Enable(PRE);
	cc.Enable(MULTIPARTY);
	UnitTestMultiparty<ILVector2n>(cc, true);
}

//TEST(UTMultiparty, FV_ILVectorArray2n_Multiparty_pri) {
//	CryptoContext<ILVectorArray2n> cc = GenCryptoContextElementArrayFV(ORDER, TOWERS, PTM);
//	UnitTestMultiparty<ILVectorArray2n>(cc, false);
//}
