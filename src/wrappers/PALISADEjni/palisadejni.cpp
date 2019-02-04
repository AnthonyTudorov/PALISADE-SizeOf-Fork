#include <jni.h>
#include "palisadejni.h"

#include "version.h"
#include "palisade.h"
#include "cryptocontextparametersets.h"
#include "cryptocontexthelper.h"
#include "cryptocontextgen.h"

using namespace std;
using namespace lbcrypto;

extern "C" JNIEXPORT jstring JNICALL
Java_com_palisade_PALISADE_version(JNIEnv *env, jobject unused) {
	return env->NewStringUTF(GetPALISADEVersion().c_str());
}

#define GENERATE_PKE_TEST_CASE(TOPNAME, FUNC, ELEMENT, SCHEME, ORD, PTM) \
	std::string TOPNAME ## _ ## FUNC ## _ ## ELEMENT ## _ ## SCHEME () { \
	CryptoContext<ELEMENT> cc; \
	try { \
		cc = GenTestCryptoContext<ELEMENT>(#SCHEME, ORD, PTM); \
	} catch( ... ) { \
		return "no context"; \
	} \
	return FUNC<ELEMENT>(cc, #SCHEME); \
}

#define GENERATE_PKE_TEST_CASE_BITS(TOPNAME, FUNC, ELEMENT, SCHEME, ORD, PTM, BITS) \
	std::string TOPNAME ## _ ## FUNC ## _ ## ELEMENT ## _ ## SCHEME () { \
	CryptoContext<ELEMENT> cc; \
	try { \
		cc = GenTestCryptoContext<ELEMENT>(#SCHEME, ORD, PTM, BITS); \
	} catch( ... ) { \
		return; \
	} \
	return FUNC<ELEMENT>(cc, #SCHEME); \
}

#define GENERATE_TEST_CASES_FUNC(x,y,ORD,PTM) \
GENERATE_PKE_TEST_CASE(x, y, Poly, Null, ORD, PTM) \
GENERATE_PKE_TEST_CASE(x, y, Poly, LTV, ORD, PTM) \
GENERATE_PKE_TEST_CASE(x, y, Poly, StSt, ORD, PTM) \
GENERATE_PKE_TEST_CASE(x, y, Poly, BGV_rlwe, ORD, PTM) \
GENERATE_PKE_TEST_CASE(x, y, Poly, BGV_opt, ORD, PTM) \
GENERATE_PKE_TEST_CASE(x, y, Poly, BFV_rlwe, ORD, PTM) \
GENERATE_PKE_TEST_CASE(x, y, Poly, BFV_opt, ORD, PTM) \
GENERATE_PKE_TEST_CASE(x, y, Poly, BFVrns_rlwe, ORD, PTM) \
GENERATE_PKE_TEST_CASE(x, y, Poly, BFVrns_opt, ORD, PTM) \
GENERATE_PKE_TEST_CASE(x, y, Poly, BFVrnsB_rlwe, ORD, PTM) \
GENERATE_PKE_TEST_CASE(x, y, Poly, BFVrnsB_opt, ORD, PTM) \
GENERATE_PKE_TEST_CASE(x, y, NativePoly, Null, ORD, PTM) \
GENERATE_PKE_TEST_CASE(x, y, NativePoly, LTV, ORD, PTM) \
GENERATE_PKE_TEST_CASE(x, y, NativePoly, StSt, ORD, PTM) \
GENERATE_PKE_TEST_CASE(x, y, NativePoly, BGV_rlwe, ORD, PTM) \
GENERATE_PKE_TEST_CASE(x, y, NativePoly, BGV_opt, ORD, PTM) \
GENERATE_PKE_TEST_CASE(x, y, NativePoly, BFV_rlwe, ORD, PTM) \
GENERATE_PKE_TEST_CASE(x, y, NativePoly, BFV_opt, ORD, PTM) \
GENERATE_PKE_TEST_CASE(x, y, NativePoly, BFVrns_rlwe, ORD, PTM) \
GENERATE_PKE_TEST_CASE(x, y, NativePoly, BFVrns_opt, ORD, PTM) \
GENERATE_PKE_TEST_CASE(x, y, NativePoly, BFVrnsB_rlwe, ORD, PTM) \
GENERATE_PKE_TEST_CASE(x, y, NativePoly, BFVrnsB_opt, ORD, PTM) \
GENERATE_PKE_TEST_CASE(x, y, DCRTPoly, Null, ORD, PTM) \
GENERATE_PKE_TEST_CASE(x, y, DCRTPoly, LTV, ORD, PTM) \
GENERATE_PKE_TEST_CASE(x, y, DCRTPoly, StSt, ORD, PTM) \
GENERATE_PKE_TEST_CASE(x, y, DCRTPoly, BGV_rlwe, ORD, PTM) \
GENERATE_PKE_TEST_CASE(x, y, DCRTPoly, BGV_opt, ORD, PTM) \
GENERATE_PKE_TEST_CASE(x, y, DCRTPoly, BFVrns_rlwe, ORD, PTM) \
GENERATE_PKE_TEST_CASE(x, y, DCRTPoly, BFVrns_opt, ORD, PTM) \
GENERATE_PKE_TEST_CASE(x, y, DCRTPoly, BFVrnsB_rlwe, ORD, PTM) \
GENERATE_PKE_TEST_CASE(x, y, DCRTPoly, BFVrnsB_opt, ORD, PTM)

#if 0
template<typename Element>
static void EncryptionScalar(const CryptoContext<Element> cc, const string& failmsg) {
	uint64_t		value = 29;
	Plaintext plaintext = cc->MakeScalarPlaintext(value);

	LPKeyPair<Element> kp = cc->KeyGen();
	EXPECT_EQ(kp.good(), true) << failmsg << " key generation for scalar encrypt/decrypt failed";

	Ciphertext<Element> ciphertext = cc->Encrypt(kp.publicKey, plaintext);
	Plaintext plaintextNew;
	cc->Decrypt(kp.secretKey, ciphertext, &plaintextNew);
	EXPECT_EQ(*plaintext, *plaintextNew) << failmsg << " unsigned scalar encrypt/decrypt failed";

	Plaintext plaintext2 = cc->MakeScalarPlaintext(-value);
	ciphertext = cc->Encrypt(kp.publicKey, plaintext2);
	cc->Decrypt(kp.secretKey, ciphertext, &plaintextNew);
	EXPECT_EQ(*plaintext2, *plaintextNew) << failmsg << " signed scalar encrypt/decrypt failed";
}

GENERATE_TEST_CASES_FUNC(Encrypt_Decrypt, EncryptionScalar, 8, 64)

template <typename Element>
void
EncryptionInteger(const CryptoContext<Element> cc, const string& failmsg) {
	int64_t		value = 250;
	Plaintext plaintext = cc->MakeIntegerPlaintext(value);

	LPKeyPair<Element> kp = cc->KeyGen();
	EXPECT_EQ(kp.good(), true) << failmsg << " key generation for integer encrypt/decrypt failed";

	Ciphertext<Element> ciphertext = cc->Encrypt(kp.publicKey, plaintext);
	Plaintext plaintextNew;
	cc->Decrypt(kp.secretKey, ciphertext, &plaintextNew);
	EXPECT_EQ(*plaintext, *plaintextNew) << failmsg << " integer encrypt/decrypt failed";
}

GENERATE_TEST_CASES_FUNC(Encrypt_Decrypt, EncryptionInteger, 128, 512)

template <typename Element>
void
EncryptionNegativeInteger(const CryptoContext<Element> cc, const string& failmsg) {
	int64_t		value = -250;
	Plaintext plaintext = cc->MakeIntegerPlaintext(value);

	LPKeyPair<Element> kp = cc->KeyGen();
	EXPECT_EQ(kp.good(), true) << failmsg << " key generation for negative integer encrypt/decrypt failed";

	Ciphertext<Element> ciphertext = cc->Encrypt(kp.publicKey, plaintext);
	Plaintext plaintextNew;
	cc->Decrypt(kp.secretKey, ciphertext, &plaintextNew);
	EXPECT_EQ(*plaintext, *plaintextNew) << failmsg << " negative integer encrypt/decrypt failed";
}

GENERATE_TEST_CASES_FUNC(Encrypt_Decrypt, EncryptionNegativeInteger, 128, 512)
#endif

template <typename Element>
string
EncryptionString(const CryptoContext<Element> cc, const string& failmsg) {
	string		value = "You keep using that word. I do not think it means what you think it means";
	Plaintext plaintext = CryptoContextImpl<Element>::MakePlaintext(String, cc, value);

	LPKeyPair<Element> kp = cc->KeyGen();
	if(kp.good() != true)
		return failmsg + " key generation for string encrypt/decrypt failed";

	Ciphertext<Element> ciphertext = cc->Encrypt(kp.publicKey, plaintext);
	Plaintext plaintextNew;
	cc->Decrypt(kp.secretKey, ciphertext, &plaintextNew);
	if(*plaintext != *plaintextNew)
		return failmsg + " string encrypt/decrypt failed";

	return "String Encrypt/Decrypt succeeds!";
}

GENERATE_TEST_CASES_FUNC(Encrypt_Decrypt, EncryptionString, 512, 256)

#if 0
template <typename Element>
void
EncryptionCoefPacked(const CryptoContext<Element> cc, const string& failmsg) {

	size_t intSize = cc->GetRingDimension();
	auto ptm = cc->GetCryptoParameters()->GetPlaintextModulus();
	int half = ptm/2;

	vector<int64_t> intvec;
	for( size_t ii=0; ii<intSize; ii++)
		intvec.push_back( rand() % half );
	Plaintext plaintextInt = cc->MakeCoefPackedPlaintext(intvec);

	vector<int64_t> sintvec;
	for( size_t ii=0; ii<intSize; ii++) {
		int rnum = rand() % half;
		if( rand()%2 ) rnum *= -1;
		sintvec.push_back( rnum );
	}
	Plaintext plaintextSInt = cc->MakeCoefPackedPlaintext(sintvec);

	LPKeyPair<Element> kp = cc->KeyGen();
	EXPECT_EQ(kp.good(), true) << failmsg << " key generation for coef packed encrypt/decrypt failed";

	Ciphertext<Element> ciphertext4 = cc->Encrypt(kp.publicKey, plaintextInt);
	Plaintext plaintextIntNew;
	cc->Decrypt(kp.secretKey, ciphertext4, &plaintextIntNew);
	EXPECT_EQ(*plaintextIntNew, *plaintextInt) << failmsg << "coef packed encrypt/decrypt failed for integer plaintext";

	Ciphertext<Element> ciphertext5 = cc->Encrypt(kp.publicKey, plaintextSInt);
	Plaintext plaintextSIntNew;
	cc->Decrypt(kp.secretKey, ciphertext5, &plaintextSIntNew);
	EXPECT_EQ(*plaintextSIntNew, *plaintextSInt) << failmsg << "coef packed encrypt/decrypt failed for signed integer plaintext";
}

GENERATE_TEST_CASES_FUNC(Encrypt_Decrypt, EncryptionCoefPacked, 128, 512)
#endif

extern "C" JNIEXPORT jstring JNICALL
Java_com_palisade_PALISADE_test1(JNIEnv *env, jobject unused) {
	std::string ans = Encrypt_Decrypt_EncryptionString_Poly_Null();
	return env->NewStringUTF(ans.c_str());
}

