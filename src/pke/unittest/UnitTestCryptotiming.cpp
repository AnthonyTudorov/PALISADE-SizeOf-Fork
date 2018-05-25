//
// Created by matt_t on 5/24/18.
//

#include "../../test/include/gtest/gtest.h" //FIXME include/gtest/gtest.h
#include "palisade.h"
#include "cryptocontext.h"
#include "ciphertext.cpp"
#include "cryptotiming.h"
#include "utils/parmfactory.h"
#include "utils/serializablehelper.h"


class UTCryptotiming : public ::testing::Test {
protected:
    void SetUp() {
    }

    void TearDown() {
        //TODO EXAMINE NEEDED RELEASES HERE
        CryptoContextFactory<Poly>::ReleaseAllContexts();
        CryptoContextImpl<Poly>::ClearEvalAutomorphismKeys();
        CryptoContextImpl<Poly>::ClearEvalSumKeys();
        CryptoContextImpl<Poly>::ClearEvalMultKeys();
    }
};

using namespace std;
using namespace lbcrypto;

TEST_F(UTCryptotiming, timing_util_functions){
    CryptoContext<Poly> cc = CryptoContextFactory<Poly>::genCryptoContextNull(0, 256);
    cc->Enable(ENCRYPTION);
    vector<TimingInfo>	times;
    cc->StartTiming(&times);
    Ciphertext<Poly> ciphertext;
    Plaintext plaintext = Plaintext( new StringEncoding( cc->GetElementParams(), cc->GetEncodingParams(), "cryptotiming" ) );
    // PErform 3 operations assuming that at least one of them will successfully push to vector
    LPKeyPair<Poly> kp = cc->KeyGen();
    ciphertext = cc->Encrypt(kp.secretKey, plaintext);
    cc->Decrypt(kp.secretKey, ciphertext, &plaintext);

    ASSERT_TRUE(0 < times.size()) << "StartTiming failed to initialize timing procedures, or many operations failed to push to vector";
    uint len = (uint)times.size();
    cc->StopTiming();
    cc->KeyGen();
    ASSERT_TRUE(len == times.size()) << "StopTiming did not stop timing procedures";

    cc->ResumeTiming();
    cc->KeyGen();
    cc->Encrypt(kp.secretKey, plaintext);
    cc->Decrypt(kp.secretKey, ciphertext, &plaintext);
    ASSERT_TRUE(len < times.size()) << "ResumeTiming did not resume timing procedures";

    cc->ResetTiming();
    ASSERT_TRUE(0 == times.size()) << "ResetTiming did not reset timing vector";

    cc->KeyGen();
    ASSERT_TRUE(times.size() == 1) << "KeyGen op failed to push to timing vector";
    ASSERT_TRUE(times.back().operation == OpKeyGen) << "KeyGen op applied an incorrect optype to its data";

}

TEST_F(UTCryptotiming, scalar_encrypt_decrypt){
    CryptoContext<Poly> cc = CryptoContextFactory<Poly>::genCryptoContextNull(0, 256);
    cc->Enable(ENCRYPTION);
    vector<TimingInfo>	times;
    cc->StartTiming(&times);
    Plaintext plaintext = Plaintext( new StringEncoding( cc->GetElementParams(), cc->GetEncodingParams(), "cryptotiming" ) );

    LPKeyPair<Poly> kp = cc->KeyGen();
    uint len = (uint)times.size();

    cc->Encrypt(kp.publicKey, plaintext);
    ASSERT_TRUE(times.size()== len+1) << "Pub Encrypt op failed to push to timing vector";
    ASSERT_TRUE(times.back().operation == OpEncryptPub) << "Pub Encrypt op applied an incorrect optype to its data:";
    if(times.size() == len+1) { len++; }

    Ciphertext<Poly> ciphertext;
    ciphertext = cc->Encrypt(kp.secretKey, plaintext);
    ASSERT_TRUE(times.size()== len+1) << "Private Encrypt op failed to push to timing vector";
    ASSERT_TRUE(times.back().operation == OpEncryptPriv) << "Private Encrypt op applied an incorrect optype to its data:";
    if(times.size() == len+1) { len++; }

    cc->Decrypt(kp.secretKey, ciphertext, &plaintext);
    ASSERT_TRUE(times.size()== len+1) << "Decrypt op failed to push to timing vector";
    ASSERT_TRUE(times.back().operation == OpDecrypt) << "Decrypt op applied an incorrect optype to its data:";
    if(times.size() == len+1) { len++; }

}

// Code transplanted from evalsum demo
TEST_F(UTCryptotiming, eval_sum_timing) {
    usint m = 22;
    BigInteger modulusP(89);

    BigInteger modulusQ("1267650600228229401496703214121");
    BigInteger squareRootOfRoot("498618454049802547396506932253");

    BigInteger bigmodulus("1645504557321206042154969182557350504982735865633579863348616321");
    BigInteger bigroot("201473555181182026164891698186176997440470643522932663932844212");

    auto cycloPoly = GetCyclotomicPolynomial<BigVector, BigInteger>(m, modulusQ);
    ChineseRemainderTransformArb<BigInteger, BigVector>::SetCylotomicPolynomial(cycloPoly, modulusQ);

    float stdDev = 4;

    usint batchSize = 8;

    shared_ptr<ILParams> params(new ILParams(m, modulusQ, squareRootOfRoot, bigmodulus, bigroot));

    EncodingParams encodingParams(new EncodingParamsImpl(89, batchSize, PackedEncoding::GetAutomorphismGenerator(m)));

    PackedEncoding::SetParams(m, encodingParams);

    CryptoContext<Poly> cc = CryptoContextFactory<Poly>::genCryptoContextLTV(params, encodingParams, 16, stdDev);

    cc->Enable(ENCRYPTION|SHE);
    vector<TimingInfo> times;
    cc->StartTiming(&times);
    LPKeyPair<Poly> kp = cc->KeyGen();

    Ciphertext<Poly> ciphertext;

    Plaintext intArray = cc->MakePackedPlaintext(std::vector<uint64_t>{1, 2, 3, 4, 5, 6, 7, 8, 9, 10});

    ciphertext = cc->Encrypt(kp.publicKey, intArray);
    uint len = (uint) times.size();

    cc->EvalSumKeyGen(kp.secretKey, kp.publicKey);
    ASSERT_TRUE(times.size() == len + 1) << "EvalSumKeyGen op failed to push to timing vector";
    ASSERT_TRUE(times.back().operation == OpEvalSumKeyGen) << "EvalSumKeyGen op applied an incorrect optype to its data:";
    if (times.size() == len + 1) { len++; }

    cc->EvalSum(ciphertext, batchSize);
    ASSERT_TRUE(times.size() == len + 1) << "EvalSum op failed to push to timing vector";
    ASSERT_TRUE(times.back().operation == OpEvalSum) << "EvalSum op applied an incorrect optype to its data:";
}

// Code transplanted from BFVEvalMultMany test
TEST_F(UTCryptotiming, eval_mult_timing){
    int relWindow = 1;
    int plaintextModulus = 256;
    double sigma = 4;
    double rootHermiteFactor = 1.03;

    CryptoContext<Poly> cc = CryptoContextFactory<Poly>::genCryptoContextBFV(
            plaintextModulus, rootHermiteFactor, relWindow, sigma, 0, 3, 0, OPTIMIZED, 4);
    cc->Enable(ENCRYPTION|SHE);

    vector<TimingInfo>	times;
    cc->StartTiming(&times);

    LPKeyPair<Poly> kp = cc->KeyGen();

    std::vector<int64_t> vectorOfInts1 = {1,2,3,4,5};
    std::vector<int64_t> vectorOfInts2 = {2,0,0,0,0};

    Ciphertext<Poly> ciphertext1 = cc->Encrypt(kp.publicKey,
            cc->MakeCoefPackedPlaintext(std::vector<int64_t>{1,2,3,4,5}));
    Ciphertext<Poly> ciphertext2 = cc->Encrypt(kp.publicKey,
            cc->MakeCoefPackedPlaintext(std::vector<int64_t>{2,0,0,0,0}));

    uint len = (uint)times.size();

    cc->EvalMultKeysGen(kp.secretKey);
    ASSERT_TRUE(times.size()== len+1) << "EvalMultKeyGen op failed to push to timing vector";
    ASSERT_TRUE(times.back().operation == OpEvalMultKeyGen) << "EvalMultKeyGen op applied an incorrect optype to its data:";
    if(times.size() == len+1) { len++; }

    cc->EvalMult(ciphertext1,ciphertext2);
    ASSERT_TRUE(times.size()== len+1) << "EvalMult op in function EvalMult(cipher, cipher) failed to push to timing vector";
    ASSERT_TRUE(times.back().operation == OpEvalMult) << "EvalMult op in function EvalMult(cipher, cipher) applied an incorrect optype to its data:";
    if(times.size() == len+1) { len++; }

    cc->EvalMult(ciphertext1, cc->MakeCoefPackedPlaintext(std::vector<int64_t>{2,0,0,0,0}));
    ASSERT_TRUE(times.size()== len+1) << "EvalMult op in function EvalMult(cipher, plain) failed to push to timing vector";
    ASSERT_TRUE(times.back().operation == OpEvalMult) << "EvalMult op in function EvalMult(cipher, plain) applied an incorrect optype to its data:";
    if(times.size() == len+1) { len++; }

    cc->EvalMultNoRelin(ciphertext1,ciphertext2);
    ASSERT_TRUE(times.size()== len+1) << "EvalMult op in function EvalMultNoRelin failed to push to timing vector";
    ASSERT_TRUE(times.back().operation == OpEvalMult) << "EvalMult op in function EvalMultNoRelin applied an incorrect optype to its data:";
    if(times.size() == len+1) { len++; }

    cc->EvalMultAndRelinearize(ciphertext1,ciphertext2);
    ASSERT_TRUE(times.size()== len+1) << "EvalMult op in function EvalMultAndRelinearize failed to push to timing vector";
    ASSERT_TRUE(times.back().operation == OpEvalMult) << "EvalMult op in function EvalMultAndRelinearize applied an incorrect optype to its data:";
    if(times.size() == len+1) { len++; }

    // TODO Add in Matrix mult here once section for encrypt/decrypt matrix is complete

}

TEST_F(UTCryptotiming, Automorphism_timing){
    CryptoContext<Poly> cc = CryptoContextFactory<Poly>::genCryptoContextNull(0, 256);
    cc->Enable(ENCRYPTION|SHE);
    vector<TimingInfo>	times;
    cc->StartTiming(&times);

    LPKeyPair<Poly> kp = cc->KeyGen();

    Ciphertext<Poly> ciphertext;
    Plaintext plaintext = Plaintext( new StringEncoding( cc->GetElementParams(), cc->GetEncodingParams(), "cryptotiming" ) );
    ciphertext = cc->Encrypt(kp.publicKey, plaintext);
    uint len = (uint)times.size();

    auto evalKeys = cc->EvalAutomorphismKeyGen(kp.secretKey, std::vector<usint>{1,2,3,4});
    ASSERT_TRUE(times.size()== len+1) << "EvalAutomorphismK op failed to push to timing vector";
    ASSERT_TRUE(times.back().operation == OpEvalAutomorphismK) << "EvalAutomorphismK op applied an incorrect optype to its data:";
    if(times.size() == len+1) { len++; }

    evalKeys = cc->EvalAutomorphismKeyGen(kp.publicKey, kp.secretKey, std::vector<usint>{1,2,3,4});
    ASSERT_TRUE(times.size()== len+1) << "EvalAutomorphismKeyGen op failed to push to timing vector";
    ASSERT_TRUE(times.back().operation == OpEvalAutomorphismKeyGen) << "EvalAutomorphismKeyGen op applied an incorrect optype to its data:";
    if(times.size() == len+1) { len++; }

    cc->EvalAutomorphism(ciphertext, 1, *evalKeys);
    ASSERT_TRUE(times.size()== len+1) << "EvalAutomorphismI op failed to push to timing vector";
    ASSERT_TRUE(times.back().operation == OpEvalAutomorphismI) << "EvalAutomorphismI op applied an incorrect optype to its data:";

}

TEST_F(UTCryptotiming, PRE_timing){
    CryptoContext<Poly> cc = CryptoContextFactory<Poly>::genCryptoContextNull(0, 256);
    vector<TimingInfo>	times;
    uint len = 0;
    cc->StartTiming(&times);
    cc->Enable(ENCRYPTION|PRE);
    Plaintext plaintext( new StringEncoding(cc->GetElementParams(), cc->GetEncodingParams(), "cryptotiming") );

    LPKeyPair<Poly> kp = cc->KeyGen();
    LPKeyPair<Poly> kp2 = cc->KeyGen();
    len = (uint)times.size();

    LPEvalKey<Poly> evalKey = cc->ReKeyGen(kp2.publicKey, kp.secretKey);
    ASSERT_TRUE(times.size() == len+1) << "ReKeyGenPubPri op failed to push to timing vector";
    ASSERT_TRUE(times.back().operation == OpReKeyGenPubPri) << "ReKeyGenPubPri op applied an incorrect optype to its data";
    if(times.size() == len+1) { len++; }

    cc->ReKeyGen(kp2.secretKey, kp.secretKey);
    ASSERT_TRUE(times.size() == len+1) << "ReKeyGenPriPri op failed to push to timing vector";
    ASSERT_TRUE(times.back().operation == OpReKeyGenPriPri) << "ReKeyGenPriPri op applied an incorrect optype to its data";
    if(times.size() == len+1) { len++; }

    Ciphertext<Poly> ciphertext = cc->Encrypt(kp.publicKey, plaintext);
    len = (uint)times.size();

    cc->ReEncrypt(evalKey, ciphertext);
    ASSERT_TRUE(times.size() == len+1) << "ReEncrypt op failed to push to timing vector";
    ASSERT_TRUE(times.back().operation == OpReEncrypt) << "ReEncrypt op applied an incorrect optype to its data:";

}


TEST_F(UTCryptotiming, timing_keygen){ //TODO delete variable storage of key pairs that are unecessary, after transferring them
    CryptoContext<Poly> cc = CryptoContextFactory<Poly>::genCryptoContextNull(0, 256);
    vector<TimingInfo>	times;
    uint len = 0;
    cc->StartTiming(&times);
    cc->Enable(ENCRYPTION|MULTIPARTY);

    LPKeyPair<Poly> kp = cc->KeyGen();
    ASSERT_TRUE(times.size() == len+1) << "KeyGen op failed to push to timing vector";
    ASSERT_TRUE(times.back().operation == OpKeyGen) << "KeyGen op applied an incorrect optype to its data";
    if(times.size() == len+1) { len++; }

    LPKeyPair<Poly> mpkp = cc->MultipartyKeyGen(kp.publicKey);
    ASSERT_TRUE(times.size() == len+1) << "MultiPartyKeyGenKey op failed to push to timing vector";
    ASSERT_TRUE(times.back().operation == OpMultiPartyKeyGenKey) << "MultiPartyKeyGenKey op applied an incorrect optype to its data";
    if(times.size() == len+1) { len++; }

    const vector<LPPrivateKey<Poly>> skv{kp.secretKey, mpkp.secretKey};
    LPKeyPair<Poly> mpskp = cc->MultipartyKeyGen(skv);
    ASSERT_TRUE(times.size() == len+1) << "MultiPartyKeyGenKeyvec op failed to push to timing vector";
    ASSERT_TRUE(times.back().operation == OpMultiPartyKeyGenKeyvec) << "MultiPartyKeyGenKeyvec op applied an incorrect optype to its data";
    if(times.size() == len+1) { len++; }

    LPKeyPair<Poly> skp = cc->SparseKeyGen();
    ASSERT_TRUE(times.size() == len+1) << "MultiPartyKeyGenKeyvec op failed to push to timing vector";
    ASSERT_TRUE(times.back().operation == OpSparseKeyGen) << "MultiPartyKeyGenKeyvec op applied an incorrect optype to its data";
    if(times.size() == len+1) { len++; }

    sleep(15000);
}
