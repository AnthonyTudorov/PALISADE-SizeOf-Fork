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
#include "lattice/elemparamfactory.h"

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

TEST_F(UTCryptotiming, encrypt_decrypt){
    CryptoContext<Poly> cc = CryptoContextFactory<Poly>::genCryptoContextNull(0, 256);
    cc->Enable(ENCRYPTION);
    vector<TimingInfo>	times;
    cc->StartTiming(&times);
    Plaintext plaintext = Plaintext( new StringEncoding( cc->GetElementParams(), cc->GetEncodingParams(), "cryptotiming" ) );

    LPKeyPair<Poly> kp = cc->KeyGen();
    uint len = (uint)times.size();

    cc->Encrypt(kp.publicKey, plaintext);
    ASSERT_TRUE(times.size() > len) << "EncryptPub op failed to push to timing vector";
    ASSERT_TRUE(times.back().operation == OpEncryptPub) << "EncryptPub op applied an incorrect optype to its data:";
    if(times.size() > len) { len = times.size(); }

    Ciphertext<Poly> ciphertext;
    ciphertext = cc->Encrypt(kp.secretKey, plaintext);
    ASSERT_TRUE(times.size() > len) << "EncryptPriv op failed to push to timing vector";
    ASSERT_TRUE(times.back().operation == OpEncryptPriv) << "EncryptPriv op applied an incorrect optype to its data:";
    if(times.size() > len) { len = times.size(); }

    cc->Decrypt(kp.secretKey, ciphertext, &plaintext);
    ASSERT_TRUE(times.size() > len) << "Decrypt op failed to push to timing vector";
    ASSERT_TRUE(times.back().operation == OpDecrypt) << "Decrypt op applied an incorrect optype to its data:";
    if(times.size() > len) { len = times.size(); }

}

TEST_F(UTCryptotiming, key_switch){
    CryptoContext<Poly> cc = CryptoContextFactory<Poly>::genCryptoContextNull(8, 256);
    cc->Enable(ENCRYPTION|SHE);
    vector<TimingInfo>	times;
    cc->StartTiming(&times);

    LPKeyPair<Poly> kp = cc->KeyGen();
    LPKeyPair<Poly> kp2 = cc->KeyGen();
    Ciphertext<Poly> ct1 = cc->Encrypt(kp.publicKey, cc->MakeIntegerPlaintext(0));
    uint len = (uint)times.size();

    auto swk = cc->KeySwitchGen(kp.secretKey, kp2.secretKey);
    ASSERT_TRUE(times.size() > len) << "KeySwitchGen op failed to push to timing vector";
    ASSERT_TRUE(times.back().operation == OpKeySwitchGen) << "KeySwitchGen op applied an incorrect optype to its data:";
    if(times.size() > len) { len = times.size(); }

    cc->KeySwitch(swk, ct1);
    ASSERT_TRUE(times.size() > len) << "KeySwitch op failed to push to timing vector";
    ASSERT_TRUE(times.back().operation == OpKeySwitch) << "KeySwitch op applied an incorrect optype to its data:";
}

TEST_F(UTCryptotiming, mod_reduce){
    CryptoContext<Poly> cc = CryptoContextFactory<Poly>::genCryptoContextNull(8, 256);
    cc->Enable(ENCRYPTION|LEVELEDSHE);
    vector<TimingInfo>	times;
    cc->StartTiming(&times);

    LPKeyPair<Poly> kp = cc->KeyGen();
    Ciphertext<Poly> ct = cc->Encrypt(kp.publicKey, cc->MakeIntegerPlaintext(4));
    uint len = (uint)times.size();

    cc->ModReduce(ct);
    ASSERT_TRUE(times.size() > len) << "ModReduce op failed to push to timing vector";
    ASSERT_TRUE(times.back().operation == OpModReduce) << "ModReduce op applied an incorrect optype to its data:";
}

TEST_F(UTCryptotiming, eval_merge){
    CryptoContext<Poly> cc = CryptoContextFactory<Poly>::genCryptoContextNull(8,257);
    cc->Enable(ENCRYPTION|SHE);
    vector<TimingInfo>	times;
    cc->StartTiming(&times);

    LPKeyPair<Poly> kp = cc->KeyGen();
    vector<Ciphertext<Poly>> ciphers = { cc->Encrypt(kp.publicKey, cc->MakeIntegerPlaintext(4)), cc->Encrypt(kp.publicKey, cc->MakeIntegerPlaintext(3)),
                                         cc->Encrypt(kp.publicKey, cc->MakeIntegerPlaintext(3)) };

    cc->EvalAtIndexKeyGen(kp.secretKey, vector<int32_t>{-1});
    uint len = (uint)times.size();

    cc->EvalMerge(ciphers);
    ASSERT_TRUE(times.size() > len) << "EvalMerge op failed to push to timing vector";
    ASSERT_TRUE(times.back().operation == OpEvalMerge) << "EvalMerge op applied an incorrect optype to its data:";
}

TEST_F(UTCryptotiming, eval_add){
    CryptoContext<Poly> cc = CryptoContextFactory<Poly>::genCryptoContextNull(8,256);
    cc->Enable(ENCRYPTION|SHE);

    vector<TimingInfo>	times;
    cc->StartTiming(&times);
    LPKeyPair<Poly> kp = cc->KeyGen();
    Ciphertext<Poly> ct1 = cc->Encrypt(kp.publicKey, cc->MakeIntegerPlaintext(4));
    Ciphertext<Poly> ct2 = cc->Encrypt(kp.publicKey, cc->MakeIntegerPlaintext(7));
    uint len = (uint)times.size();

    cc->EvalAdd(ct1, ct2);
    ASSERT_TRUE(times.size() > len) << "EvalAdd op failed to push to timing vector";
    ASSERT_TRUE(times.back().operation == OpEvalAdd) << "EvalAdd op applied an incorrect optype to its data:";
    if (times.size() > len) { len = (uint)times.size(); }

    cc->EvalAdd(ct1, cc->MakeIntegerPlaintext(7));
    ASSERT_TRUE(times.size() > len) << "EvalAddPlain op failed to push to timing vector";
    ASSERT_TRUE(times.back().operation == OpEvalAddPlain) << "EvalAddPlain op applied an incorrect optype to its data:";
}

TEST_F(UTCryptotiming, eval_sub){
    CryptoContext<Poly> cc = CryptoContextFactory<Poly>::genCryptoContextNull(8,256);
    cc->Enable(ENCRYPTION|SHE);

    vector<TimingInfo>	times;
    cc->StartTiming(&times);
    LPKeyPair<Poly> kp = cc->KeyGen();
    Ciphertext<Poly> ct1 = cc->Encrypt(kp.publicKey, cc->MakeIntegerPlaintext(4));
    Ciphertext<Poly> ct2 = cc->Encrypt(kp.publicKey, cc->MakeIntegerPlaintext(7));
    uint len = (uint)times.size();

    cc->EvalSub(ct1, ct2);
    ASSERT_TRUE(times.size() > len) << "EvalSub op failed to push to timing vector";
    ASSERT_TRUE(times.back().operation == OpEvalSub) << "EvalSub op applied an incorrect optype to its data:";
    if (times.size() > len) { len = (uint)times.size(); }

    cc->EvalSub(ct1, cc->MakeIntegerPlaintext(7));
    ASSERT_TRUE(times.size() > len) << "EvalSubPlain op failed to push to timing vector";
    ASSERT_TRUE(times.back().operation == OpEvalSubPlain) << "EvalSubPlain op applied an incorrect optype to its data:";
}

TEST_F(UTCryptotiming, eval_negate){
    CryptoContext<Poly> cc = CryptoContextFactory<Poly>::genCryptoContextNull(0, 256);
    cc->Enable(ENCRYPTION|SHE);
    vector<TimingInfo>	times;
    cc->StartTiming(&times);

    LPKeyPair<Poly> kp = cc->KeyGen();

    Ciphertext<Poly> ct;
    Plaintext pt = Plaintext( new StringEncoding( cc->GetElementParams(), cc->GetEncodingParams(), "cryptotiming" ) );
    ct = cc->Encrypt(kp.publicKey, pt);
    uint len = (uint)times.size();

    cc->EvalNegate(ct);
    ASSERT_TRUE(times.size() > len) << "EvalNeg op failed to push to timing vector";
    ASSERT_TRUE(times.back().operation == OpEvalNeg) << "EvalNeg op applied an incorrect optype to its data:";
}

TEST_F(UTCryptotiming, eval_rightshift){
    CryptoContext<Poly> cc = CryptoContextFactory<Poly>::genCryptoContextNull(8,256);
    cc->Enable(ENCRYPTION|SHE);
    vector<TimingInfo>	times;
    cc->StartTiming(&times);

    LPKeyPair<Poly> kp = cc->KeyGen();

    Ciphertext<Poly> ct =  cc->Encrypt(kp.publicKey, cc->MakeFractionalPlaintext(4));
    uint len = (uint)times.size();

    cc->EvalRightShift(ct, 1);
    // EvalRightShift calls EvalMult, so if both timing functions work, the method pushes two objects to the vector
    ASSERT_TRUE(times.size() > len) << "EvalRightShift op failed to push to timing vector";
    ASSERT_TRUE(times.back().operation == OpEvalRightShift) << "EvalRightShift op applied an incorrect optype to its data:";
}

// Code transplanted from evalsum demo
TEST_F(UTCryptotiming, eval_sum) {
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

    Plaintext intArray = cc->MakePackedPlaintext(std::vector<uint64_t>{1,2});

    ciphertext = cc->Encrypt(kp.publicKey, intArray);
    uint len = (uint) times.size();

    cc->EvalSumKeyGen(kp.secretKey, kp.publicKey);
    ASSERT_TRUE(times.size() > len) << "EvalSumKeyGen op failed to push to timing vector";
    ASSERT_TRUE(times.back().operation == OpEvalSumKeyGen) << "EvalSumKeyGen op applied an incorrect optype to its data:";
    if (times.size() == len + 1) { len++; }

    cc->EvalSum(ciphertext, batchSize);
    ASSERT_TRUE(times.size() > len) << "EvalSum op failed to push to timing vector";
    ASSERT_TRUE(times.back().operation == OpEvalSum) << "EvalSum op applied an incorrect optype to its data:";
}

// Code transplanted from BFVEvalMultMany test
TEST_F(UTCryptotiming, eval_mult){
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

    Ciphertext<Poly> ct1 = cc->Encrypt(kp.publicKey, cc->MakeScalarPlaintext(1));
    Ciphertext<Poly> ct2 = cc->Encrypt(kp.publicKey, cc->MakeScalarPlaintext(1));

    uint len = (uint)times.size();

    cc->EvalMultKeysGen(kp.secretKey);
    ASSERT_TRUE(times.size() > len) << "EvalMultKeyGen op failed to push to timing vector";
    ASSERT_TRUE(times.back().operation == OpEvalMultKeyGen) << "EvalMultKeyGen op applied an incorrect optype to its data:";
    if(times.size() > len) { len = times.size(); }

    cc->EvalMult(ct1, ct2);
    ASSERT_TRUE(times.size() > len) << "EvalMult op in function EvalMult(cipher, cipher) failed to push to timing vector";
    ASSERT_TRUE(times.back().operation == OpEvalMult) << "EvalMult op in function EvalMult(cipher, cipher) applied an incorrect optype to its data:";
    if(times.size() > len) { len = times.size(); }

    cc->EvalMult(ct1, cc->MakeScalarPlaintext(1));
    ASSERT_TRUE(times.size() > len) << "EvalMult op in function EvalMult(cipher, plain) failed to push to timing vector";
    ASSERT_TRUE(times.back().operation == OpEvalMult) << "EvalMult op in function EvalMult(cipher, plain) applied an incorrect optype to its data:";
    if(times.size() > len) { len = times.size(); }

    cc->EvalMultNoRelin(ct1, ct2);
    ASSERT_TRUE(times.size() > len) << "EvalMult op in function EvalMultNoRelin failed to push to timing vector";
    ASSERT_TRUE(times.back().operation == OpEvalMult) << "EvalMult op in function EvalMultNoRelin applied an incorrect optype to its data:";
    if(times.size() > len) { len = times.size(); }

    cc->EvalMultAndRelinearize(ct1 ,ct2);
    ASSERT_TRUE(times.size() > len) << "EvalMult op in function EvalMultAndRelinearize failed to push to timing vector";
    ASSERT_TRUE(times.back().operation == OpEvalMult) << "EvalMult op in function EvalMultAndRelinearize applied an incorrect optype to its data:";
    if(times.size() > len) { len = times.size(); }

    // TODO Add in Matrix mult here once section for encrypt/decrypt matrix is complete

}

TEST_F(UTCryptotiming, eval_mult_many){
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

    Ciphertext<Poly> ct1 = cc->Encrypt(kp.publicKey, cc->MakeScalarPlaintext(1));
    Ciphertext<Poly> ct2 = cc->Encrypt(kp.publicKey, cc->MakeScalarPlaintext(1));
    vector<Ciphertext<Poly>> cipherTextList = {ct1, ct2};
    cc->EvalMultKeysGen(kp.secretKey);
    uint len = (uint)times.size();

    cc->EvalMultMany(cipherTextList);
    ASSERT_TRUE(times.size() > len) << "EvalMultMany op failed to push to timing vector";
    ASSERT_TRUE(times.back().operation == OpEvalMultMany) << "EvalMultMany op applied an incorrect optype to its data:";
}

TEST_F(UTCryptotiming, eval_index){
    CryptoContext<Poly> cc = CryptoContextFactory<Poly>::genCryptoContextNull(8,257);
    cc->Enable(ENCRYPTION|SHE);
    vector<TimingInfo>	times;
    cc->StartTiming(&times);

    LPKeyPair<Poly> kp = cc->KeyGen();
    int32_t n = cc->GetCryptoParameters()->GetElementParams()->GetCyclotomicOrder()/2;

    cc->EvalAtIndexKeyGen(kp.secretKey, vector<int32_t>{2});
    std::vector<uint64_t> vectorOfInts = {1};
    vectorOfInts.resize(n);


    auto ciphertext = cc->Encrypt(kp.publicKey, cc->MakePackedPlaintext(vectorOfInts));

    cc->EvalAtIndex(ciphertext, 2);

}

TEST_F(UTCryptotiming, ring_reduce){
    usint m = 16;
    float stdDev = 4;
    shared_ptr<Poly::Params> params = ElemParamFactory::GenElemParams<Poly::Params>(m);
    CryptoContext<Poly> cc = CryptoContextFactory<Poly>::genCryptoContextLTV(params, 2, 1, stdDev);
    cc->Enable(ENCRYPTION|LEVELEDSHE|SHE);
    vector<TimingInfo>	times;
    cc->StartTiming(&times);

    LPKeyPair<Poly> kp = cc->KeyGen();
    LPKeyPair<Poly> kp2 = cc->SparseKeyGen();// TODO ADD test for this keygen, or determine if it best falls here
    Ciphertext<Poly> ct1 = cc->Encrypt(kp.publicKey, cc->MakeIntegerPlaintext(0));
    auto swk = cc->KeySwitchGen(kp.secretKey, kp2.secretKey);
    uint len = (uint)times.size();

    cc->RingReduce(ct1, swk);
    ASSERT_TRUE(times.size() > len) << "RingReduce op failed to push to timing vector";
    ASSERT_TRUE(times.back().operation == OpRingReduce) << "RingReduce op applied an incorrect optype to its data:";

}

TEST_F(UTCryptotiming, automorphism){
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
    ASSERT_TRUE(times.size() > len) << "EvalAutomorphismK op failed to push to timing vector";
    ASSERT_TRUE(times.back().operation == OpEvalAutomorphismK) << "EvalAutomorphismK op applied an incorrect optype to its data:";
    if(times.size() > len) { len = times.size(); }

    evalKeys = cc->EvalAutomorphismKeyGen(kp.publicKey, kp.secretKey, std::vector<usint>{1,2,3,4});
    ASSERT_TRUE(times.size() > len) << "EvalAutomorphismKeyGen op failed to push to timing vector";
    ASSERT_TRUE(times.back().operation == OpEvalAutomorphismKeyGen) << "EvalAutomorphismKeyGen op applied an incorrect optype to its data:";
    if(times.size() > len) { len = times.size(); }

    cc->EvalAutomorphism(ciphertext, 1, *evalKeys);
    ASSERT_TRUE(times.size() > len) << "EvalAutomorphismI op failed to push to timing vector";
    ASSERT_TRUE(times.back().operation == OpEvalAutomorphismI) << "EvalAutomorphismI op applied an incorrect optype to its data:";

}

TEST_F(UTCryptotiming, PRE){
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
    ASSERT_TRUE(times.size() > len) << "ReKeyGenPubPri op failed to push to timing vector";
    ASSERT_TRUE(times.back().operation == OpReKeyGenPubPri) << "ReKeyGenPubPri op applied an incorrect optype to its data";
    if(times.size() > len) { len = times.size(); }

    cc->ReKeyGen(kp2.secretKey, kp.secretKey);
    ASSERT_TRUE(times.size() > len) << "ReKeyGenPriPri op failed to push to timing vector";
    ASSERT_TRUE(times.back().operation == OpReKeyGenPriPri) << "ReKeyGenPriPri op applied an incorrect optype to its data";
    if(times.size() > len) { len = times.size(); }

    Ciphertext<Poly> ciphertext = cc->Encrypt(kp.publicKey, plaintext);
    len = (uint)times.size();

    cc->ReEncrypt(evalKey, ciphertext);
    ASSERT_TRUE(times.size() > len) << "ReEncrypt op failed to push to timing vector";
    ASSERT_TRUE(times.back().operation == OpReEncrypt) << "ReEncrypt op applied an incorrect optype to its data:";

}

