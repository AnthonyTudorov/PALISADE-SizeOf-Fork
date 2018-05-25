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
    ASSERT_TRUE(len+1 == times.size()) << "ResumeTiming did not resume timing procedures";

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

TEST_F(UTCryptotiming, stream_encrypt_decrypt){}

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

    auto evalKeys = cc->EvalAutomorphismKeyGen(kp.publicKey, kp.secretKey, std::vector<usint>{1,2,3,4});
    ASSERT_TRUE(times.size()== len+1) << "EvalAutomorphismKeyGen op failed to push to timing vector";
    ASSERT_TRUE(times.back().operation == OpEvalAutomorphismKeyGen) << "EvalAutomorphismKeyGen op applied an incorrect optype to its data:";
    if(times.size() == len+1) { len++; }

    cc->EvalAutomorphism(ciphertext, 1, *evalKeys);
    ASSERT_TRUE(times.size()== len+1) << "EvalAutomorphismI op failed to push to timing vector";
    ASSERT_TRUE(times.back().operation == OpEvalAutomorphismI) << "EvalAutomorphismI op applied an incorrect optype to its data:";
    if(times.size() == len+1) { len++; }

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
    sleep(15000);

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
}
