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


class UTPKECryptotiming : public ::testing::Test {
protected:
    void SetUp() {
    }

    void TearDown() {
        CryptoContextFactory<Poly>::ReleaseAllContexts();
        CryptoContextImpl<Poly>::ClearEvalMultKeys();
    }
};

using namespace std;
using namespace lbcrypto;

TEST_F(UTPKECryptotiming, timing_util_functions){
    CryptoContext<Poly> cc = CryptoContextFactory<Poly>::genCryptoContextNull(0, 256);
    vector<TimingInfo>	times;
    cc->StartTiming(&times);
    cc->Enable(ENCRYPTION);
    cc->KeyGen();
    ASSERT_TRUE(1 == times.size()) << "StartTiming failed to initialize timing procedures";

    cc->StopTiming();
    cc->KeyGen();
    ASSERT_TRUE(1 == times.size()) << "StopTiming did not stop timing procedures";

    cc->ResumeTiming();
    cc->KeyGen();
    ASSERT_TRUE(2 == times.size()) << "ResumeTiming did not resume timing procedures";

    cc->ResetTiming();
    ASSERT_TRUE(0 == times.size()) << "ResetTiming did not reset timing vector";
}

TEST_F(UTPKECryptotiming, PRE_timing){
    CryptoContext<Poly> cc = CryptoContextFactory<Poly>::genCryptoContextNull(0, 256);
    vector<TimingInfo>	times;
    uint len = 0;
    cc->StartTiming(&times);
    cc->Enable(ENCRYPTION|PRE);
    Plaintext plaintext( new StringEncoding(cc->GetElementParams(), cc->GetEncodingParams(), "cryptotiming") );

    LPKeyPair<Poly> kp = cc->KeyGen();
    ASSERT_TRUE(times.size() == len+1) << "KeyGen op failed to push to timing vector";
    ASSERT_TRUE(times.back().operation == OpKeyGen) << "KeyGen op applied an incorrect optype to its data";
    if(times.size() == len+1) { len++; }

    LPKeyPair<Poly> kp2 = cc->KeyGen();
    ASSERT_TRUE(times.size() == len+1) << "KeyGen op failed to push to timing vector";
    ASSERT_TRUE(times.back().operation == OpKeyGen) << "KeyGen op applied an incorrect optype to its data";
    if(times.size() == len+1) { len++; }

    LPEvalKey<Poly> evalKey = cc->ReKeyGen(kp2.publicKey, kp.secretKey);
    ASSERT_TRUE(times.size() == len+1) << "ReKeyGenPubPri op failed to push to timing vector";
    ASSERT_TRUE(times.back().operation == OpReKeyGenPubPri) << "ReKeyGenPubPri op applied an incorrect optype to its data";
    if(times.size() == len+1) { len++; }

    cc->ReKeyGen(kp2.secretKey, kp.secretKey);
    ASSERT_TRUE(times.size() == len+1) << "ReKeyGenPriPri op failed to push to timing vector";
    ASSERT_TRUE(times.back().operation == OpReKeyGenPriPri) << "ReKeyGenPriPri op applied an incorrect optype to its data";
    if(times.size() == len+1) { len++; }

    Ciphertext<Poly> ciphertext = cc->Encrypt(kp.publicKey, plaintext);
    ASSERT_TRUE(times.size() == len+1) << "Pub Encrypt op failed to push to timing vector";
    ASSERT_TRUE(times.back().operation == OpEncryptPub) << "Pub Encrypt op applied an incorrect optype to its data:";
    if(times.size() == len+1) { len++; }

    cc->ReEncrypt(evalKey, ciphertext);
    ASSERT_TRUE(times.size() == len+1) << "ReEncrypt op failed to push to timing vector";
    ASSERT_TRUE(times.back().operation == OpReEncrypt) << "ReEncrypt op applied an incorrect optype to its data:";

}




TEST_F(UTPKECryptotiming, timing_keygen){ //TODO delete variable storage of key pairs that are unecessary, after transferring them to
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


TEST_F(UTPKECryptotiming, cryptotiming_null){
    usint m = 0;
    PlaintextModulus p = 256;
    CryptoContext<Poly> cc = CryptoContextFactory<Poly>::genCryptoContextNull(m, p);
    string pct = "testing cryptotiming";
    vector<TimingInfo>	times;
    Ciphertext<Poly> ciphertext;
    uint len = 0;
    cc->StartTiming(&times);
    cc->Enable(ENCRYPTION);
    Plaintext plaintext = cc->MakeStringPlaintext(pct);
//    cerr<<times.size()<<endl;

    LPKeyPair<Poly> kp = cc->KeyGen();
    ASSERT_TRUE(times.size() == len+1) << "KeyGen op failed to push to timing vector";
    ASSERT_TRUE(times.back().operation == OpKeyGen) << "KeyGen op applied an incorrect optype to its data";
    if(times.size() == len+1) { len++; }

    cc->Encrypt(kp.publicKey, plaintext);
    ASSERT_TRUE(times.size()== len+1) << "Pub Encrypt op failed to push to timing vector";
    ASSERT_TRUE(times.back().operation == OpEncryptPub) << "Pub Encrypt op applied an incorrect optype to its data:";
    if(times.size() == len+1) { len++; }

    ciphertext = cc->Encrypt(kp.secretKey, plaintext);
    ASSERT_TRUE(times.size()== len+1) << "Private Encrypt op failed to push to timing vector";
    ASSERT_TRUE(times.back().operation == OpEncryptPriv) << "Private Encrypt op applied an incorrect optype to its data:";
    if(times.size() == len+1) { len++; }

    cc->Decrypt(kp.secretKey, ciphertext, &plaintext);
    ASSERT_TRUE(times.size()== len+1) << "Decrypt op failed to push to timing vector";
    ASSERT_TRUE(times.back().operation == OpDecrypt) << "Decrypt op applied an incorrect optype to its data:";
    if(times.size() == len+1) { len++; }



    Serialized ser;
    ciphertext->Serialize(&ser);

    sleep(15000);

}
