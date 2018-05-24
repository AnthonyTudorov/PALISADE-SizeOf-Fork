//
// Created by Matt Triplett on 5/21/18.
// This is the test development file and should never appear in Master
// All tests which appear here should be placed into their respective proper testing locaations
//
//

#include "../../test/include/gtest/gtest.h" //FIXME include/gtest/gtest.h
#include <iostream>
#include <regex>

#include "palisade.h"
#include "cryptocontext.h"
#include "ciphertext.cpp"
#include "cryptotiming.h"
#include "math/nbtheory.h"
#include "utils/utilities.h"
#include "utils/parmfactory.h"
#include "utils/serializablehelper.h"

using namespace std;
using namespace lbcrypto;


class MTest : public ::testing::Test {
protected:
    void SetUp() {
    }

    void TearDown() {
        CryptoContextFactory<Poly>::ReleaseAllContexts();
        CryptoContextFactory<DCRTPoly>::ReleaseAllContexts();
        CryptoContextImpl<Poly>::ClearEvalMultKeys();
        CryptoContextImpl<DCRTPoly>::ClearEvalMultKeys();
    }
};



TEST_F(MTest, null_encrypt_failure) {
    cerr << "MT TEST" << endl;
    usint m = 0;
    PlaintextModulus p = 256;
    CryptoContext<Poly> cc = CryptoContextFactory<Poly>::genCryptoContextNull(m, p);
    CryptoContext<Poly> cc2 = CryptoContextFactory<Poly>::genCryptoContextNull(m + 1, p);
//    cc->Enable(ENCRYPTION);
//    cc2->Enable(ENCRYPTION); //TODO COMMENT FOR WEIRD ERROR

    string pct = "testing the plain ciphertext encryption on null scheme";
    LPKeyPair<Poly> kp = cc->KeyGen();
//    unsigned int offset = 100;
//    usleep(offset);
    LPKeyPair<Poly> kp2 = cc2->KeyGen();
    Plaintext plaintext = cc->MakeStringPlaintext(pct);
    cerr << plaintext;
    EXPECT_THROW({
                     try {
                         cc->Encrypt(NULL, plaintext);
                     }
                     catch (const std::logic_error &e) {
                         EXPECT_STREQ("null key passed to Encrypt", e.what());
                         throw;
                     }
                 }, std::logic_error) << "null key encryption succeeded";

    EXPECT_THROW({
                     try {
                         cc->Encrypt(kp.publicKey, NULL);
                     }
                     catch (const std::logic_error &e) {
                         EXPECT_STREQ("null plaintext passed to Encrypt", e.what());
                         throw;
                     }
                 }, std::logic_error) << "null plaintext public encryption succeeded";

    EXPECT_THROW({
                     try {
                         cc->Encrypt(kp2.publicKey, plaintext);
                     }
                     catch (const std::logic_error &e) {
                         EXPECT_STREQ("key passed to Encrypt was not generated with this crypto context", e.what());
                         throw;
                     }
                 }, std::logic_error) << "non-context public key encryption succeeded";

    EXPECT_THROW({
                     try {
                         cc->Encrypt(kp.secretKey, NULL);
                     }
                     catch (const std::logic_error &e) {
                         EXPECT_STREQ("null plaintext passed to Encrypt", e.what());
                         throw;
                     }
                 }, std::logic_error) << "null plaintext private encryption succeeded";

    EXPECT_THROW({
                     try
                     {
                         cc->Encrypt(kp2.secretKey, plaintext);
                     }
                     catch( const std::logic_error& e)
                     {
                         EXPECT_STREQ("key passed to Encrypt was not generated with this crypto context", e.what());
                         throw;
                     }
                 }, std::logic_error) << "non-context private key encryption succeeded";
//    Ciphertext<Poly> ciphertext2 = cc->Encrypt(kp.publicKey, plaintext);




    cerr<<"end MT TEST"<<endl;
}

TEST_F(MTest, ciphertext_deserialze_failure){
    usint m = 0;
    PlaintextModulus p = 256;
    CryptoContext<Poly> cc = CryptoContextFactory<Poly>::genCryptoContextNull(m, p);
    cc->Enable(ENCRYPTION);
    LPKeyPair<Poly> kp = cc->KeyGen();
    std::string pct = "testing the plain ciphertext encryption on null scheme";
    Plaintext plaintext = cc->MakeStringPlaintext(pct);
    std::string ct = "";
    Serialized ser;

    Ciphertext<Poly> ciphertext = cc->Encrypt(kp.publicKey, plaintext);
    ciphertext->Serialize(&ser);
    SerializableHelper::SerializationToString(ser, ct);
    cerr << ct << endl << endl;

    ct = regex_replace(ct, regex("KeyTag"), "");
    cerr << ct << endl;
    SerializableHelper::StringToSerialization(ct, &ser);
    ASSERT_FALSE(ciphertext->Deserialize(ser)) << "missing KeyTag was not a fatal deserialization error";
//    ASSERT_TRUE( (Ciphertext<Poly>.Serialize(&ser)) ) <<"Serialize off ciphertext method failed";

}

