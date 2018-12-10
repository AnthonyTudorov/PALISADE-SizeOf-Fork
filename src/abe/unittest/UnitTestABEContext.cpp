#include "include/gtest/gtest.h"
#include <iostream>
#include <vector>

#include "../lib/math/backend.h"
#include "../lib/abecontext.h"


using namespace std;
using namespace lbcrypto;

template <class T>
class UTABE : public ::testing::Test {

public:


protected:
	UTABE() {}

	virtual void SetUp() {

	}

	virtual void TearDown() {

	}

	virtual ~UTABE() {  }

};
template <class Element>
void UnitTestCPABE(int32_t base, usint k, usint ringDimension,usint ell){
    ABEContext<Element> context;
    context.GenerateCPABEContext(ringDimension,k,base,ell,SIGMA,false);
    CPABEMasterPublicKey<Element> mpk;
	CPABEMasterSecretKey<Element> msk;
    context.Setup(&mpk,&msk);

    usint *s = new usint[ell];
	int *w = new int[ell];

    for(usint j=0; j<ell; j++)
		s[j] = rand()%2;

	for(usint j=0; j<ell; j++)
		w[j] = s[j];

	for(usint j=0; j<ell; j++)
		if(w[j]==1) {
			w[j] = 0;
			break;
		}
	for(usint j=0; j<ell; j++)
		if(s[j]==0) {
			w[j] = -1;
			break;
		}
    
    CPABEUserAccess<Element> ua(s);
    CPABEAccessPolicy<Element> ap(w);

    CPABESecretKey<Element> sk;
	context.KeyGen(msk,mpk,ua,&sk);
    CPABEPlaintext<Element> pt(context.GenerateRandomBinaryElement());
    CPABECiphertext<Element> ct;
	context.Encrypt(mpk,ap,pt,&ct);
    CPABEPlaintext<Element> dt;
	context.Decrypt(ap,ua,sk,ct,&dt);


    EXPECT_EQ(pt.GetPText(),dt.GetPText());

	delete[] s;
	delete[] w;
}
template <class Element>
void UnitTestIBE(int32_t base, usint k, usint ringDimension){
	
    ABEContext<Element> context;
    context.GenerateIBEContext(ringDimension,k,base,SIGMA,false);
    IBEMasterPublicKey<Element> mpk;
	IBEMasterSecretKey<Element> msk;
    context.Setup(&mpk,&msk);
    IBEUserIdentifier<Element> id(context.GenerateRandomElement());
    IBESecretKey<Element> sk;
	context.KeyGen(msk,mpk,id,&sk);
    IBEPlaintext<Element> pt(context.GenerateRandomBinaryElement());
    IBECiphertext<Element> ct;
	context.Encrypt(mpk,id,pt,&ct);
    IBEPlaintext<Element> dt;
	context.Decrypt(id,id,sk,ct,&dt);

	EXPECT_EQ(pt.GetPText(),dt.GetPText());
}


TEST(UTABE, cp_abe_base_poly_32) {
	UnitTestCPABE<Poly>(32,34, 1024,4);
}

TEST(UTABE, cp_abe_base_native_32) {
	UnitTestCPABE<NativePoly>(32,34, 1024,4);
}
TEST(UTABE, ibe_base_32_poly) {
	UnitTestIBE<Poly>(32,32,1024);
}

TEST(UTABE, ibe_base_32_native) {
	UnitTestIBE<NativePoly>(32,32,1024);
}