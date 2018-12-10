
#include "palisade.h"
#include "../lib/cpabe.h"

using namespace lbcrypto;
int main(){
    

    usint sm = 1024 * 2;
    typename NativePoly::DggType dgg(SIGMA);
    typename NativePoly::DugType dug;
    typename NativePoly::Integer smodulus;
    typename NativePoly::Integer srootOfUnity;
    smodulus = FirstPrime<typename NativePoly::Integer>(34,sm);
    srootOfUnity = RootOfUnity(sm, smodulus);
    dug.SetModulus(smodulus);
	ILParamsImpl<typename NativePoly::Integer> ilParams = ILParamsImpl<typename NativePoly::Integer>(sm, smodulus, srootOfUnity);

    ChineseRemainderTransformFTT<BigVector>::PreCompute(srootOfUnity, sm, smodulus);
	DiscreteFourierTransform::PreComputeTable(sm);

        
        
    shared_ptr<ILParamsImpl<typename NativePoly::Integer>> silparams = std::make_shared<ILParamsImpl<typename NativePoly::Integer>>(ilParams);
    RLWETrapdoorParams<NativePoly> tparams(silparams,dgg,SIGMA,2,false);
	CPABEParams<NativePoly> abeparams(std::make_shared<RLWETrapdoorParams<NativePoly>>(tparams),6,dug);
    CPABEScheme<NativePoly> sch;
    shared_ptr<CPABEParams<NativePoly>>params = std::make_shared<CPABEParams<NativePoly>>(abeparams);
    CPABEMasterPublicKey<NativePoly> mpk;
    CPABEMasterSecretKey<NativePoly> msk;
    sch.Setup(params,&mpk,&msk);
    usint *s = new usint[6];
	int *w = new int[6];

    for(usint j=0; j<6; j++)
		s[j] = rand()%2;

	for(usint j=0; j<6; j++)
		w[j] = s[j];

	for(usint j=0; j<6; j++)
		if(w[j]==1) {
			w[j] = 0;
			break;
		}
	for(usint j=0; j<6; j++)
		if(s[j]==0) {
			w[j] = -1;
			break;
		}
    
    CPABEUserAccess<NativePoly> ua(s);
    CPABEAccessPolicy<NativePoly> ap(w);

    CPABESecretKey<NativePoly> sk;
    
    sch.KeyGen(params,msk,mpk,ua,&sk);
    typename NativePoly::BugType bug = typename NativePoly::BugType();
    NativePoly u(params->GetDUG(),params->GetTrapdoorParams()->GetElemParams(), COEFFICIENT);
    u.SetValues(bug.GenerateVector(params->GetTrapdoorParams()->GetN(),smodulus), COEFFICIENT);
    CPABEPlaintext<NativePoly> pt(u);
    CPABECiphertext<NativePoly> ct;
    sch.Encrypt(params,mpk,ap,pt,&ct);
    CPABEPlaintext<NativePoly> dt;
     sch.Decrypt(params,ap,ua,sk,ct,&dt);

    if(pt.GetPText()==dt.GetPText()){
        std::cout<<"Encryption & decryption successful"<<std::endl;
    }else{
        std::cout<<"Encryption & decryption failed"<<std::endl;
    }

	delete[] s;
	delete[] w;
    return 0;
}