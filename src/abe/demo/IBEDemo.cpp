#include "../lib/ibe.h"
#include "palisade.h"

using namespace lbcrypto;

int main(){

        usint sm = 1024 * 2;
        typename NativePoly::DggType dgg(SIGMA);
        typename NativePoly::DugType dug;
        typename NativePoly::BugType bug;
        typename NativePoly::Integer smodulus;
        typename NativePoly::Integer srootOfUnity;
        smodulus = FirstPrime<typename NativePoly::Integer>(32,sm);
        srootOfUnity = RootOfUnity(sm, smodulus);
        dug.SetModulus(smodulus);
		ILParamsImpl<typename NativePoly::Integer> ilParams = ILParamsImpl<typename NativePoly::Integer>(sm, smodulus, srootOfUnity);
        ChineseRemainderTransformFTT<BigVector>::PreCompute(srootOfUnity, sm, smodulus);
		DiscreteFourierTransform::PreComputeTable(sm);

        
        
        shared_ptr<ILParamsImpl<typename NativePoly::Integer>> silparams = std::make_shared<ILParamsImpl<typename NativePoly::Integer>>(ilParams);
        RLWETrapdoorParams<NativePoly> tparams(silparams,dgg,SIGMA,2,false);
		IBEParams<NativePoly> ibeparams(std::make_shared<RLWETrapdoorParams<NativePoly>>(tparams),dug);
        IBEScheme<NativePoly> sch;
        shared_ptr<IBEParams<NativePoly>> params = std::make_shared<IBEParams<NativePoly>>(ibeparams);
        IBEMasterPublicKey<NativePoly> mpk;
        IBEMasterSecretKey<NativePoly> msk;
        sch.Setup(params,&mpk,&msk);
        NativePoly r(params->GetDUG(),params->GetTrapdoorParams()->GetElemParams(), EVALUATION);
        IBEUserIdentifier<NativePoly> id(r);
        IBESecretKey<NativePoly> sk;
     sch.KeyGen(params,msk,mpk,id,&sk);
    NativePoly u(params->GetDUG(),params->GetTrapdoorParams()->GetElemParams(), COEFFICIENT);
    u.SetValues(bug.GenerateVector(params->GetTrapdoorParams()->GetN(),smodulus), COEFFICIENT);
    IBEPlaintext<NativePoly> pt(u);
    IBECiphertext<NativePoly> ct;
    sch.Encrypt(params,mpk,id,pt,&ct);
    IBEPlaintext<NativePoly> dt;
    sch.Decrypt(params,id,id,sk,ct,&dt);

    if(pt.GetPText()==dt.GetPText()){
        std::cout<<"Encryption & decryption successful"<<std::endl;
    }else{
        std::cout<<"Encryption & decryption failed"<<std::endl;
    }




    return 0;
}