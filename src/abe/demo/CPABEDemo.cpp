/**
 * @file CPABEDemo.cpp - Demo file for ciphertext-policy attribute based encryption

 * @author  TPOC: palisade@njit.edu
 *
 * @copyright Copyright (c) 2017, New Jersey Institute of Technology (NJIT)
 * All rights reserved.
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:
 * 1. Redistributions of source code must retain the above copyright notice, this
 * list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice, this
 * list of conditions and the following disclaimer in the documentation and/or other
 * materials provided with the distribution.
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR
 * ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
 * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
 * IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */
#include "palisade.h"
#include "../lib/cpabe.h"

using namespace lbcrypto;
int main(){
    
    //Prepare parameters for the execution
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
    
    //Create and generate master key pair
    CPABEMasterPublicKey<NativePoly> mpk;
    CPABEMasterSecretKey<NativePoly> msk;
    sch.Setup(params,&mpk,&msk);

    //Generate a random attribute set of user and access policy 
    std::vector<usint> s(6);
	std::vector<int> w(6);

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

    //Define a secret key for the policy and generate it
    CPABESecretKey<NativePoly> sk;
    sch.KeyGen(params,msk,mpk,ua,&sk);
    
    //Generate a random plaintext
    typename NativePoly::BugType bug = typename NativePoly::BugType();
    NativePoly u(params->GetDUG(),params->GetTrapdoorParams()->GetElemParams(), COEFFICIENT);
    u.SetValues(bug.GenerateVector(params->GetTrapdoorParams()->GetN(),smodulus), COEFFICIENT);
    CPABEPlaintext<NativePoly> pt(u);
    
    //Encrypt the plaintext
    CPABECiphertext<NativePoly> ct;
    sch.Encrypt(params,mpk,ap,pt,&ct);
    
    //Decrypt the ciphertext
    CPABEPlaintext<NativePoly> dt;
     sch.Decrypt(params,ap,ua,sk,ct,&dt);

    //Check if original plaintext and decrypted plaintext match
    if(pt.GetPText()==dt.GetPText()){
        std::cout<<"Encryption & decryption successful"<<std::endl;
    }else{
        std::cout<<"Encryption & decryption failed"<<std::endl;
    }
    return 0;
}