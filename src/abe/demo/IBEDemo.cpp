/**
 * @file IBEDemo.cpp - Demo file for identity based encryption

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
#include "../lib/ibe.h"
#include "palisade.h"

using namespace lbcrypto;

int main(){
        //Prepare parameters for the execution
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
        
        //Create and generate master key pair
        IBEMasterPublicKey<NativePoly> mpk;
        IBEMasterSecretKey<NativePoly> msk;
        sch.Setup(params,&mpk,&msk);

        //Generate a random user identifier
        NativePoly r(params->GetDUG(),params->GetTrapdoorParams()->GetElemParams(), EVALUATION);
        IBEUserIdentifier<NativePoly> id(r);
        
        //Generate a secret key for the identifier
        IBESecretKey<NativePoly> sk;
        sch.KeyGen(params,msk,mpk,id,&sk);
    
        //Generate a random plaintext
        NativePoly u(params->GetDUG(),params->GetTrapdoorParams()->GetElemParams(), COEFFICIENT);
        u.SetValues(bug.GenerateVector(params->GetTrapdoorParams()->GetN(),smodulus), COEFFICIENT);
        IBEPlaintext<NativePoly> pt(u);
        
        //Encrypt the plaintext
        IBECiphertext<NativePoly> ct;
        sch.Encrypt(params,mpk,id,pt,&ct);
        //Decrypt the ciphertext
        IBEPlaintext<NativePoly> dt;
        sch.Decrypt(params,id,id,sk,ct,&dt);

        //Check if original plaintext and decrypted plaintext match
        if(pt.GetPText()==dt.GetPText()){
            std::cout<<"Encryption & decryption successful"<<std::endl;
        }else{
            std::cout<<"Encryption & decryption failed"<<std::endl;
        }




    return 0;
}