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
#include "../lib/abecontext.h"

using namespace lbcrypto;
int main(){
    //Create context under security level and number of attributes
    ABEContext<NativePoly> context;
    context.GenerateCPABEContext(6,1024,64);
    
    //Generate master keys
    CPABEMasterPublicKey<NativePoly> mpk;
	CPABEMasterSecretKey<NativePoly> msk;
    context.Setup(&mpk,&msk);

    //Create a random access policy and user attribute set
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

    //Create the key corresponding to the access policy
    CPABESecretKey<NativePoly> sk;
	context.KeyGen(msk,mpk,ua,&sk);
    
    //Create a plaintext
    std::vector<int64_t> vectorOfInts = { 1,0,0,1,1,0,1,0, 1, 0};
    Plaintext pt = context.MakeCoefPackedPlaintext(vectorOfInts);
    
    //Encrypt the plaintext
    CPABECiphertext<NativePoly> ct;
	context.Encrypt(mpk,ap,pt,&ct);
    
    //Decrypt the ciphertext
	Plaintext dt = context.Decrypt(ap,ua,sk,ct);
    //Check if original plaintext and decrypted plaintext match
    if(pt->GetElement<NativePoly>() == dt->GetElement<NativePoly>()){
        std::cout<<"Encryption & decryption successful"<<std::endl;
    }else{
        std::cout<<"Encryption & decryption failed"<<std::endl;
    }
}