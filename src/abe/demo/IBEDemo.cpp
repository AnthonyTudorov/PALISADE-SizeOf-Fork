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
#include "../lib/abecontext.h"
#include "palisade.h"

using namespace lbcrypto;

int main(){
    //Create context under given ringsize and base
     ABEContext<NativePoly> context;
    context.GenerateIBEContext(1024,512);
    
    //Generate master keys
    IBEMasterPublicKey<NativePoly> mpk;
	IBEMasterSecretKey<NativePoly> msk;
    context.Setup(&mpk,&msk);
    
    //Generate a random identifier for the user
    IBEUserIdentifier<NativePoly> id(context.GenerateRandomElement());
    
    //Generate the secret key for the user
    IBESecretKey<NativePoly> sk;
	context.KeyGen(msk,mpk,id,&sk);
    
    //Generate a plaintext
    std::vector<int64_t> vectorOfInts = { 1,0,0,1,1,0,1,0, 1, 0};
    Plaintext pt = context.MakeCoefPackedPlaintext(vectorOfInts);
    
    //Encrypt the plaintext
    IBECiphertext<NativePoly> ct;
	context.Encrypt(mpk,id,pt,&ct);
    
    //Decrypt the ciphertext
	Plaintext dt = context.Decrypt(id,id,sk,ct);
    
    //Check if original plaintext and decrypted plaintext match
    if(pt->GetElement<NativePoly>() == dt->GetElement<NativePoly>()){
        std::cout<<"Encryption & decryption successful"<<std::endl;
    }else{
        std::cout<<"Encryption & decryption failed"<<std::endl;
    }

    return 0;
}