/**
 * @file GPVSource.cpp - Demo file for GPV signature scheme

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
#include "../lib/signaturecontext.h"

using namespace lbcrypto;
    int main(){
        SignatureContext<Poly> context;
        context.GenerateGPVContext(8,27,2);
        GPVVerificationKey<Poly> vk;
        GPVSignKey<Poly> sk;
        context.KeyGen(&sk,&vk);
        GPVPlaintext<Poly> plaintext, plaintext2;
        plaintext.SetPlaintext("This is a test");
        plaintext2.SetPlaintext("This is the wrong one");
        
        GPVSignature<Poly> signature;
        context.Sign(plaintext,sk,vk,&signature);
        bool result1 = context.Verify(plaintext,signature,vk);
        bool result2 = context.Verify(plaintext2,signature,vk);
        std::cout<<"Verif result 1: "<<result1<<std::endl;
        std::cout<<"Verif result 2: "<<result2<<std::endl;    
        return 0;    
    }