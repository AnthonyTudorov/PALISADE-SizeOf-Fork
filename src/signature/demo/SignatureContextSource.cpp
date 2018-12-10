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