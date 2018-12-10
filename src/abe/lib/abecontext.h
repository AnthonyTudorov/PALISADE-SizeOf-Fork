 #ifndef ABE_ABECONTEXT_H
 #define ABE_ABECONTEXT_H

#include "cpabe.h"
#include "ibe.h"
#include "abeparamset.h"

 namespace lbcrypto{
    template <class Element>
    class ABEContext{
        public:
            /*
            *Default constructor
            */
            ABEContext(){}
            void GenerateCPABEContext(usint ringsize,usint bits,usint base,usint ell,double stddev, bool bal=false);
            void GenerateIBEContext(usint ringsize,usint bits,usint base,double stddev, bool bal=false);
            void GenerateIBEContext(ABESecurityLevel security);
            void GenerateCPABEContext(ABESecurityLevel security);
            void Setup(ABECoreMasterPublicKey<Element>* pk,ABECoreMasterSecretKey<Element>* sk);
            void KeyGen(const ABECoreMasterSecretKey<Element> & msk,const ABECoreMasterPublicKey<Element>& mpk, const ABECoreAccessPolicy<Element> &,ABECoreSecretKey<Element>* sk);
            void Encrypt(const ABECoreMasterPublicKey<Element> & mpk,const ABECoreAccessPolicy<Element> & ap,const ABECorePlaintext<Element> & ptext,ABECoreCiphertext<Element>* ct);
            void Decrypt(const ABECoreAccessPolicy<Element> & ap, const ABECoreAccessPolicy<Element>& ua,const ABECoreSecretKey<Element>& sk, const ABECoreCiphertext<Element>& ct, ABECorePlaintext<Element>* dt);
            void Decrypt(const ABECoreSecretKey<Element>& sk, const ABECoreCiphertext<Element>& ct, ABECorePlaintext<Element>* dt);
            Element GenerateRandomElement();
            Element GenerateRandomBinaryElement();
        private:
            shared_ptr<ABECoreScheme<Element>> m_scheme;
            shared_ptr<ABECoreParams<Element>> m_params;
    };
 }

#endif
 