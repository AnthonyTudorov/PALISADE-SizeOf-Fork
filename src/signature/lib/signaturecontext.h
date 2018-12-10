#ifndef SIGNATURE_SIGNATURECONTEXT_H
#define SIGNATURE_SIGNATURECONTEXT_H

#include "gpv.h"
#include "signatureparamset.h"


namespace lbcrypto{
   
    template <class Element>
    class SignatureContext{
        public:
            /*
            *Default constructor
            */
            SignatureContext(){}
            void GenerateGPVContext(usint ringsize,usint bits,usint base);
            void GenerateGPVContext(SignatureSecurityLevel level);
            void KeyGen(LPSignKey<Element>* sk, LPVerificationKey<Element>* vk);
            void Sign(const LPSignPlaintext<Element> & pt,const LPSignKey<Element> & sk, const LPVerificationKey<Element> & vk,LPSignature<Element>* sign);
            bool Verify(const LPSignPlaintext<Element> & pt, const LPSignature<Element> & signature, const LPVerificationKey<Element> & vk);

        private:
            //The signature scheme used
            shared_ptr<LPSignatureScheme<Element>> m_scheme;
            //Parameters related to the scheme
            shared_ptr<LPSignatureParameters<Element>> m_params;
    };
     
}

#endif