/**
 * @file signaturecontext.h - Header file for SignatureContext class, which is used for digital signature schemes
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