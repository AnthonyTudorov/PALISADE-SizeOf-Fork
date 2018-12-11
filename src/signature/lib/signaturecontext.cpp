/**
 * @file signaturecontext.cpp - Implementation file for signature context class
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
#include "signaturecontext.h"

namespace lbcrypto{
    //Method for setting up a GPV context with specific parameters
    template <class Element>
    void SignatureContext<Element>::GenerateGPVContext(SecurityLevel level,usint ringsize,usint base){
       std::pair<SecurityLevel,usint> key = std::make_pair(level,ringsize);
        if(signparammap.count(key)>0){
            usint bits = signparammap.at(key);
            usint sm = ringsize * 2;
            double stddev = 4.578;
            typename Element::DggType dgg(stddev);
            typename Element::Integer smodulus;
            typename Element::Integer srootOfUnity;
            smodulus = FirstPrime<typename Element::Integer>(bits,sm);
            srootOfUnity = RootOfUnity(sm, smodulus);
		    ILParamsImpl<typename Element::Integer> ilParams = ILParamsImpl<typename Element::Integer>(sm, smodulus, srootOfUnity);

            ChineseRemainderTransformFTT<typename Element::Vector>::PreCompute(srootOfUnity, sm, smodulus);
		    DiscreteFourierTransform::PreComputeTable(sm);

        
            shared_ptr<ILParamsImpl<typename Element::Integer>> silparams = std::make_shared<ILParamsImpl<typename Element::Integer>>(ilParams);
            shared_ptr<LPSignatureParameters<Element>> signparams(new GPVSignatureParameters<Element>(silparams,dgg,base));
            shared_ptr<LPSignatureScheme<Element>> scheme(new GPVSignatureScheme<Element>());
            m_params = signparams;
            m_scheme = scheme;
        }else{
            throw std::logic_error("No parameter set matches with the given values");
        }
    }
    //Method for setting up a GPV context with desired security level only
    template <class Element>
    void SignatureContext<Element>::GenerateGPVContext(SecurityLevel level){
        if(minringsizemap.count(level)>0){
            usint ringsize = minringsizemap.at(level);
            GenerateGPVContext(level,ringsize);
        }
        else{
            throw std::logic_error("Unknown minimum ringsize for given security level");
        }
        
    }
    //Method for key generation
    template <class Element>
        void SignatureContext<Element>::KeyGen(LPSignKey<Element>* sk, LPVerificationKey<Element>* vk){
        m_scheme->KeyGen(m_params,sk,vk);
    }
    template <class Element>
       void SignatureContext<Element>::Sign(const LPSignPlaintext<Element> & pt,const LPSignKey<Element> & sk, const LPVerificationKey<Element> & vk,LPSignature<Element>* sign){
        m_scheme->Sign(m_params,sk,vk,pt,sign);

    }
    template <class Element>
    bool  SignatureContext<Element>::Verify(const LPSignPlaintext<Element> & pt, const LPSignature<Element> & signature, const LPVerificationKey<Element> & vk){
        return m_scheme->Verify(m_params,vk,signature,pt);
    } 
}