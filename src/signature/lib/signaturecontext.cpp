#include "signaturecontext.h"

namespace lbcrypto{
    template <class Element>
    void SignatureContext<Element>::GenerateGPVContext(usint ringsize,usint bits,usint base){
        usint sm = ringsize * 2;
        double stddev = 4;
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
    }
    template <class Element>
    void SignatureContext<Element>::GenerateGPVContext(SignatureSecurityLevel level){
        SignatureParamSet set = SignatureParamsSets[level];
        GenerateGPVContext(set.ringsize,set.modulusbitwidth,set.base);
    }
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