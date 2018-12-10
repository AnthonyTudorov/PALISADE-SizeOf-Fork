#include "abecontext.h"

namespace lbcrypto{
    template <class Element>
    void ABEContext<Element>::GenerateCPABEContext(usint ringsize,usint bits,usint base,usint ell,double stddev, bool bal){
        usint sm = ringsize * 2;
        typename Element::DggType dgg(stddev);
        typename Element::DugType dug;
        typename Element::Integer smodulus;
        typename Element::Integer srootOfUnity;
        smodulus = FirstPrime<typename Element::Integer>(bits,sm);
        srootOfUnity = RootOfUnity(sm, smodulus);
        dug.SetModulus(smodulus);
		ILParamsImpl<typename Element::Integer> ilParams = ILParamsImpl<typename Element::Integer>(sm, smodulus, srootOfUnity);

        ChineseRemainderTransformFTT<typename Element::Vector>::PreCompute(srootOfUnity, sm, smodulus);
		DiscreteFourierTransform::PreComputeTable(sm);

        
        
        shared_ptr<ILParamsImpl<typename Element::Integer>> silparams = std::make_shared<ILParamsImpl<typename Element::Integer>>(ilParams);
        RLWETrapdoorParams<Element> tparams(silparams,dgg,stddev,base,bal);
        shared_ptr<ABECoreScheme<Element>> sch(new CPABEScheme<Element>());
        shared_ptr<ABECoreParams<Element>> abeparams(new CPABEParams<Element>(std::make_shared<RLWETrapdoorParams<Element>>(tparams),ell,dug));
        m_scheme = sch;
        m_params = abeparams;
    }
    template <class Element>
    void ABEContext<Element>::GenerateCPABEContext(ABESecurityLevel level){
        ABEParamSet paramset = ABEParamsSets[level];
        GenerateCPABEContext(paramset.ringsize,paramset.modulusbitwidth,paramset.base,paramset.numofattributes,paramset.stddev);
    }
    template <class Element>
    void ABEContext<Element>::GenerateIBEContext(usint ringsize,usint bits,usint base,double stddev, bool bal){
        usint sm = ringsize * 2;
        typename Element::DggType dgg(stddev);
        typename Element::DugType dug;
        typename Element::Integer smodulus;
        typename Element::Integer srootOfUnity;
        smodulus = FirstPrime<typename Element::Integer>(bits,sm);
        srootOfUnity = RootOfUnity(sm, smodulus);
        dug.SetModulus(smodulus);
		ILParamsImpl<typename Element::Integer> ilParams = ILParamsImpl<typename Element::Integer>(sm, smodulus, srootOfUnity);

        ChineseRemainderTransformFTT<BigVector>::PreCompute(srootOfUnity, sm, smodulus);
		DiscreteFourierTransform::PreComputeTable(sm);

        
        
        shared_ptr<ILParamsImpl<typename Element::Integer>> silparams = std::make_shared<ILParamsImpl<typename Element::Integer>>(ilParams);
        RLWETrapdoorParams<Element> tparams(silparams,dgg,stddev,base,bal);
        shared_ptr<ABECoreScheme<Element>> sch(new IBEScheme<Element>());
        shared_ptr<ABECoreParams<Element>> ibeparams(new IBEParams<Element>(std::make_shared<RLWETrapdoorParams<Element>>(tparams),dug));
        m_scheme = sch;
        m_params = ibeparams;
    }
    template<class Element>
    void ABEContext<Element>::GenerateIBEContext(ABESecurityLevel level){
        ABEParamSet paramset = ABEParamsSets[level];
        GenerateIBEContext(paramset.ringsize,paramset.modulusbitwidth,paramset.base,paramset.stddev);
    }

    template <class Element>
        void ABEContext<Element>::Setup(ABECoreMasterPublicKey<Element>* pk,ABECoreMasterSecretKey<Element>* sk){
        m_scheme->Setup(m_params,pk,sk);
    }
    template <class Element>
    void ABEContext<Element>::KeyGen(const ABECoreMasterSecretKey<Element> & msk,const ABECoreMasterPublicKey<Element>& mpk, const ABECoreAccessPolicy<Element> & ap,ABECoreSecretKey<Element>* sk){
        m_scheme->KeyGen(m_params,msk,mpk,ap,sk);
    }
    template <class Element>
    void ABEContext<Element>::Encrypt(const ABECoreMasterPublicKey<Element> & mpk,const ABECoreAccessPolicy<Element> & ap,const ABECorePlaintext<Element> & ptext,ABECoreCiphertext<Element>* ct){
        m_scheme->Encrypt(m_params,mpk,ap,ptext,ct);
    }
    template <class Element>
    void ABEContext<Element>::Decrypt(const ABECoreAccessPolicy<Element> & ap, const ABECoreAccessPolicy<Element> & ua,const ABECoreSecretKey<Element>& sk, const ABECoreCiphertext<Element>& ct, ABECorePlaintext<Element>* dt){
        m_scheme->Decrypt(m_params,ap,ua,sk,ct,dt);
    }
    template <class Element>
    void ABEContext<Element>::Decrypt(const ABECoreSecretKey<Element>& sk, const ABECoreCiphertext<Element>& ct, ABECorePlaintext<Element>* dt){
        m_scheme->Decrypt(m_params,sk,ct,dt);
    }
    template <class Element>
    Element ABEContext<Element>::GenerateRandomElement(){
        Element r(m_params->GetDUG(),m_params->GetTrapdoorParams()->GetElemParams(), COEFFICIENT);
        return r;
    }
    template <class Element>
    Element ABEContext<Element>::GenerateRandomBinaryElement(){
        typename Element::BugType bug = typename Element::BugType();
        Element r(m_params->GetTrapdoorParams()->GetElemParams(), COEFFICIENT,true);
        r.SetValues(bug.GenerateVector(m_params->GetTrapdoorParams()->GetN(), m_params->GetTrapdoorParams()->GetElemParams()->GetModulus()), COEFFICIENT);
        return r;
    }

}