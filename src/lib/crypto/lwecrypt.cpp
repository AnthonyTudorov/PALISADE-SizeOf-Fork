//LAYER 3 : CRYPTO DATA STRUCTURES AND OPERATIONS
/*
PRE SCHEME PROJECT, Crypto Lab, NJIT
Version: 
	v00.01 
Last Edited: 
	6/14/2015 5:37AM
List of Authors:
	TPOC: 
		Dr. Kurt Rohloff, rohloff@njit.edu
	Programmers:
		Dr. Yuriy Polyakov, polyakov@njit.edu
		Gyana Sahu, grs22@njit.edu
Description:	
	This code provides the core proxy re-encryption functionality.

License Information:

Copyright (c) 2015, New Jersey Institute of Technology (NJIT)
All rights reserved.
Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:
1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

 */

#include "lwecrypt.h"
#include <cstring>
#include <iostream>
//#include "saveparams.h"
using namespace std;

namespace lbcrypto {

template <class Element>
bool LPAlgorithmLTV<Element>::KeyGen(LPPublicKey<Element> *publicKey, 
		LPPrivateKey<Element> *privateKey) const
		{
	const LPCryptoParametersLTV<Element> &cryptoParams = static_cast<const LPCryptoParametersLTV<Element>&>(privateKey->GetCryptoParameters());
	//const LPCryptoParameters<Element> &cryptoParams = privateKey.GetCryptoParameters();
	const ElemParams &elementParams = cryptoParams.GetElementParams();
	const BigBinaryInteger &p = cryptoParams.GetPlaintextModulus();

	const DiscreteGaussianGenerator &dgg = cryptoParams.GetDiscreteGaussianGenerator();

	Element f(dgg,elementParams,Format::COEFFICIENT);

	f = p*f;

	f = f + BigBinaryInteger::ONE;

	//added for saving the cryptoparams
	/*	const LPCryptoParametersLTV<Element> &cryptoParamsLWE = static_cast<const LPCryptoParametersLTV<Element>&>(cryptoParams);

	float DistributionParameter = cryptoParamsLWE.GetDistributionParameter();
	float AssuranceMeasure = cryptoParamsLWE.GetAssuranceMeasure();
	float SecurityLevel = cryptoParamsLWE.GetSecurityLevel();
	usint RelinWindow = cryptoParamsLWE.GetRelinWindow(); 
	int Depth = cryptoParamsLWE.GetDepth();*/ 
	//std::cout<<p<<DistributionParameter<<AssuranceMeasure<<SecurityLevel<<RelinWindow<<Depth<<std::endl;
	//////
	f.SwitchFormat();

	//check if inverse does not exist
	while (!f.InverseExists())
	{
		//std::cout << "inverse does not exist" << std::endl;
		Element temp(dgg, elementParams, Format::COEFFICIENT);
		f = temp;
		f = p*f;
		f = f + BigBinaryInteger::ONE;
		f.SwitchFormat();
	}

	privateKey->SetPrivateElement(f);
	privateKey->AccessCryptoParameters() = cryptoParams;

	Element g(dgg,elementParams,Format::COEFFICIENT);
	g.SwitchFormat();

	//public key is generated
	privateKey->MakePublicKey(g,publicKey);

	return true;
		}

template <class Element>
bool LPEncryptionAlgorithmStehleSteinfeld<Element>::KeyGen(LPPublicKey<Element> *publicKey, 
		LPPrivateKey<Element> *privateKey) const
		{
	const LPCryptoParametersStehleSteinfeld<Element> &cryptoParams = static_cast<const LPCryptoParametersStehleSteinfeld<Element>&>(privateKey->GetCryptoParameters());
	const ElemParams &elementParams = cryptoParams.GetElementParams();
	const BigBinaryInteger &p = cryptoParams.GetPlaintextModulus();

	const DiscreteGaussianGenerator &dgg = cryptoParams.GetDiscreteGaussianGeneratorStSt();

	Element f(dgg,elementParams,Format::COEFFICIENT);

	f = p*f;

	f = f + BigBinaryInteger::ONE;

	f.SwitchFormat();

	//check if inverse does not exist
	while (!f.InverseExists())
	{
		//std::cout << "inverse does not exist" << std::endl;
		Element temp(dgg, elementParams, Format::COEFFICIENT);
		f = temp;
		f = p*f;
		f = f + BigBinaryInteger::ONE;
		f.SwitchFormat();
	}

	privateKey->SetPrivateElement(f);
	privateKey->AccessCryptoParameters() = cryptoParams;

	Element g(dgg,elementParams,Format::COEFFICIENT);
	g.SwitchFormat();

	//public key is generated
	privateKey->MakePublicKey(g,publicKey);

	return true;
		}


template <class Element>
void LPAlgorithmLTV<Element>::Encrypt(const LPPublicKey<Element> &publicKey, 
		const PlaintextEncodingInterface &plaintext,
		Ciphertext<Element> *ciphertext) const
		{

	const LPCryptoParametersLTV<Element> &cryptoParams = static_cast<const LPCryptoParametersLTV<Element>&>(publicKey.GetCryptoParameters());
	//const LPCryptoParameters<Element> &cryptoParams = publicKey.GetCryptoParameters();
	const ElemParams &elementParams = cryptoParams.GetElementParams();
	const BigBinaryInteger &p = cryptoParams.GetPlaintextModulus();
	const DiscreteGaussianGenerator &dgg = cryptoParams.GetDiscreteGaussianGenerator();

	Element m(elementParams);

	plaintext.Encode(p,&m);

	//	m.PrintValues();
	//m.EncodeElement(plaintext,p);

	m.SwitchFormat();

	const Element &h = publicKey.GetPublicElement();

	Element s(dgg,elementParams);
	Element e(dgg,elementParams);

	//Element a(p*e + m);
	//a.SwitchFormat();

	Element c(elementParams);

	c = h*s + p*e + m;

	ciphertext->SetCryptoParameters(cryptoParams);
	ciphertext->SetPublicKey(publicKey);
	ciphertext->SetEncryptionAlgorithm(this->GetScheme());
	ciphertext->SetElement(c);

		}

template <class Element>
DecodingResult LPAlgorithmLTV<Element>::Decrypt(const LPPrivateKey<Element> &privateKey, 
		const Ciphertext<Element> &ciphertext,
		PlaintextEncodingInterface *plaintext) const
		{

	const LPCryptoParameters<Element> &cryptoParams = privateKey.GetCryptoParameters();
	const ElemParams &elementParams = cryptoParams.GetElementParams();
	const BigBinaryInteger &p = cryptoParams.GetPlaintextModulus();

	Element c(elementParams);
	c = ciphertext.GetElement();

	Element b(elementParams);
	Element f = privateKey.GetPrivateElement(); //add const

	b = f*c;

	b.SwitchFormat();

	//Element m(elementParams);
	//m = b.Mod(p);

	//Element m(b.ModByTwo());

	//	Element m(b.Mod(p));

	//cout<<"m ="<<m.GetValues()<<endl;

	//m.DecodeElement(static_cast<ByteArrayPlaintextEncoding*>(plaintext),p);
	//	plaintext->Decode(p,m);
	plaintext->Decode(p,b);

	return DecodingResult(plaintext->GetLength());
		}

// JSON FACILITY - LPCryptoParametersLWE SetIdFlag Operation
template <class Element>
bool LPCryptoParametersStehleSteinfeld<Element>::SetIdFlag(Serialized& serObj, std::string flag) const {

	return true;
}

// JSON FACILITY - LPCryptoParametersLWE Serialize Operation
template <class Element>
bool LPCryptoParametersStehleSteinfeld<Element>::Serialize(Serialized& serObj, std::string fileFlag) const {

	SerialItem cryptoParamsMap;
	cryptoParamsMap.AddMember("DistributionParameter", this->ToStr(this->GetDistributionParameter()), serObj.GetAllocator());
	cryptoParamsMap.AddMember("DistributionParameterStSt", this->ToStr(this->GetDistributionParameterStSt()), serObj.GetAllocator());
	cryptoParamsMap.AddMember("AssuranceMeasure", this->ToStr(this->GetAssuranceMeasure()), serObj.GetAllocator());
	cryptoParamsMap.AddMember("SecurityLevel", this->ToStr(this->GetSecurityLevel()), serObj.GetAllocator());
	cryptoParamsMap.AddMember("RelinWindow", this->ToStr(this->GetRelinWindow()), serObj.GetAllocator());
	cryptoParamsMap.AddMember("Depth", this->ToStr(this->GetDepth()), serObj.GetAllocator());
	cryptoParamsMap.AddMember("PlaintextModulus", this->GetPlaintextModulus().ToString(), serObj.GetAllocator());

	serObj.AddMember("LPCryptoParametersStehleSteinfeld", cryptoParamsMap, serObj.GetAllocator());

	return this->GetElementParams().Serialize(serObj, "");
}

// JSON FACILITY - LPCryptoParametersLWE Deserialize Operation
template <class Element>
bool LPCryptoParametersStehleSteinfeld<Element>::Deserialize(const Serialized& serObj) {

	Serialized::ConstMemberIterator mIter = serObj.FindMember("LPCryptoParametersStehleSteinfeld");
	if( mIter == serObj.MemberEnd() ) return false;

	SerialItem::ConstMemberIterator pIt;

	if( (pIt = mIter->value.FindMember("PlaintextModulus")) == mIter->value.MemberEnd() )
		return false;
	BigBinaryInteger bbiPlaintextModulus(pIt->value.GetString());

	if( (pIt = mIter->value.FindMember("DistributionParameter")) == mIter->value.MemberEnd() )
		return false;
	float distributionParameter = atof(pIt->value.GetString());

	if( (pIt = mIter->value.FindMember("DistributionParameterStSt")) == mIter->value.MemberEnd() )
		return false;
	float distributionParameterStSt = atof(pIt->value.GetString());

	if( (pIt = mIter->value.FindMember("AssuranceMeasure")) == mIter->value.MemberEnd() )
		return false;
	float assuranceMeasure = atof(pIt->value.GetString());

	if( (pIt = mIter->value.FindMember("SecurityLevel")) == mIter->value.MemberEnd() )
		return false;
	float securityLevel = atof(pIt->value.GetString());

	if( (pIt = mIter->value.FindMember("RelinWindow")) == mIter->value.MemberEnd() )
		return false;
	usint relinWindow = atoi(pIt->value.GetString());

	if( (pIt = mIter->value.FindMember("Depth")) == mIter->value.MemberEnd() )
		return false;
	int depth = atoi(pIt->value.GetString());

	this->SetPlaintextModulus(bbiPlaintextModulus);
	this->SetDistributionParameter(distributionParameter);
	this->SetDistributionParameterStSt(distributionParameterStSt);
	this->SetAssuranceMeasure(assuranceMeasure);
	this->SetSecurityLevel(securityLevel);
	this->SetRelinWindow(relinWindow);
	this->SetDepth(depth);

	//YURIY's FIX
	//find out the type of object using the input JSON and static object id
	//create an object of that class using the new operator (on the heap)
	// if (classname=="ILParams")
	//		ILParams json_ilParams = new ILParams();
	//Rely on object factory approach to determine what class to instantiate for
	//deserialization.
	ElemParams *json_ilParams = new ILParams();
	if( json_ilParams->Deserialize(serObj) ) {
		this->SetElementParams(*json_ilParams);
		return true;
	}

	return false;
}

// JSON FACILITY - LPCryptoParametersLWE Serialize Operation
template <class Element>
bool LPCryptoParametersLTV<Element>::SetIdFlag(Serialized& serObj, std::string flag) const {

	return true;
}

template <class Element>
bool LPCryptoParametersLTV<Element>::Serialize(Serialized& serObj, std::string fileFlag) const {

	SerialItem cryptoParamsMap;
	cryptoParamsMap.AddMember("DistributionParameter", this->ToStr(GetDistributionParameter()), serObj.GetAllocator());
	cryptoParamsMap.AddMember("AssuranceMeasure", this->ToStr(GetAssuranceMeasure()), serObj.GetAllocator());
	cryptoParamsMap.AddMember("SecurityLevel", this->ToStr(GetSecurityLevel()), serObj.GetAllocator());
	cryptoParamsMap.AddMember("RelinWindow", this->ToStr(GetRelinWindow()), serObj.GetAllocator());
	cryptoParamsMap.AddMember("Depth", this->ToStr(GetDepth()), serObj.GetAllocator());
	cryptoParamsMap.AddMember("PlaintextModulus", this->GetPlaintextModulus().ToString(), serObj.GetAllocator());

	serObj.AddMember("LPCryptoParametersLTV", cryptoParamsMap, serObj.GetAllocator());

	return this->GetElementParams().Serialize(serObj, "");
}

// JSON FACILITY - LPCryptoParametersLWE Deserialize Operation
template <class Element>
bool LPCryptoParametersLTV<Element>::Deserialize(const Serialized& serObj) {

	Serialized::ConstMemberIterator mIter = serObj.FindMember("LPCryptoParametersLTV");
	if( mIter == serObj.MemberEnd() ) return false;

	SerialItem::ConstMemberIterator pIt;

	if( (pIt = mIter->value.FindMember("PlaintextModulus")) == mIter->value.MemberEnd() )
		return false;
	BigBinaryInteger bbiPlaintextModulus(pIt->value.GetString());

	if( (pIt = mIter->value.FindMember("DistributionParameter")) == mIter->value.MemberEnd() )
		return false;
	float distributionParameter = atof(pIt->value.GetString());

	if( (pIt = mIter->value.FindMember("AssuranceMeasure")) == mIter->value.MemberEnd() )
		return false;
	float assuranceMeasure = atof(pIt->value.GetString());

	if( (pIt = mIter->value.FindMember("SecurityLevel")) == mIter->value.MemberEnd() )
		return false;
	float securityLevel = atof(pIt->value.GetString());

	if( (pIt = mIter->value.FindMember("RelinWindow")) == mIter->value.MemberEnd() )
		return false;
	usint relinWindow = atoi(pIt->value.GetString());

	if( (pIt = mIter->value.FindMember("Depth")) == mIter->value.MemberEnd() )
		return false;
	int depth = atoi(pIt->value.GetString());

	this->SetPlaintextModulus(bbiPlaintextModulus);
	this->SetDistributionParameter(distributionParameter);
	this->SetAssuranceMeasure(assuranceMeasure);
	this->SetSecurityLevel(securityLevel);
	this->SetRelinWindow(relinWindow);
	this->SetDepth(depth);

	//YURIY's FIX
	//find out the type of object using the input JSON and static object id
	//create an object of that class using the new operator (on the heap)
	// if (classname=="ILParams")
	//		ILParams json_ilParams = new ILParams();
	//Rely on object factory approach to determine what class to instantiate for
	//deserialization.
	ElemParams *json_ilParams = new ILParams();
	if( json_ilParams->Deserialize(serObj) ) {
		this->SetElementParams(*json_ilParams);
		return true;
	}

	return false;
}


// JSON FACILITY - LPPublicKeyLTV SetIdFlag Operation
template <class Element>
bool LPPublicKeyLTV<Element>::SetIdFlag(Serialized& serObj, std::string flag) const {

	SerialItem idFlagMap;
	idFlagMap.AddMember("ID", "LPPublicKeyLTV", serObj.GetAllocator());
	idFlagMap.AddMember("Flag", flag, serObj.GetAllocator());
	serObj.AddMember("Root", idFlagMap, serObj.GetAllocator());

	return true;
}

// JSON FACILITY - LPPublicKeyLTV Serialize Operation
template <class Element>
bool LPPublicKeyLTV<Element>::Serialize(Serialized& serObj, std::string fileFlag) const {

	if( !this->SetIdFlag(serObj, fileFlag) )
		return false;

	if( !this->GetCryptoParameters().Serialize(serObj, "") )
		return false;

	return this->GetPublicElement().Serialize(serObj, "");
}

// JSON FACILITY - LPPublicKeyLTV Deserialize Operation
template <class Element>
bool LPPublicKeyLTV<Element>::Deserialize(const Serialized& serObj) {

	if( !this->AccessCryptoParameters().Deserialize(serObj) )
		return false;

	Element json_ilElement;
	if( json_ilElement.Deserialize(serObj) ) {
		this->SetPublicElement(json_ilElement);
		return true;
	}

	return false;
}

// JSON FACILITY - LPEvalKeyLTV SetIdFlag Operation
template <class Element>
bool LPEvalKeyLTV<Element>::SetIdFlag(Serialized& serObj, std::string flag) const {

	SerialItem idFlagMap;
	idFlagMap.AddMember("ID", "LPEvalKeyLTV", serObj.GetAllocator());
	idFlagMap.AddMember("Flag", flag, serObj.GetAllocator());
	serObj.AddMember("Root", idFlagMap, serObj.GetAllocator());

	return true;
}

// JSON FACILITY - LPEvalKeyLTV Serialize Operation
template <class Element>
bool LPEvalKeyLTV<Element>::Serialize(Serialized& serObj, std::string fileFlag) const {

	Serialized localMap;

	if( !this->SetIdFlag(serObj, fileFlag) )
		return false;

	if( !this->GetCryptoParameters().Serialize(serObj, "") )
		return false;

	std::vector<int>::size_type evalKeyVectorLength = this->GetEvalKeyElements().size();

	serObj["Root"].AddMember("VectorLength", this->ToStr(evalKeyVectorLength), serObj.GetAllocator());

	SerialItem ilVector2nMap;
	for (unsigned i = 0; i < evalKeyVectorLength; i++) {
		localMap.Clear();
		if( this->GetEvalKeyElements().at(i).Serialize(localMap, "") ) {
			// get first item
			Serialized::ConstMemberIterator vv = localMap.MemberBegin();
			ilVector2nMap.AddMember(this->ToStr(i), vv->value, serObj.GetAllocator());
		}
		else
			return false;

		serObj.AddMember("ILVector2nVector", ilVector2nMap, serObj.GetAllocator());

	}

	return true;
}

// JSON FACILITY - LPEvalKeyLTV Deserialize Operation
template <class Element>
bool LPEvalKeyLTV<Element>::Deserialize(const Serialized& serObj) {

	if( !this->AccessCryptoParameters().Deserialize(serObj) ) return false;

	std::vector<Element> evalKeyVectorBuffer;

	Serialized::ConstMemberIterator rIt = serObj.FindMember("Root");
	if( rIt == serObj.MemberEnd() ) return false;

	SerialItem::ConstMemberIterator mIt = rIt->value.FindMember("VectorLength");
	if( mIt == rIt->value.MemberEnd() ) return false;

	std::vector<int>::size_type evalKeyVectorLength = atoi(mIt->value.GetString());

	if( (rIt = serObj.FindMember("ILVector2nVector")) == serObj.MemberEnd() )
		return false;

	for (int i = 0; i < evalKeyVectorLength; i++) {
		std::string indexName = this->ToStr(i);
		SerialItem::ConstMemberIterator fi = rIt->value.FindMember(indexName.c_str());
		if( fi == rIt->value.MemberEnd() )
			return false;

		Element evalKeySubVector;
		evalKeySubVector.Deserialize(rIt->value);
		evalKeyVectorBuffer.push_back(evalKeySubVector);
	}

	this->SetEvalKeyElements(evalKeyVectorBuffer);
	return true;
}

// JSON FACILITY - LPPrivateKeyLTV SetIdFlag Operation
template <class Element>
bool LPPrivateKeyLTV<Element>::SetIdFlag(Serialized& serObj, std::string flag) const {

	SerialItem idFlagMap;
	idFlagMap.AddMember("ID", "LPPrivateKeyLTV", serObj.GetAllocator());
	idFlagMap.AddMember("Flag", flag, serObj.GetAllocator());
	serObj.AddMember("Root", idFlagMap, serObj.GetAllocator());

	return true;
}

// JSON FACILITY - LPPrivateKeyLTV Serialize Operation
template <class Element>
bool LPPrivateKeyLTV<Element>::Serialize(Serialized& serObj, std::string fileFlag) const {

	if( !this->SetIdFlag(serObj, fileFlag) )
		return false;

	if( !this->GetCryptoParameters().Serialize(serObj, "") )
		return false;

	return this->GetPrivateElement().Serialize(serObj, "");
}

// JSON FACILITY - LPPrivateKeyLTV Deserialize Operation
template <class Element>
bool LPPrivateKeyLTV<Element>::Deserialize(const Serialized& serObj) {

	if( !this->AccessCryptoParameters().Deserialize(serObj) ) return false;

	Element json_ilElement;
	if( json_ilElement.Deserialize(serObj) ) {
		this->SetPrivateElement(json_ilElement);
		return true;
	}
	return false;
}

// Default constructor for LPPublicKeyEncryptionSchemeLTV
template <class Element>
LPPublicKeyEncryptionSchemeLTV<Element>::LPPublicKeyEncryptionSchemeLTV(){
	this->m_algorithmEncryption = NULL;
	this->m_algorithmPRE = NULL;
	this->m_algorithmEvalAdd = NULL;
	this->m_algorithmEvalAutomorphism = NULL;
	this->m_algorithmSHE = NULL;
	this->m_algorithmFHE = NULL;
}

// Constructor for LPPublicKeyEncryptionSchemeLTV
template <class Element>
LPPublicKeyEncryptionSchemeLTV<Element>::LPPublicKeyEncryptionSchemeLTV(std::bitset<FEATURESETSIZE> mask){

	if (mask[ENCRYPTION])
		this->m_algorithmEncryption = new LPAlgorithmLTV<Element>(*this);
	if (mask[PRE])
		this->m_algorithmPRE = new LPAlgorithmPRELTV<Element>(*this);
	if (mask[EVALADD])
		this->m_algorithmEvalAdd = new LPAlgorithmAHELTV<Element>(*this);
	if (mask[EVALAUTOMORPHISM])
		this->m_algorithmEvalAutomorphism = new LPAlgorithmAutoMorphLTV<Element>(*this);
	if (mask[SHE])
		this->m_algorithmSHE = new LPAlgorithmSHELTV<Element>(*this);
	if (mask[FHE])
		this->m_algorithmFHE = new LPAlgorithmFHELTV<Element>(*this);

}

// Destructor for LPPublicKeyEncryptionSchemeLTV
template <class Element>
LPPublicKeyEncryptionSchemeLTV<Element>::~LPPublicKeyEncryptionSchemeLTV(){
	if (this->m_algorithmEncryption != NULL)
		delete this->m_algorithmEncryption;
	if (this->m_algorithmPRE != NULL)
		delete this->m_algorithmPRE;
	if (this->m_algorithmEvalAdd != NULL)
		delete this->m_algorithmEvalAdd;
	if (this->m_algorithmEvalAutomorphism != NULL)
		delete this->m_algorithmEvalAutomorphism;
	if (this->m_algorithmSHE != NULL)
		delete this->m_algorithmSHE;
	if (this->m_algorithmFHE != NULL)
		delete this->m_algorithmFHE;
}

// Destructor for LPPublicKeyEncryptionSchemeLTV
template <class Element>
void LPPublicKeyEncryptionSchemeLTV<Element>::Enable(PKESchemeFeature feature){
	switch (feature)
	{
	case ENCRYPTION:
		this->m_algorithmEncryption = new LPAlgorithmLTV<Element>(*this);
	case PRE:
		this->m_algorithmPRE = new LPAlgorithmPRELTV<Element>(*this);
	case EVALADD:
		this->m_algorithmEvalAdd = new LPAlgorithmAHELTV<Element>(*this);
	case EVALAUTOMORPHISM:
		this->m_algorithmEvalAutomorphism = new LPAlgorithmAutoMorphLTV<Element>(*this);
	case SHE:
		this->m_algorithmSHE = new LPAlgorithmSHELTV<Element>(*this);
	case FHE:
		this->m_algorithmFHE = new LPAlgorithmFHELTV<Element>(*this);
	}
}

// Constructor for LPPublicKeyEncryptionSchemeStehleSteinfeld
template <class Element>
LPPublicKeyEncryptionSchemeStehleSteinfeld<Element>::LPPublicKeyEncryptionSchemeStehleSteinfeld(std::bitset<FEATURESETSIZE> mask){
	if (mask[ENCRYPTION])
		this->m_algorithmEncryption = new LPEncryptionAlgorithmStehleSteinfeld<Element>(*this);
	if (mask[PRE])
		this->m_algorithmPRE = new LPAlgorithmPRELTV<Element>(*this);
	if (mask[EVALADD])
		this->m_algorithmEvalAdd = new LPAlgorithmAHELTV<Element>(*this);
	if (mask[EVALAUTOMORPHISM])
		this->m_algorithmEvalAutomorphism = new LPAlgorithmAutoMorphLTV<Element>(*this);
	if (mask[SHE])
		this->m_algorithmSHE = new LPAlgorithmSHELTV<Element>(*this);
	if (mask[FHE])
		this->m_algorithmFHE = new LPAlgorithmFHELTV<Element>(*this);

}

// Feature enable method for LPPublicKeyEncryptionSchemeStehleSteinfeld
template <class Element>
void LPPublicKeyEncryptionSchemeStehleSteinfeld<Element>::Enable(PKESchemeFeature feature){
	switch (feature)
	{
	case ENCRYPTION:
		this->m_algorithmEncryption = new LPEncryptionAlgorithmStehleSteinfeld<Element>(*this);
	case PRE:
		this->m_algorithmPRE = new LPAlgorithmPRELTV<Element>(*this);
	case EVALADD:
		this->m_algorithmEvalAdd = new LPAlgorithmAHELTV<Element>(*this);
	case EVALAUTOMORPHISM:
		this->m_algorithmEvalAutomorphism = new LPAlgorithmAutoMorphLTV<Element>(*this);
	case SHE:
		this->m_algorithmSHE = new LPAlgorithmSHELTV<Element>(*this);
	case FHE:
		this->m_algorithmFHE = new LPAlgorithmFHELTV<Element>(*this);
	}
}


}  // namespace lbcrypto ends
