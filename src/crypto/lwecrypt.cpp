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
		Nishanth Pasham, np386@njit.edu
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
	const ElemParams &elementParams = cryptoParams.GetElementParams();
	const BigBinaryInteger &p = cryptoParams.GetPlaintextModulus();

	const DiscreteGaussianGenerator &dgg = cryptoParams.GetDiscreteGaussianGenerator();

	Element f(dgg,elementParams,Format::COEFFICIENT);

	f = p*f;

	f = f + BigBinaryInteger::ONE;

	//added for saving the cryptoparams
	const LPCryptoParametersLTV<Element> &cryptoParamsLTV = static_cast<const LPCryptoParametersLTV<Element>&>(cryptoParams);

	float DistributionParameter = cryptoParamsLTV.GetDistributionParameter();
	float AssuranceMeasure = cryptoParamsLTV.GetAssuranceMeasure();
	float SecurityLevel = cryptoParamsLTV.GetSecurityLevel();
	usint RelinWindow = cryptoParamsLTV.GetRelinWindow(); 
	int Depth = cryptoParamsLTV.GetDepth(); 
	
	f.SwitchFormat();

	//check if inverse does not exist
	while (!f.InverseExists())
	{
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
	privateKey->MakePublicKey(g, publicKey);

	return true;
}

template <class Element>
bool LPAlgorithmLTV<Element>::SparseKeyGen(LPPublicKey<Element> &publicKey, 
		        	LPPrivateKey<Element> &privateKey, 
			        DiscreteGaussianGenerator &dgg) const
{
	LPPublicKeyLTV<Element> &publicKeyLTV = dynamic_cast< LPPublicKeyLTV<Element>& >(publicKey); 
	LPPrivateKeyLTV<Element> &privateKeyLTV = dynamic_cast< LPPrivateKeyLTV<Element>& >(privateKey);
	const LPCryptoParameters<Element> &cryptoParams = privateKey.GetCryptoParameters();
	const ElemParams &elementParams = cryptoParams.GetElementParams();
	const BigBinaryInteger &p = cryptoParams.GetPlaintextModulus();

	Element f(dgg,elementParams,Format::COEFFICIENT);

	f = p*f;
	f = f + BigBinaryInteger::ONE;
	f.MakeSparse(BigBinaryInteger::TWO);

	f.SwitchFormat();

	//check if inverse does not exist
	while (!f.InverseExists())
	{
		//std::cout << "inverse does not exist" << std::endl;
		Element temp(dgg, elementParams, Format::COEFFICIENT);
		f = temp;
		f = p*f;
		f = f + BigBinaryInteger::ONE;
		f.MakeSparse(BigBinaryInteger::TWO);
		f.SwitchFormat();
	}

	privateKeyLTV.SetPrivateElement(f);
	privateKeyLTV.AccessCryptoParameters() = cryptoParams;
	

	Element g(dgg,elementParams,Format::COEFFICIENT);
	g.SwitchFormat();

	//public key is generated
	privateKeyLTV.MakePublicKey(g, &publicKeyLTV);

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


template<class Element>
LPKeySwitchHint<Element> LPLeveledSHEAlgorithmLTV<Element>::KeySwitchHintGen(const LPPrivateKey<Element> &originalPrivateKey, 
				const LPPrivateKey<Element> &newPrivateKey) const {

		const LPCryptoParametersLTV<Element> &cryptoParams = dynamic_cast<const LPCryptoParametersLTV<Element> &>(originalPrivateKey.GetPrivateElement() );

		
		
		const ElemParams &originalKeyParams = cryptoParams.GetElementParams() ;

		const Element f1 = originalPrivateKey.GetPrivateElement(); //add const
		const Element f2 = newPrivateKey.GetPrivateElement(); //add const
		const BigBinaryInteger &p = cryptoParams.GetPlaintextModulus();

		Element e(cryptoParams.GetDiscreteGaussianGenerator() , originalKeyParams, Format::COEFFICIENT );
		e.SwitchFormat();

		Element m(originalKeyParams);
		m = p * e;
		
		m.ModularOne();

		Element newKeyInverse = f2.MultiplicativeInverse(); 

		Element keySwitchHint(originalKeyParams);

		keySwitchHint = m * f1 * newKeyInverse ;

		LPKeySwitchHintLTV<Element> lPKeySwitchHintLTV;
		lPKeySwitchHintLTV.SetHintElement(keySwitchHint);
		lPKeySwitchHintLTV.SetCryptoParameters(new LPCryptoParametersLTV<Element>(cryptoParams));

		return lPKeySwitchHintLTV;			

}
			
/**
	* Method for encrypting plaintex using LBC
	*
	* @param &keySwitchHint Hint required to perform the ciphertext switching.
	* @param &cipherText Original ciphertext to perform switching on.
	*/
template<class Element>
Ciphertext<Element> LPLeveledSHEAlgorithmLTV<Element>::KeySwitch(const LPKeySwitchHint<Element> &keySwitchHint,const Ciphertext<Element> &cipherText) const {

	Ciphertext<Element> newCipherText(cipherText);

	Element newCipherTextElement = cipherText.GetElement()*keySwitchHint.GetHintElement();

	newCipherText.SetElement( newCipherTextElement );
	
	return newCipherText ;
}

/**
	* Method for encrypting plaintex using LBC
	*
	* @param &cipherText Ciphertext to perform mod reduce on.
	* @param &privateKey Private key used to encrypt the first argument.
	*/
template<> inline
void LPLeveledSHEAlgorithmLTV<ILVectorArray2n>::ModReduce(Ciphertext<ILVectorArray2n> *cipherText, LPPrivateKey<ILVectorArray2n> *privateKey) const {

	ILVectorArray2n cipherTextElement(cipherText->GetElement());

	cipherTextElement.ModReduce();

	cipherText->SetElement(cipherTextElement);
	
	ILVectorArray2n pvElement = privateKey->GetPrivateElement();
	
	pvElement.DropTower(pvElement.GetLength() - 1);

	privateKey->SetPrivateElement(pvElement);

}

	/**
	* Method for encrypting plaintex using LBC
	*
	* @param &cipherText Ciphertext to perform ring reduce on.
	* @param &privateKey Private key used to encrypt the first argument.
	*/
template<class Element>
void LPLeveledSHEAlgorithmLTV<Element>::RingReduce(Ciphertext<Element> *cipherText, LPPrivateKey<Element> *privateKey) const {

	LPPublicKeyEncryptionSchemeLTV<Element> LTVScheme;
	LTVScheme.Enable(PKESchemeFeature::ENCRYPTION);
	

}




template <class Element>
void LPAlgorithmLTV<Element>::Encrypt(const LPPublicKey<Element> &publicKey, 
				const PlaintextEncodingInterface &plaintext, 
				Ciphertext<Element> *ciphertext) const
{

	const LPCryptoParametersLTV<Element> &cryptoParams = static_cast<const LPCryptoParametersLTV<Element>&>(publicKey.GetCryptoParameters());
	const ElemParams &elementParams = cryptoParams.GetElementParams();
	const BigBinaryInteger &p = cryptoParams.GetPlaintextModulus();
	const DiscreteGaussianGenerator &dgg = cryptoParams.GetDiscreteGaussianGenerator();

	Element m(elementParams);

	/*Uncomment for regular plaintext*/
	plaintext.Encode(p,&m);
	m.SwitchFormat();
	
	const Element &h = publicKey.GetPublicElement();
	
	Element s(dgg,elementParams);
	Element e(dgg,elementParams);
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

	b = c*f;

	f.SwitchFormat();

	b.SwitchFormat();

	b = b.Mod(p);

	std::cout << "PRINTING b: " << std::endl;
	b.PrintValues();

	plaintext->Decode(p,b);
	
	return DecodingResult(plaintext->GetLength());
}

// JSON FACILITY - LPCryptoParametersLWE SetIdFlag Operation
template <class Element>
std::unordered_map <std::string, std::unordered_map <std::string, std::string>> LPCryptoParametersLTV<Element>::SetIdFlag(std::unordered_map <std::string, std::unordered_map <std::string, std::string>> serializationMap, std::string flag) const {

	//Place holder

	return serializationMap;
}

// JSON FACILITY - LPCryptoParametersLWE Serialize Operation
template <class Element>
std::unordered_map <std::string, std::unordered_map <std::string, std::string>> LPCryptoParametersLTV<Element>::Serialize(std::unordered_map <std::string, std::unordered_map <std::string, std::string>> serializationMap, std::string fileFlag) const {

	std::unordered_map <std::string, std::string> cryptoParamsMap;
	cryptoParamsMap.emplace("DistributionParameter", this->ToStr(GetDistributionParameter()));
	cryptoParamsMap.emplace("AssuranceMeasure", this->ToStr(GetAssuranceMeasure()));
	cryptoParamsMap.emplace("SecurityLevel", this->ToStr(GetSecurityLevel()));
	cryptoParamsMap.emplace("RelinWindow", this->ToStr(GetRelinWindow()));
	cryptoParamsMap.emplace("Depth", this->ToStr(GetDepth()));
	cryptoParamsMap.emplace("PlaintextModulus", this->GetPlaintextModulus().ToString());
	serializationMap.emplace("LPCryptoParametersLWE", cryptoParamsMap);

	const ElemParams *cpElemParams = &this->GetElementParams();
	serializationMap = cpElemParams->Serialize(serializationMap, "");

	return serializationMap;
}

// JSON FACILITY - LPCryptoParametersLWE Deserialize Operation
template <class Element>
void LPCryptoParametersLTV<Element>::Deserialize(std::unordered_map <std::string, std::unordered_map <std::string, std::string>> serializationMap) {

	std::unordered_map<std::string, std::string> cryptoParamsMap = serializationMap["LPCryptoParametersLWE"];
	BigBinaryInteger bbiPlaintextModulus(cryptoParamsMap["PlaintextModulus"]);
	float distributionParameter = stof(cryptoParamsMap["DistributionParameter"]);
	float assuranceMeasure = stof(cryptoParamsMap["AssuranceMeasure"]);
	float securityLevel = stof(cryptoParamsMap["SecurityLevel"]);
	usint relinWindow = stoi(cryptoParamsMap["RelinWindow"]);
	int depth = stoi(cryptoParamsMap["Depth"]);

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
	json_ilParams->Deserialize(serializationMap);
	this->SetElementParams(*json_ilParams);
}

// JSON FACILITY - LPPublicKeyLTV SetIdFlag Operation
template <class Element>
std::unordered_map <std::string, std::unordered_map <std::string, std::string>> LPPublicKeyLTV<Element>::SetIdFlag(std::unordered_map <std::string, std::unordered_map <std::string, std::string>> serializationMap, std::string flag) const {

	std::unordered_map <std::string, std::string> idFlagMap;
	idFlagMap.emplace("ID", "LPPublicKeyLTV");
	idFlagMap.emplace("Flag", flag);
	serializationMap.emplace("Root", idFlagMap);

	return serializationMap;
}

// JSON FACILITY - LPPublicKeyLTV Serialize Operation
template <class Element>
std::unordered_map <std::string, std::unordered_map <std::string, std::string>> LPPublicKeyLTV<Element>::Serialize(std::unordered_map <std::string, std::unordered_map <std::string, std::string>> serializationMap, std::string fileFlag) const {

	serializationMap = this->SetIdFlag(serializationMap, fileFlag);

	const LPCryptoParameters<Element> *lpCryptoParams = &this->GetCryptoParameters();
	serializationMap = lpCryptoParams->Serialize(serializationMap, "");

	serializationMap = this->GetPublicElement().Serialize(serializationMap, "");

	return serializationMap;
}

// JSON FACILITY - LPPublicKeyLTV Deserialize Operation
template <class Element>
void LPPublicKeyLTV<Element>::Deserialize(std::unordered_map <std::string, std::unordered_map <std::string, std::string>> serializationMap) {

	LPCryptoParameters<Element> *json_cryptoParams = &this->AccessCryptoParameters();
	json_cryptoParams->Deserialize(serializationMap);

	Element json_ilElement;
	json_ilElement.Deserialize(serializationMap);
	this->SetPublicElement(json_ilElement);
}

// JSON FACILITY - LPEvalKeyLTV SetIdFlag Operation
template <class Element>
std::unordered_map <std::string, std::unordered_map <std::string, std::string>> LPEvalKeyLTV<Element>::SetIdFlag(std::unordered_map <std::string, std::unordered_map <std::string, std::string>> serializationMap, std::string flag) const {

	std::unordered_map <std::string, std::string> idFlagMap;
	idFlagMap.emplace("ID", "LPEvalKeyLTV");
	idFlagMap.emplace("Flag", flag);
	serializationMap.emplace("Root", idFlagMap);

	return serializationMap;
}

// JSON FACILITY - LPEvalKeyLTV Serialize Operation
template <class Element>
std::unordered_map <std::string, std::unordered_map <std::string, std::string>> LPEvalKeyLTV<Element>::Serialize(std::unordered_map <std::string, std::unordered_map <std::string, std::string>> serializationMap, std::string fileFlag) const {

	serializationMap = this->SetIdFlag(serializationMap, fileFlag);

	const LPCryptoParameters<Element> *lpCryptoParams = &this->GetCryptoParameters();
	serializationMap = lpCryptoParams->Serialize(serializationMap, "");

	std::vector<int>::size_type evalKeyVectorLength = this->GetEvalKeyElements().size();
	std::unordered_map <std::string, std::string> idFlagMap = serializationMap["Root"];
	idFlagMap.emplace("VectorLength", this->ToStr(evalKeyVectorLength));
	serializationMap.erase("Root");
	serializationMap.emplace("Root", idFlagMap);

	Element evalKeyElemVector;
	std::unordered_map <std::string, std::string> ilVector2nMap;
	for (unsigned i = 0; i < evalKeyVectorLength; i++) {
		evalKeyElemVector = this->GetEvalKeyElements().at(i);
		serializationMap = evalKeyElemVector.Serialize(serializationMap, "");
		ilVector2nMap = serializationMap["ILVector2n"];
		serializationMap.erase("ILVector2n");
		std::string indexName = this->ToStr(i);
		serializationMap.emplace(indexName, ilVector2nMap);
	}

	return serializationMap;
}

// JSON FACILITY - LPEvalKeyLTV Deserialize Operation
template <class Element>
void LPEvalKeyLTV<Element>::Deserialize(std::unordered_map <std::string, std::unordered_map <std::string, std::string>> serializationMap) {

	LPCryptoParameters<Element> *json_cryptoParams = &this->AccessCryptoParameters();
	json_cryptoParams->Deserialize(serializationMap);

	std::vector<Element> evalKeyVectorBuffer;
	std::vector<int>::size_type evalKeyVectorLength = stoi(serializationMap["Root"]["VectorLength"]);
	std::unordered_map<std::string, std::string> ilVector2nMapBuffer;
	std::unordered_map <std::string, std::unordered_map <std::string, std::string>> ilVector2nMap;
	std::unordered_map<std::string, std::string> ilParamsMapBuffer = serializationMap["ILParams"];
	ilVector2nMap.emplace("ILParams", ilParamsMapBuffer);
	for (int i = 0; i < evalKeyVectorLength; i++) {
		std::string indexName = "ILVector2n";
		indexName.append(this->ToStr(i));
		ilVector2nMapBuffer = serializationMap[indexName];
		ilVector2nMap.emplace("ILVector2n", ilVector2nMapBuffer);
		Element evalKeySubVector;
		evalKeySubVector.Deserialize(ilVector2nMap);
		evalKeyVectorBuffer.push_back(evalKeySubVector);
		ilVector2nMap.erase("ILVector2n");
	}

	this->SetEvalKeyElements(evalKeyVectorBuffer);
}

// JSON FACILITY - LPPrivateKeyLTV SetIdFlag Operation
template <class Element>
std::unordered_map <std::string, std::unordered_map <std::string, std::string>> LPPrivateKeyLTV<Element>::SetIdFlag(std::unordered_map <std::string, std::unordered_map <std::string, std::string>> serializationMap, std::string flag) const {

	std::unordered_map <std::string, std::string> idFlagMap;
	idFlagMap.emplace("ID", "LPPrivateKeyLTV");
	idFlagMap.emplace("Flag", flag);
	serializationMap.emplace("Root", idFlagMap);

	return serializationMap;
}

// JSON FACILITY - LPPrivateKeyLTV Serialize Operation
template <class Element>
std::unordered_map <std::string, std::unordered_map <std::string, std::string>> LPPrivateKeyLTV<Element>::Serialize(std::unordered_map <std::string, std::unordered_map <std::string, std::string>> serializationMap, std::string fileFlag) const {

	serializationMap = this->SetIdFlag(serializationMap, fileFlag);

	const LPCryptoParameters<Element> *lpCryptoParams = &this->GetCryptoParameters();
	serializationMap = lpCryptoParams->Serialize(serializationMap, "");

	serializationMap = this->GetPrivateElement().Serialize(serializationMap, "");

	return serializationMap;
}

// JSON FACILITY - LPPrivateKeyLTV Deserialize Operation
template <class Element>
void LPPrivateKeyLTV<Element>::Deserialize(std::unordered_map <std::string, std::unordered_map <std::string, std::string>> serializationMap) {

	LPCryptoParameters<Element> *json_cryptoParams = &this->AccessCryptoParameters();
	json_cryptoParams->Deserialize(serializationMap);

	Element json_ilElement;
	json_ilElement.Deserialize(serializationMap);
	this->SetPrivateElement(json_ilElement);
}


template <class Element>
LPPrivateKeyLTV<Element>& LPPrivateKeyLTV<Element>::operator=(LPPrivateKeyLTV &rhs){ //rhs needs to be const, however, we need a copy constructor
				
	this->SetCryptoParameters(&rhs.AccessCryptoParameters());
	this->SetPrivateElement(rhs.GetPrivateElement());	

	return *this;
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