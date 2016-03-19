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
bool LPAlgorithmLWENTRU<Element>::KeyGen(LPPublicKey<Element> &publicKey, 
		LPPrivateKey<Element> &privateKey, 
		DiscreteGaussianGenerator &dgg) const
{
	const LPCryptoParameters<Element> &cryptoParams = privateKey.GetCryptoParameters();
	const ElemParams &elementParams = cryptoParams.GetElementParams();
	const BigBinaryInteger &p = cryptoParams.GetPlaintextModulus();

	Element f(dgg,elementParams,Format::COEFFICIENT);

	f = p*f;

	f = f + BigBinaryInteger::ONE;
	
	//cout<<"f="<<f.GetValues()<<endl;


	//added for saving the cryptoparams
	const LPCryptoParametersLWE<Element> &cryptoParamsLWE = static_cast<const LPCryptoParametersLWE<Element>&>(cryptoParams);

	float DistributionParameter = cryptoParamsLWE.GetDistributionParameter();
	float AssuranceMeasure = cryptoParamsLWE.GetAssuranceMeasure();
	float SecurityLevel = cryptoParamsLWE.GetSecurityLevel();
	usint RelinWindow = cryptoParamsLWE.GetRelinWindow(); 
	int Depth = cryptoParamsLWE.GetDepth(); 
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

	privateKey.SetPrivateElement(f);
	privateKey.AccessCryptoParameters() = cryptoParams;

	Element g(dgg,elementParams,Format::COEFFICIENT);
	g.SwitchFormat();

	//public key is generated
	privateKey.MakePublicKey(g,publicKey);

	return true;
}

template <class Element>
void LPAlgorithmLWENTRU<Element>::Encrypt(const LPPublicKey<Element> &publicKey, 
				DiscreteGaussianGenerator &dgg, 
				const PlaintextEncodingInterface &plaintext, 
				Ciphertext<Element> *ciphertext) const
{

	const LPCryptoParameters<Element> &cryptoParams = publicKey.GetCryptoParameters();
	const ElemParams &elementParams = cryptoParams.GetElementParams();
	const BigBinaryInteger &p = cryptoParams.GetPlaintextModulus();

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
	ciphertext->SetEncryptionAlgorithm(*this);
	ciphertext->SetElement(c);

}

template <class Element>
DecodingResult LPAlgorithmLWENTRU<Element>::Decrypt(const LPPrivateKey<Element> &privateKey, 
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
std::unordered_map <std::string, std::unordered_map <std::string, std::string>> LPCryptoParametersLWE<Element>::SetIdFlag(std::unordered_map <std::string, std::unordered_map <std::string, std::string>> serializationMap, std::string flag) const {

	//Place holder

	return serializationMap;
}

// JSON FACILITY - LPCryptoParametersLWE Serialize Operation
template <class Element>
std::unordered_map <std::string, std::unordered_map <std::string, std::string>> LPCryptoParametersLWE<Element>::Serialize(std::unordered_map <std::string, std::unordered_map <std::string, std::string>> serializationMap, std::string fileFlag) const {

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
void LPCryptoParametersLWE<Element>::Deserialize(std::unordered_map <std::string, std::unordered_map <std::string, std::string>> serializationMap) {

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

// JSON FACILITY - LPPublicKeyLWENTRU SetIdFlag Operation
template <class Element>
std::unordered_map <std::string, std::unordered_map <std::string, std::string>> LPPublicKeyLWENTRU<Element>::SetIdFlag(std::unordered_map <std::string, std::unordered_map <std::string, std::string>> serializationMap, std::string flag) const {

	std::unordered_map <std::string, std::string> idFlagMap;
	idFlagMap.emplace("ID", "LPPublicKeyLWENTRU");
	idFlagMap.emplace("Flag", flag);
	serializationMap.emplace("Root", idFlagMap);

	return serializationMap;
}

// JSON FACILITY - LPPublicKeyLWENTRU Serialize Operation
template <class Element>
std::unordered_map <std::string, std::unordered_map <std::string, std::string>> LPPublicKeyLWENTRU<Element>::Serialize(std::unordered_map <std::string, std::unordered_map <std::string, std::string>> serializationMap, std::string fileFlag) const {

	serializationMap = this->SetIdFlag(serializationMap, fileFlag);

	const LPCryptoParameters<Element> *lpCryptoParams = &this->GetCryptoParameters();
	serializationMap = lpCryptoParams->Serialize(serializationMap, "");

	serializationMap = this->GetPublicElement().Serialize(serializationMap, "");

	return serializationMap;
}

// JSON FACILITY - LPPublicKeyLWENTRU Deserialize Operation
template <class Element>
void LPPublicKeyLWENTRU<Element>::Deserialize(std::unordered_map <std::string, std::unordered_map <std::string, std::string>> serializationMap) {

	LPCryptoParameters<Element> *json_cryptoParams = &this->AccessCryptoParameters();
	json_cryptoParams->Deserialize(serializationMap);

	Element json_ilElement;
	json_ilElement.Deserialize(serializationMap);
	this->SetPublicElement(json_ilElement);
}

// JSON FACILITY - LPEvalKeyLWENTRU SetIdFlag Operation
template <class Element>
std::unordered_map <std::string, std::unordered_map <std::string, std::string>> LPEvalKeyLWENTRU<Element>::SetIdFlag(std::unordered_map <std::string, std::unordered_map <std::string, std::string>> serializationMap, std::string flag) const {

	std::unordered_map <std::string, std::string> idFlagMap;
	idFlagMap.emplace("ID", "LPEvalKeyLWENTRU");
	idFlagMap.emplace("Flag", flag);
	serializationMap.emplace("Root", idFlagMap);

	return serializationMap;
}

// JSON FACILITY - LPEvalKeyLWENTRU Serialize Operation
template <class Element>
std::unordered_map <std::string, std::unordered_map <std::string, std::string>> LPEvalKeyLWENTRU<Element>::Serialize(std::unordered_map <std::string, std::unordered_map <std::string, std::string>> serializationMap, std::string fileFlag) const {

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

// JSON FACILITY - LPEvalKeyLWENTRU Deserialize Operation
template <class Element>
void LPEvalKeyLWENTRU<Element>::Deserialize(std::unordered_map <std::string, std::unordered_map <std::string, std::string>> serializationMap) {

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

// JSON FACILITY - LPPrivateKeyLWENTRU SetIdFlag Operation
template <class Element>
std::unordered_map <std::string, std::unordered_map <std::string, std::string>> LPPrivateKeyLWENTRU<Element>::SetIdFlag(std::unordered_map <std::string, std::unordered_map <std::string, std::string>> serializationMap, std::string flag) const {

	std::unordered_map <std::string, std::string> idFlagMap;
	idFlagMap.emplace("ID", "LPPrivateKeyLWENTRU");
	idFlagMap.emplace("Flag", flag);
	serializationMap.emplace("Root", idFlagMap);

	return serializationMap;
}

// JSON FACILITY - LPPrivateKeyLWENTRU Serialize Operation
template <class Element>
std::unordered_map <std::string, std::unordered_map <std::string, std::string>> LPPrivateKeyLWENTRU<Element>::Serialize(std::unordered_map <std::string, std::unordered_map <std::string, std::string>> serializationMap, std::string fileFlag) const {

	serializationMap = this->SetIdFlag(serializationMap, fileFlag);

	const LPCryptoParameters<Element> *lpCryptoParams = &this->GetCryptoParameters();
	serializationMap = lpCryptoParams->Serialize(serializationMap, "");

	serializationMap = this->GetPrivateElement().Serialize(serializationMap, "");

	return serializationMap;
}

// JSON FACILITY - LPPrivateKeyLWENTRU Deserialize Operation
template <class Element>
void LPPrivateKeyLWENTRU<Element>::Deserialize(std::unordered_map <std::string, std::unordered_map <std::string, std::string>> serializationMap) {

	LPCryptoParameters<Element> *json_cryptoParams = &this->AccessCryptoParameters();
	json_cryptoParams->Deserialize(serializationMap);

	Element json_ilElement;
	json_ilElement.Deserialize(serializationMap);
	this->SetPrivateElement(json_ilElement);
}

}  // namespace lbcrypto ends
