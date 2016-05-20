/**
* @file
* @author  TPOC: Dr. Kurt Rohloff <rohloff@njit.edu>,
*	Programmers: Dr. Yuriy Polyakov, <polyakov@njit.edu>, Gyana Sahu <grs22@njit.edu>, Hadi Sajjadpour <ss2959@njit.edu>
* @version 00_03
*
* @section LICENSE
*
* Copyright (c) 2015, New Jersey Institute of Technology (NJIT)
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
* @section DESCRIPTION
* LAYER 2 : LATTICE DATA STRUCTURES AND OPERATIONS
* This code provides basic lattice ideal manipulation functionality.
*/

#include "ilparams.h"

/**
* @namespace lbcrypto
* The namespace of lbcrypto
*/
namespace lbcrypto {

	
		//JSON FACILITY
		/**
		* Implemented by this object only for inheritance requirements of abstract class Serializable.
		*
		* @param serializationMap stores this object's serialized attribute name value pairs.
		* @return map passed in.
		*/
		bool ILParams::SetIdFlag(SerializationMap& serializationMap, std::string flag) const {

			return true;
		}

		//JSON FACILITY
		/**
		* Stores this object's attribute name value pairs to a map for serializing this object to a JSON file.
		*
		* @param serializationMap stores this object's serialized attribute name value pairs.
		* @return map updated with the attribute name value pairs required to serialize this object.
		*/
		bool ILParams::Serialize(SerializationMap& serializationMap, std::string fileFlag) const {

			rapidjson::Value ser(kObjectType);
			ser.AddMember("Modulus", this->GetModulus().ToString());
			ser.AddMember("Order", this->ToStr(this->GetCyclotomicOrder()));
			ser.AddMember("RootOfUnity", this->GetRootOfUnity().ToString());

			//serializationMap.AddMember("ILParams", ser);

			std::unordered_map <std::string, std::string> ilParamsMap;
			ilParamsMap.emplace("Modulus", this->GetModulus().ToString());
			ilParamsMap.emplace("Order", this->ToStr(this->GetCyclotomicOrder()));
			ilParamsMap.emplace("RootOfUnity", this->GetRootOfUnity().ToString());
			serializationMap.emplace("ILParams", ilParamsMap);

			return true;
		}

		//JSON FACILITY
		/**
		* Sets this object's attribute name value pairs to deserialize this object from a JSON file.
		*
		* @param serializationMap stores this object's serialized attribute name value pairs.
		*/
		bool ILParams::Deserialize(const SerializationMap& serializationMap) {

			SerializationMap::const_iterator mIter = serializationMap.find("ILParams");
			if( mIter == serializationMap.end() )
				return false;

			SerializationKV ilParamsMap = mIter->second;

			SerializationKV::iterator kf;

			kf = ilParamsMap.find("Modulus");
			if( kf == ilParamsMap.end() ) return false;
			BigBinaryInteger bbiModulus(kf->second);

			kf = ilParamsMap.find("Order");
			if( kf == ilParamsMap.end() ) return false;
			usint order = stoi(kf->second);

			kf = ilParamsMap.find("RootOfUnity");
			if( kf == ilParamsMap.end() ) return false;
			BigBinaryInteger bbiRootOfUnity(kf->second);

			this->SetModulus(bbiModulus);
			this->SetOrder(order);
			this->SetRootOfUnity(bbiRootOfUnity);
			return true;
		}


} // namespace lbcrypto ends

