/**0
* @file
* @author  TPOC: Dr. Kurt Rohloff <rohloff@njit.edu>,
*	Programmers: Arnab Deb Gupta <ad479@njit.edu>
* @version 00_01
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
*
* This code serves as the abstract class for Palisade's JSON Facility.
* This abstract class is inherited through LPKey in pubkeylp.h, ElemParams in elemparams.h,
* ILVector2n in ilvector2n.h, and BigBinaryVector in binvect.h.
* Virtual methods are implemented in Ciphertext, LPCryptoParametersLWE, LPPublicKeyLTV,
* LPEvalKeyLTV, LPPrivateKeyLTV, ILParams, ILDCRTParams, ILVector2n, BigBinaryVector.
*
* TODO:  Complete implementation in LPEvalKeyLTV, ILDCRTParams.
* TODO:  Setup inheritance through ILElement for ILVector2n once Double CRT is working.
*/
#ifndef LBCRYPTO_SERIALIZABLE_H
#define LBCRYPTO_SERIALIZABLE_H

#include <unordered_map>
#include <sstream>
#include <string>
#define RAPIDJSON_HAS_STDSTRING 1
#include "../../../include/rapidjson/document.h"
#include "../../../include/rapidjson/pointer.h"
#include "../../../include/rapidjson/reader.h"
#include "../../../include/rapidjson/error/en.h"

/**
* @namespace lbcrypto
* The namespace of lbcrypto
*/
namespace lbcrypto {

	// C+11 "using" is not supported in VS 2012 - so it was replaced with C+03 "typedef"
	typedef rapidjson::Value SerialItem;
	typedef rapidjson::Document Serialized;

	//using SerialItem = rapidjson::Value;
	//using Serialized = rapidjson::Document;

	class Serializable
	{
		/**
		* Version number of the serialization; defaults to 1
		* @return version of the serialization
		*/
		virtual int getVersion() { return 1; }

	public:

		/**
		* Serialize the object into a Serialized
		* @param serObj is used to store the serialized result. It MUST be a rapidjson Object (SetObject());
		* @param fileFlag is an object-specific parameter for the serialization
		* @return true if successfully serialized
		*/
		virtual bool Serialize(Serialized& serObj, std::string fileFlag = "") const = 0;
		virtual ~Serializable(){};

		/**
		* Higher level info about the serialization is saved here
		* @param serObj to store the the implementing object's serialization specific attributes.
		* @param flag a file flag
		* @return true on success
		*/
		virtual bool SetIdFlag(Serialized& serObj, const std::string flag) const { return true; }

		/**
		* Populate the object from the deserialization of the Setialized
		* @param serObj contains the serialized object
		* @return true on success
		*/
		virtual bool Deserialize(const Serialized& serObj) = 0;

		/**
		* Converts the input data type into a string
		* @tparam T a data type.
		* @return the string equivalent.
		*/
		template <typename T> 
		std::string ToStr(const T& num) const {
			std::ostringstream buffer;
			buffer << num;
			return buffer.str();
		}
	};

}

#endif
