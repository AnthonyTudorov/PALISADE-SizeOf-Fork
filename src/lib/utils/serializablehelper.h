/**
 * @file
 * @author  TPOC: Dr. Kurt Rohloff <rohloff@njit.edu>,
 *	Programmers: Arnab Deb Gupta <ad479@njit.edu>
			Jerry Ryan <gwryan@njit.edu>
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
 * This code serves as a helper class for Palisade's JSON Facility.
 *
 */

#define RAPIDJSON_HAS_STDSTRING 1
#include "../../../include/rapidjson/document.h"
#include "../../../include/rapidjson/pointer.h"
#include "../../../include/rapidjson/reader.h"
#include "../../../include/rapidjson/writer.h"
#include "../../../include/rapidjson/filereadstream.h"
#include "../../../include/rapidjson/filewritestream.h"
#include "../../../include/rapidjson/error/en.h"
#include "../../../include/rapidjson/prettywriter.h"
#include "../../../include/rapidjson/stringbuffer.h"
#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <unordered_map>

#include "serializable.h"
#include "../math/backend.h"

#define RAPIDJSON_NO_SIZETYPEDEFINE

#ifndef LBCRYPTO_SERIALIZABLEHELPER_H
#define LBCRYPTO_SERIALIZABLEHELPER_H

namespace lbcrypto {

class SerializableHelper {

public:
	/**
	 * Generates a std::string for a serialized Palisade object (a rapidjson Document)
	 * @param serObj the serialized Palisade object
	 * @param jsonString - string with the JSON data structure of the serialized Palisade object.
	 * @return success or failure
	 */
	static bool SerializationToString(const Serialized& serObj, std::string& jsonString);

	/**
	 * Writes serialization to a file
	 * @param serObj - the serialized Palisade object
	 * @param out - destination stream for writing the serialization
	 * @return success or failure
	 */
	static bool SerializationToStream(const Serialized& serObj, std::ostream& out);

	/**
	 * Generates a serialized Palisade object from an input JSON string
	 * @param jsonString reflecting the nested JSON data structure of the serialized Palisade object.
	 * @param serObj stores the serialized Palisade object's attributes.
	 * @return success or failure
	 */
	static bool StringToSerialization(const std::string& jsonString, Serialized* serObj);

	/**
	 * Generate a serialized Palisade object from a JSON string read from an input stream
	 * @param in - stream to read
	 * @param serObj stores the serialized Palisade object's attributes.
	 * @return success or failure
	 */
	static bool StreamToSerialization(std::istream& in, Serialized* serObj);

	/**
	 * Saves a serialized Palisade object's JSON string to file
	 * @param serObj is the serialized object
	 * @param outputFileName is the name of the file to save JSON data string to.
	 * @return success or failure
	 */
	static bool WriteSerializationToFile(const Serialized& serObj, std::string outputFileName);

	/**
	 * Read a serialized Palisade object from a JSON file
	 * @param jsonFileName is the file to read in for the Palisade object's nested serialized JSON data structure.
	 * @param map containing the serialized object read from the file
	 * @return success or failure
	 */
	static bool ReadSerializationFromFile(const std::string jsonFileName, Serialized* map);
};

template<typename T>
void SerializeVector(const std::string& vectorName, const std::string& typeName, const std::vector<T> inVector, Serialized* serObj) {

	Serialized ser(rapidjson::kObjectType, &serObj->GetAllocator());
bool SerializeVector(const std::string& vectorName, const std::string& typeName, const std::vector<T> inVector, Serialized* serObj) {
	SerialItem ser(rapidjson::kObjectType);
		serElements.AddMember(key, oneEl, serObj->GetAllocator());
	}

	ser.AddMember("Members", serElements, serObj->GetAllocator());

	serObj->AddMember(SerialItem(vectorName, serObj->GetAllocator()), ser, serObj->GetAllocator());
}

template<typename T>
bool DeserializeVector(const std::string& vectorName, const std::string& typeName, const SerialItem::ConstMemberIterator& serObj, std::vector<T>* outVector) {
	SerialItem::ConstMemberIterator it = serObj->value.FindMember(vectorName);

	if( it == serObj->value.MemberEnd() )
		return false;

	SerialItem::ConstMemberIterator mIt = it->value.FindMember("Typename");
	if( mIt == it->value.MemberEnd() ) return false;
	if( mIt->value.GetString() != typeName ) return false;

	mIt = it->value.FindMember("Length");
	if( mIt == it->value.MemberEnd() ) return false;

	outVector->clear();
	outVector->resize( std::stoi(mIt->value.GetString()) );

	mIt = it->value.FindMember("Members");
	if( mIt == it->value.MemberEnd() ) return false;

	const SerialItem& members = mIt->value;

	for( int i=0; i<outVector->size(); i++ ) {
		Serialized::ConstMemberIterator eIt = members.FindMember( std::to_string(i) );
		if( eIt == members.MemberEnd() ) return false;

		T vectorElem;
		const SerialItem& s = eIt->value;
		Serialized ser(rapidjson::kObjectType);

		std::cout << "looking at item " << i << ", its " << eIt->value.IsObject() << std::endl;
//		s.AddMember("help", eIt->value, s.GetAllocator());
//
////		Serialized svec(rapidjson::kObjectType);
////		svec.AddMember( SerialItem(typeName, svec.GetAllocator()), &s, svec.GetAllocator());
//		vectorElem.Deserialize(s);
//		outVector->at(i) = vectorElem;
	}

	return true;
}

class IStreamWrapper {
public:
	typedef char Ch;

	IStreamWrapper(std::istream& is) : is_(is) {
	}

	Ch Peek() const { // 1
		int c = is_.peek();
		return c == std::char_traits<char>::eof() ? '\0' : (Ch)c;
	}

	Ch Take() { // 2
		int c = is_.get();
		return c == std::char_traits<char>::eof() ? '\0' : (Ch)c;
	}

	size_t Tell() const { return (size_t)is_.tellg(); } // 3

	Ch* PutBegin() { assert(false); return 0; }
	void Put(Ch) { assert(false); }
	void Flush() { assert(false); }
	size_t PutEnd(Ch*) { assert(false); return 0; }

private:
	IStreamWrapper(const IStreamWrapper&);
	IStreamWrapper& operator=(const IStreamWrapper&);

	std::istream& is_;
};

class OStreamWrapper {
public:
	typedef char Ch;

	OStreamWrapper(std::ostream& os) : os_(os) {
	}

	Ch Peek() const { assert(false); return '\0'; }
	Ch Take() { assert(false); return '\0'; }
	size_t Tell() const { return 0; }

	Ch* PutBegin() { assert(false); return 0; }
	void Put(Ch c) { os_.put(c); }                  // 1
	void Flush() { os_.flush(); }                   // 2
	size_t PutEnd(Ch*) { assert(false); return 0; }

private:
	OStreamWrapper(const OStreamWrapper&);
	OStreamWrapper& operator=(const OStreamWrapper&);

	std::ostream& os_;
};

}

#endif
