/**
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
* This code serves as a helper class for Palisade's JSON Facility.
*
*/
#include "../../../include/rapidjson/document.h"
#include "../../../include/rapidjson/pointer.h"
#include "../../../include/rapidjson/reader.h"
#include "../../../include/rapidjson/error/en.h"
#include "../../../include/rapidjson/prettywriter.h"
#include "../../../include/rapidjson/stringbuffer.h"
#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <unordered_map>

#include "serializable.h"

#define RAPIDJSON_NO_SIZETYPEDEFINE

#ifndef LBCRYPTO_SERIALIZABLEHELPER_H
#define LBCRYPTO_SERIALIZABLEHELPER_H

namespace lbcrypto {

	class SerializableHelper {

	public:

		SerializableHelper() {}

		/**
		* Converts the input data type into a string
		* @tparam T a data type.
		* @return the string equivalent.
		*/
		template <typename T>
		std::string ToStr(const T& num) const;

		/**
		* Generates a JSON data string for a node of a serialized Palisade object's nested JSON structure
		* @param nodeMap stores the serialized Palisade object's node attributes.
		* @return string reflecting the JSON data structure of the serialized Palisade object's node.
		*/
		std::string GetJsonNodeString(SerializationKV nodeMap);

		/**
		* Generates a JSON data string for a node vector of a serialized Palisade object's nested JSON structure
		* @param nodeMap stores the serialized Palisade object's node attributes.
		* @param serializationMap is a map of attribute name value pairs to used for serializing a Palisade object.
		* @return string reflecting the JSON data structure of the serialized Palisade object's node vector.
		*/
		std::string GetJsonNodeVectorString(SerializationMap serializationMap) ;

		/**
		* Generates a nested JSON data string for a serialized Palisade object
		* @param serializationMap stores the serialized Palisade object's attributes.
		* @return string reflecting the nested JSON data structure of the serialized Palisade object.
		*/
		std::string GetJsonString(SerializationMap serializationMap) ;

		/**
		* Generates a nested JSON data string for a serialized Palisade object
		* @param serializationMap stores the serialized Palisade object's attributes.
		* @return string reflecting the nested JSON data structure of the serialized Palisade object.
		*/
		std::string GetJsonString(SerializationMap serializationMap, std::string fileType);

		std::string GetSimpleJsonString(SerializationMap serializationMap);

		/**
		* Determines the file name for saving a serialized Palisade object
		* @param serializationMap stores the serialized Palisade object's attributes.
		* @return string reflecting file name to save serialized Palisade object to.
		*/
		std::string GetJsonFileName(SerializationMap serializationMap);

		/**
		* Saves a serialized Palisade object's JSON string to file as a nested JSON data structure 
		* @param jsoninputstring is the serialized object's nested JSON data string.
		* @param outputFileName is the name of the file to save JSON data string to.
		*/
		void OutputRapidJsonFile(std::string jsonInputString, std::string outputFileName);

		/**
		* Generates a map of attribute name value pairs for deserializing a Palisade object's node from a JSON file
		* @param doc is the RapidJson DOM object created for the Palisdae object's JSON file
		* @param nodeName is the node to read in for the Palisade object's node's serialized JSON data structure.
		* @return map containing name value pairs for the attributes of the Palisade object's node to be deserialized.
		*/
		SerializationKV GetSerializationMapNode(rapidjson::Document &doc, std::string nodeName);

		/**
		* Generates and adds maps of attribute name value pairs for deserializing a Palisade object's node vector from a JSON file
		* @param doc is the RapidJson DOM object created for the Palisdae object's JSON file
		* @param serializationMap is a map of attribute name value pairs to be used for deserializing a Palisade object
		* @param nodeName is the node to read in for the Palisade object's node's serialized JSON data structure.
		* @param childNodeFlag is used to label each map created for the node vector's members
		* @return map containing maps of name value pairs for the attributes of the Palisade object's node vector to be deserialized.
		*/
		SerializationMap GetSerializationMapNodeVector(rapidjson::Document &doc, SerializationMap serializationMap, std::string nodeName, std::string childNodeFlag) ;

		/**
		* Generates a map of attribute name value pairs for deserializing a Palisade object from a JSON file
		* @param jsonFileName is the file to read in for the Palisade object's nested serialized JSON data structure.
		* @return map containing name value pairs for the attributes of the Palisade object to be deserialized.
		*/
		bool GetSerializationFromFile(std::string jsonFileName, SerializationMap& map);

		/**
		* Generates a map of attribute name value pairs for deserializing a Palisade object from a const char * JSON data string
		* @param jsonInputString is the string to process for the Palisade object's nested serialized JSON data structure.
		* @return map containing name value pairs for the attributes of the Palisade object to be deserialized.
		*/
		bool GetSerializationMap(const char *jsonInputString, SerializationMap& map);

		SerializationMap GetSimpleSerializationMap(const char *jsonInputString, std::string ID);

	};
}

#endif
