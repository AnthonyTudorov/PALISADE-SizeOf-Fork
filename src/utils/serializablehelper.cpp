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
* This code serves as a helper class for Palisade's JSON Facility.
*
*/
#include "../../include/rapidjson/document.h"
#include "../../include/rapidjson/prettywriter.h"
#include "../../include/rapidjson/stringbuffer.h"
#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <unordered_map>
#define RAPIDJSON_NO_SIZETYPEDEFINE
using namespace std;

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
		std::string ToStr(const T& num) const {
			std::ostringstream buffer;
			buffer << num;
			return buffer.str();
		}

		/**
		* Generates a JSON data string for a node of a serialized Palisade object's nested JSON structure
		* @param nodeMap stores the serialized Palisade object's node attributes.
		* @return string reflecting the JSON data structure of the serialized Palisade object's node.
		*/
		std::string GetJsonNodeString(std::unordered_map<std::string, std::string> nodeMap) {
			
			std::string jsonNodeInputBuffer = "";
			jsonNodeInputBuffer.append("{");
			for (std::unordered_map<std::string, std::string>::iterator i = nodeMap.begin(); i != nodeMap.end(); i++) {
				jsonNodeInputBuffer.append("\"");
				jsonNodeInputBuffer.append(i->first);
				jsonNodeInputBuffer.append("\"");
				jsonNodeInputBuffer.append(":");
				jsonNodeInputBuffer.append("\"");
				jsonNodeInputBuffer.append(i->second);
				jsonNodeInputBuffer.append("\"");
				jsonNodeInputBuffer.append(",");
			}
			jsonNodeInputBuffer = jsonNodeInputBuffer.substr(0, jsonNodeInputBuffer.length() - 1);
			jsonNodeInputBuffer.append("}");

			return jsonNodeInputBuffer;
		}

		/**
		* Generates a JSON data string for a node array of a serialized Palisade object's nested JSON structure
		* @param nodeMap stores the serialized Palisade object's node attributes.
		* @param serializationMap is a map of attribute name value pairs to used for serializing a Palisade object.
		* @return string reflecting the JSON data structure of the serialized Palisade object's node array.
		*/
		std::string GetJsonNodeArrayString(std::unordered_map<std::string, std::unordered_map<std::string, std::string>> serializationMap) {

			std::string jsonNodeInputBuffer = "";
			jsonNodeInputBuffer.append("{");
			int evalKeyVectorLength = stoi(serializationMap["Root"]["VectorLength"]);
			for (int i = 0; i < evalKeyVectorLength; i++) {
				std::string indexName = this->ToStr(i);
				jsonNodeInputBuffer.append("\"" + indexName + "\":");
				jsonNodeInputBuffer.append(GetJsonNodeString(serializationMap[indexName]));
				jsonNodeInputBuffer.append(",");
			}
			jsonNodeInputBuffer = jsonNodeInputBuffer.substr(0, jsonNodeInputBuffer.length() - 1);
			jsonNodeInputBuffer.append("}");

			return jsonNodeInputBuffer;
		}

		/**
		* Generates a nested JSON data string for a serialized Palisade object
		* @param serializationMap stores the serialized Palisade object's attributes.
		* @return string reflecting the nested JSON data structure of the serialized Palisade object.
		*/
		std::string GetJsonString(std::unordered_map<std::string, std::unordered_map<std::string, std::string>> serializationMap) {

			/*
			for (unordered_map<string, unordered_map<string, string>>::iterator i = serializationMap.begin(); i != serializationMap.end(); i++) {
				cout << "GetJsonString: " << i->first << endl;
			}
			*/

			std::string jsonInputBuffer = "";

			jsonInputBuffer.append("{");

			std::string ID = serializationMap["Root"]["ID"];

			jsonInputBuffer.append("\"Root\":");
			jsonInputBuffer.append(GetJsonNodeString(serializationMap["Root"]));
			jsonInputBuffer.append(",");

			jsonInputBuffer.append("\"LPCryptoParametersLWE\":");
			jsonInputBuffer.append(GetJsonNodeString(serializationMap["LPCryptoParametersLWE"]));
			jsonInputBuffer.append(",");

			jsonInputBuffer.append("\"ILParams\":");
			jsonInputBuffer.append(GetJsonNodeString(serializationMap["ILParams"]));
			jsonInputBuffer.append(",");

			if (ID.compare("LPEvalKeyLWENTRU") != 0) {
				jsonInputBuffer.append("\"ILVector2n\":");
				jsonInputBuffer.append(GetJsonNodeString(serializationMap["ILVector2n"]));
			} else {
				jsonInputBuffer.append("\"ILVector2nArray\":");
				jsonInputBuffer.append(GetJsonNodeArrayString(serializationMap));
			}

			jsonInputBuffer.append("}");

			return jsonInputBuffer;
		}

		/**
		* Determines the file name for saving a serialized Palisade object
		* @param serializationMap stores the serialized Palisade object's attributes.
		* @return string reflecting file name to save serialized Palisade object to.
		*/
		std::string GetJsonFileName(std::unordered_map<std::string, std::unordered_map<std::string, std::string>> serializationMap) {

			std::unordered_map<std::string, std::string> rootMap = serializationMap["Root"];
			return rootMap["ID"].append("_").append(rootMap["Flag"]);
		}

		/**
		* Saves a serialized Palisade object's JSON string to file as a nested JSON data structure 
		* @param jsoninputstring is the serialized object's nested JSON data string.
		* @param outputFileName is the name of the file to save JSON data string to.
		*/
		void OutputRapidJsonFile(std::string jsonInputString, std::string outputFileName) {

			std::string jsonFileName = outputFileName.append(".txt");

			const char* jsonInput = jsonInputString.c_str();

			rapidjson::Document d;
			d.Parse(jsonInput);
			rapidjson::StringBuffer buffer;
			rapidjson::PrettyWriter<rapidjson::StringBuffer> writer(buffer);
			d.Accept(writer);

			std::ofstream jsonFout;
			jsonFout.open(jsonFileName);
			jsonFout << "\n" << buffer.GetString() << std::endl;
			jsonFout.close();
		}

		/**
		* Generates a map of attribute name value pairs for deserializing a Palisade object's node from a JSON file
		* @param doc is the RapidJson DOM object created for the Palisdae object's JSON file
		* @param nodeName is the node to read in for the Palisade object's node's serialized JSON data structure.
		* @return map containing name value pairs for the attributes of the Palisade object's node to be deserialized.
		*/
		std::unordered_map<std::string, std::string> GetSerializationMapNode(rapidjson::Document &doc, std::string nodeName) {
			
			//cout << "---" << nodeName << "---" << endl;
			std::unordered_map<std::string, std::string> nodeMap;
			const rapidjson::Value& node = doc[nodeName.c_str()];
			for (rapidjson::Value::ConstMemberIterator it = node.MemberBegin(); it != node.MemberEnd(); it++) {
				//cout << it->name.GetString() << " | " << it->value.GetString() << endl;
				nodeMap.emplace(it->name.GetString(), it->value.GetString());
			}

			return nodeMap;
		}

		/**
		* Generates and adds maps of attribute name value pairs for deserializing a Palisade object's array node from a JSON file
		* @param doc is the RapidJson DOM object created for the Palisdae object's JSON file
		* @param serializationMap is a map of attribute name value pairs to be used for deserializing a Palisade object
		* @param nodeName is the node to read in for the Palisade object's node's serialized JSON data structure.
		* @param childNodeFlag is used to label each map created for the array node's indexes
		* @return map containing maps of name value pairs for the attributes of the Palisade object's array node to be deserialized.
		*/
		std::unordered_map<std::string, std::unordered_map<std::string, std::string>> GetSerializationMapNodeArray(rapidjson::Document &doc, std::unordered_map<std::string, std::unordered_map<std::string, std::string>> serializationMap, std::string nodeName, std::string childNodeFlag) {
			
			//cout << "---" << nodeName << "---" << endl;
			std::unordered_map<std::string, std::string> childNodeMap;
			const rapidjson::Value& node = doc[nodeName.c_str()];
			std::string childNodeFlagBuffer = childNodeFlag;
			for (rapidjson::Value::ConstMemberIterator it = node.MemberBegin(); it != node.MemberEnd(); it++) {
				//cout << it->name.GetString() << endl;
				std::string indexValue = it->name.GetString();
				const rapidjson::Value& childNode = doc[nodeName.c_str()][it->name.GetString()];
				for (rapidjson::Value::ConstMemberIterator childIt = childNode.MemberBegin(); childIt != childNode.MemberEnd(); childIt++) {
					//cout << childIt->name.GetString() << endl;
					childNodeMap.emplace(childIt->name.GetString(), childIt->value.GetString());
				}
				serializationMap.emplace(childNodeFlagBuffer.append(indexValue), childNodeMap);
				childNodeMap.clear();
				childNodeFlagBuffer = childNodeFlag;
			}

			return serializationMap;
		}

		/**
		* Generates a map of attribute name value pairs for deserializing a Palisade object from a JSON file
		* @param jsonFileName is the file to read in for the Palisade object's nested serialized JSON data structure.
		* @return map containing name value pairs for the attributes of the Palisade object to be deserialized.
		*/
		std::unordered_map<std::string, std::unordered_map<std::string, std::string>> GetSerializationMap(std::string jsonFileName) {
			
			std::unordered_map<std::string, std::unordered_map<std::string, std::string>> serializationMap;
			std::unordered_map<std::string, std::string> childMap;

			//Retrieve contents of output Json file
			std::string jsonReadLine;
			std::string jsonReadBuffer;
			std::ifstream jsonFin(jsonFileName);
			while (getline(jsonFin, jsonReadLine)) {
				jsonReadBuffer += jsonReadLine;
			}
			jsonFin.close();

			//Retrieve elements from output Json file
			rapidjson::Document doc;
			doc.Parse(jsonReadBuffer.c_str());

			std::string ID = doc["Root"]["ID"].GetString();
			serializationMap.emplace("Root", GetSerializationMapNode(doc, "Root"));
			serializationMap.emplace("LPCryptoParametersLWE", GetSerializationMapNode(doc, "LPCryptoParametersLWE"));
			serializationMap.emplace("ILParams", GetSerializationMapNode(doc, "ILParams"));
			if (ID.compare("LPEvalKeyLWENTRU") != 0) {
				serializationMap.emplace("ILVector2n", GetSerializationMapNode(doc, "ILVector2n"));
			} else {
				serializationMap = GetSerializationMapNodeArray(doc, serializationMap, "ILVector2nArray", "ILVector2n");
			}

			return serializationMap;
		}
	};
}