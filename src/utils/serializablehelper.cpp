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
		string GetJsonNodeString(unordered_map<string, string> nodeMap) {
			
			string jsonNodeInputBuffer = "";
			jsonNodeInputBuffer.append("{");
			for (unordered_map<string, string>::iterator i = nodeMap.begin(); i != nodeMap.end(); i++) {
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
		* Generates a nested JSON data string for a serialized Palisade object
		* @param serializationMap stores the serialized Palisade object's attributes.
		* @return string reflecting the nested JSON data structure of the serialized Palisade object.
		*/
		string GetJsonString(unordered_map<string, unordered_map<string, string>> serializationMap) {

			/*
			for (unordered_map<string, unordered_map<string, string>>::iterator i = serializationMap.begin(); i != serializationMap.end(); i++) {
				cout << "GetJsonString: " << i->first << endl;
			}
			*/

			string jsonInputBuffer = "";

			jsonInputBuffer.append("{");

			string ID = serializationMap["Root"]["ID"];

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
				int evalKeyVectorLength = stoi(serializationMap["Root"]["VectorLength"]);
				for (int i = 0; i < evalKeyVectorLength; i++) {
					std::string indexName = "ILVector2n";
					indexName.append(this->ToStr(i));
					jsonInputBuffer.append("\"" + indexName + "\":");
					jsonInputBuffer.append(GetJsonNodeString(serializationMap[indexName]));
					jsonInputBuffer.append(",");
				}
				jsonInputBuffer = jsonInputBuffer.substr(0, jsonInputBuffer.length() - 1);
			}

			jsonInputBuffer.append("}");

			return jsonInputBuffer;
		}

		/**
		* Determines the file name for saving a serialized Palisade object
		* @param serializationMap stores the serialized Palisade object's attributes.
		* @return string reflecting file name to save serialized Palisade object to.
		*/
		string GetJsonFileName(unordered_map<string, unordered_map<string, string>> serializationMap) {

			unordered_map<string, string> rootMap = serializationMap["Root"];
			return rootMap["ID"].append("_").append(rootMap["Flag"]);
		}

		/**
		* Saves a serialized Palisade object's JSON string to file as a nested JSON data structure 
		* @param jsoninputstring is the serialized object's nested JSON data string.
		* @param outputFileName is the name of the file to save JSON data string to.
		*/
		void OutputRapidJsonFile(string jsonInputString, string outputFileName) {

			string jsonFileName = outputFileName.append(".txt");

			const char* jsonInput = jsonInputString.c_str();

			rapidjson::Document d;
			d.Parse(jsonInput);
			rapidjson::StringBuffer buffer;
			rapidjson::PrettyWriter<rapidjson::StringBuffer> writer(buffer);
			d.Accept(writer);

			ofstream jsonFout;
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
		unordered_map<string, string> GetSerializationMapNode(rapidjson::Document &doc, string nodeName) {
			
			//cout << "---" << nodeName << "---" << endl;
			unordered_map<string, string> nodeMap;
			const rapidjson::Value& node = doc[nodeName.c_str()];
			for (rapidjson::Value::ConstMemberIterator it = node.MemberBegin(); it != node.MemberEnd(); it++) {
				//cout << it->name.GetString() << " | " << it->value.GetString() << endl;
				nodeMap.emplace(it->name.GetString(), it->value.GetString());
			}

			return nodeMap;
		}

		/**
		* Generates a map of attribute name value pairs for deserializing a Palisade object from a JSON file
		* @param jsonFileName is the file to read in for the Palisade object's nested serialized JSON data structure.
		* @return map containing name value pairs for the attributes of the Palisade object to be deserialized.
		*/
		unordered_map<string, unordered_map<string, string>> GetSerializationMap(string jsonFileName) {
			
			unordered_map<string, unordered_map<string, string>> serializationMap;
			unordered_map<string, string> childMap;

			//Retrieve contents of output Json file
			string jsonReadLine;
			string jsonReadBuffer;
			ifstream jsonFin(jsonFileName);
			while (getline(jsonFin, jsonReadLine)) {
				jsonReadBuffer += jsonReadLine;
			}
			jsonFin.close();

			//Retrieve elements from output Json file
			rapidjson::Document doc;
			doc.Parse(jsonReadBuffer.c_str());

			string ID = doc["Root"]["ID"].GetString();
			serializationMap.emplace("Root", GetSerializationMapNode(doc, "Root"));
			serializationMap.emplace("LPCryptoParametersLWE", GetSerializationMapNode(doc, "LPCryptoParametersLWE"));
			serializationMap.emplace("ILParams", GetSerializationMapNode(doc, "ILParams"));
			if (ID.compare("LPEvalKeyLWENTRU") != 0) {
				serializationMap.emplace("ILVector2n", GetSerializationMapNode(doc, "ILVector2n"));
			} else {
				int evalKeyVectorLength = stoi(doc["Root"]["VectorLength"].GetString());
				for (int i = 0; i < evalKeyVectorLength; i++) {
					string indexName = "ILVector2n";
					indexName.append(ToStr(i));
					serializationMap.emplace(indexName, GetSerializationMapNode(doc, indexName));
				}
			}

			return serializationMap;
		}
	};
}