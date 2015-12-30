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
#include <string>
#include <unordered_map>
#define RAPIDJSON_NO_SIZETYPEDEFINE
using namespace std;

namespace lbcrypto {

	class SerializableHelper {

	public:

		SerializableHelper() {}

		/**
		* Generates a nested JSON data string for a serialized Palisade object
		* @param serializationMap stores the serialized Palisade object's attributes.
		* @return string reflecting the nested data structure of the serialized Palisade object.
		*/
		string GetJsonString(unordered_map<string, unordered_map<string, string>> serializationMap) {

			string jsonInputBuffer = "";
			unordered_map<string, string> mapBuffer;

			jsonInputBuffer.append("{");

			mapBuffer = serializationMap["Root"];
			jsonInputBuffer.append("\"Root\":");
			jsonInputBuffer.append("{");
			for (unordered_map<string, string>::iterator i = mapBuffer.begin(); i != mapBuffer.end(); i++) {
				jsonInputBuffer.append("\"");
				jsonInputBuffer.append(i->first);
				jsonInputBuffer.append("\"");
				jsonInputBuffer.append(":");
				jsonInputBuffer.append("\"");
				jsonInputBuffer.append(i->second);
				jsonInputBuffer.append("\"");
				jsonInputBuffer.append(",");
			}
			jsonInputBuffer = jsonInputBuffer.substr(0, jsonInputBuffer.length() - 1);
			jsonInputBuffer.append("}");
			jsonInputBuffer.append(",");

			mapBuffer = serializationMap["LPCryptoParametersLWE"];
			jsonInputBuffer.append("\"LPCryptoParametersLWE\":");
			jsonInputBuffer.append("{");
			for (unordered_map<string, string>::iterator i = mapBuffer.begin(); i != mapBuffer.end(); i++) {
				jsonInputBuffer.append("\"");
				jsonInputBuffer.append(i->first);
				jsonInputBuffer.append("\"");
				jsonInputBuffer.append(":");
				jsonInputBuffer.append("\"");
				jsonInputBuffer.append(i->second);
				jsonInputBuffer.append("\"");
				jsonInputBuffer.append(",");
			}
			jsonInputBuffer = jsonInputBuffer.substr(0, jsonInputBuffer.length() - 1);
			jsonInputBuffer.append("}");
			jsonInputBuffer.append(",");

			mapBuffer = serializationMap["ILParams"];
			jsonInputBuffer.append("\"ILParams\":");
			jsonInputBuffer.append("{");
			for (unordered_map<string, string>::iterator i = mapBuffer.begin(); i != mapBuffer.end(); i++) {
				jsonInputBuffer.append("\"");
				jsonInputBuffer.append(i->first);
				jsonInputBuffer.append("\"");
				jsonInputBuffer.append(":");
				jsonInputBuffer.append("\"");
				jsonInputBuffer.append(i->second);
				jsonInputBuffer.append("\"");
				jsonInputBuffer.append(",");
			}
			jsonInputBuffer = jsonInputBuffer.substr(0, jsonInputBuffer.length() - 1);
			jsonInputBuffer.append("}");
			jsonInputBuffer.append(",");

			mapBuffer = serializationMap["ILVector2n"];
			jsonInputBuffer.append("\"ILVector2n\":");
			jsonInputBuffer.append("{");
			for (unordered_map<string, string>::iterator i = mapBuffer.begin(); i != mapBuffer.end(); i++) {
				jsonInputBuffer.append("\"");
				jsonInputBuffer.append(i->first);
				jsonInputBuffer.append("\"");
				jsonInputBuffer.append(":");
				jsonInputBuffer.append("\"");
				jsonInputBuffer.append(i->second);
				jsonInputBuffer.append("\"");
				jsonInputBuffer.append(",");
			}
			jsonInputBuffer = jsonInputBuffer.substr(0, jsonInputBuffer.length() - 1);
			jsonInputBuffer.append("}");

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
		* Generates a map of attribute name value pairs for deserializing a Palisade object from a JSON file
		* @param jsonFileName is the file to read in for the Palisade's object nested serialized JSON data structure.
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

			//cout << "---Root---" << endl;
			const rapidjson::Value& rootNode = doc["Root"];
			for (rapidjson::Value::ConstMemberIterator it = rootNode.MemberBegin(); it != rootNode.MemberEnd(); it++) {
				//cout << it->name.GetString() << " | " << it->value.GetString() << endl;
				childMap.emplace(it->name.GetString(), it->value.GetString());
			}
			serializationMap.emplace("Root", childMap);
			childMap.clear();

			//cout << "---CryptoParams---" << endl;
			const rapidjson::Value& cryptoParamsNode = doc["LPCryptoParametersLWE"];
			for (rapidjson::Value::ConstMemberIterator it = cryptoParamsNode.MemberBegin(); it != cryptoParamsNode.MemberEnd(); it++) {
				//cout << it->name.GetString() << " | " << it->value.GetString() << endl;
				childMap.emplace(it->name.GetString(), it->value.GetString());
			}
			serializationMap.emplace("LPCryptoParametersLWE", childMap);
			childMap.clear();

			//cout << "---ILParams---" << endl;
			const rapidjson::Value& ilParamsNode = doc["ILParams"];
			for (rapidjson::Value::ConstMemberIterator it = ilParamsNode.MemberBegin(); it != ilParamsNode.MemberEnd(); it++) {
				//cout << it->name.GetString() << " | " << it->value.GetString() << endl;
				childMap.emplace(it->name.GetString(), it->value.GetString());
			}
			serializationMap.emplace("ILParams", childMap);
			childMap.clear();

			//cout << "---ILVector2n---" << endl;
			const rapidjson::Value& ilVector2nNode = doc["ILVector2n"];
			for (rapidjson::Value::ConstMemberIterator it = ilVector2nNode.MemberBegin(); it != ilVector2nNode.MemberEnd(); it++) {
				//cout << it->name.GetString() << " | " << it->value.GetString() << endl;
				childMap.emplace(it->name.GetString(), it->value.GetString());
			}
			serializationMap.emplace("ILVector2n", childMap);
			childMap.clear();

			return serializationMap;
		}
	};
}