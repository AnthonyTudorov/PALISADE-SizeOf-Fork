/**0
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
#include "serializablehelper.h"

using namespace std;

namespace lbcrypto {

		/**
		* Generates a nested JSON data string for a serialized Palisade object
		* @param serObj input serialization of object
		* @param jsonString output string representation
		* @return success or failure
		*/
		bool SerializableHelper::SerializationToString(const Serialized& serObj, std::string& jsonString) {

			rapidjson::StringBuffer buffer;
			rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
			serObj.Accept(writer);

			jsonString = buffer.GetString();
			return writer.IsComplete();
		}

		/**
		* Generates a nested JSON data string for a serialized Palisade object
		* @param serObj stores the serialized Palisade object's attributes.
		* @return string reflecting the nested JSON data structure of the serialized Palisade object.
		*/
		bool SerializableHelper::StringToSerialization(const std::string& jsonString, Serialized* serObj) {

			return !serObj->Parse( jsonString.c_str() ).HasParseError();
		}

		/**
		* Saves a serialized Palisade object's JSON string to file as a nested JSON data structure 
		* @param doc is the serialized object's nested JSON data string.
		* @param outputFileName is the name of the file to save JSON data string to.
		*/
		bool SerializableHelper::WriteSerializationToFile(const Serialized& doc, std::string outputFileName) {

			FILE *fp = fopen(outputFileName.c_str(), "w");
			if( fp == 0 ) return false;

			char writeBuffer[32768];
			rapidjson::FileWriteStream os(fp, writeBuffer, sizeof(writeBuffer));

			rapidjson::Writer<rapidjson::FileWriteStream> writer(os);
			doc.Accept(writer);

			fclose(fp);
			return true;
		}

		/**
		* Generates a map of attribute name value pairs for deserializing a Palisade object from a JSON file
		* @param jsonFileName is the file to read in for the Palisade object's nested serialized JSON data structure.
		* @param serObj containing name value pairs for the attributes of the Palisade object to be deserialized.
		*/
		bool SerializableHelper::ReadSerializationFromFile(const std::string jsonFileName, Serialized* serObj) {
			
			//Retrieve contents of input Json file
			FILE *fp = fopen(jsonFileName.c_str(), "r");
			if( fp == 0 ) return false;

			char readBuffer[32768];
			rapidjson::FileReadStream is(fp, readBuffer, sizeof(readBuffer));

			serObj->ParseStream(is);
			fclose(fp);

			return !serObj->HasParseError();
		}

}
