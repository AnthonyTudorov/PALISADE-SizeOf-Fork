#include "../../include/rapidjson/document.h"
#include "../../include/rapidjson/writer.h"
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

		string GetJsonString(unordered_map<string, string> serializationMap) {

			string jsonInputBuffer = "";
			jsonInputBuffer.append("{");
			for (unordered_map<string, string>::iterator i = serializationMap.begin(); i != serializationMap.end(); i++) {
				string key = i->first;
				string value = i->second;
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

			return jsonInputBuffer;
		}

		string GetJsonFileName(unordered_map<string, string> serializationMap) {
			return serializationMap["ID"].append("_").append(serializationMap["Flag"]);
		}

		void OutputRapidJsonFile(string jsonInputString, string outputFileName) {

			string jsonFileName = outputFileName.append(".txt");

			const char* jsonInput = jsonInputString.c_str();

			rapidjson::Document d;
			d.Parse(jsonInput);
			rapidjson::StringBuffer buffer;
			rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
			d.Accept(writer);

			ofstream jsonFout;
			jsonFout.open(jsonFileName);
			jsonFout << "\n" << buffer.GetString() << endl;
			jsonFout.close();

		}

		unordered_map<string, string> GetSerializationMap(string jsonFileName) {
			unordered_map<string, string> serializationMap;

			//Retrieve contents of output Json file
			string jsonReadLine;
			string jsonReadBuffer;
			ifstream jsonFin(jsonFileName);
			while (getline(jsonFin, jsonReadLine)) {
				jsonReadBuffer += jsonReadLine;
			}
			jsonFin.close();

			//Retrieve elements from output Json file
			rapidjson::Document d;
			d.Parse(jsonReadBuffer.c_str());

			//Store Json file name value pairs 
			for (rapidjson::SizeType i = 0; i < (d.Size() * 2); i++) {
				if (i != 0) {
					if ((i % 2) != 0) {
						serializationMap.emplace(d[i-1].GetString(), d[i].GetString());
					}
				}
			}

			return serializationMap;
		}
	};
}