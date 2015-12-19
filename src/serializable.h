
#ifndef LBCRYPTO_SERIALIZABLE_H
#define LBCRYPTO_SERIALIZABLE_H

#include <unordered_map>
#include <sstream>
#include <string>

/**
* @namespace lbcrypto
* The namespace of lbcrypto
*/
namespace lbcrypto {

	class Serializable
	{

	public:

		virtual std::unordered_map <std::string, std::string> Serialize(std::unordered_map <std::string, std::string> serializationMap, std::string fileFlag) const = 0; //const added because method does not change implementing class

		virtual std::unordered_map <std::string, std::string> SetIdFlag(std::unordered_map <std::string, std::string> serializationMap, std::string flag) const = 0; //const added because method does not change implementing class

		template <typename T> 
		std::string ToStr(const T& num) const {
			std::ostringstream buffer;
			buffer << num;
			return buffer.str();
		}

		virtual void Deserialize(std::unordered_map <std::string, std::string> serializationMap) = 0;
	};

}

#endif