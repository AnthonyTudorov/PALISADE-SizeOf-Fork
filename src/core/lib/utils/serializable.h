/**
 * @file serializable.h Serialization utilities.
 * @author  TPOC: palisade@njit.edu
 *
 * @copyright Copyright (c) 2017, New Jersey Institute of Technology (NJIT)
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
 */ 
#ifndef LBCRYPTO_SERIALIZABLE_H
#define LBCRYPTO_SERIALIZABLE_H

#include <vector>
#include <unordered_map>
#include <sstream>
#include <string>
#include <iomanip>
#include <iostream>

#ifndef CEREAL_RAPIDJSON_HAS_STDSTRING
#define CEREAL_RAPIDJSON_HAS_STDSTRING 1
#endif
#ifndef CEREAL_RAPIDJSON_HAS_CXX11_RVALUE_REFS
#define CEREAL_RAPIDJSON_HAS_CXX11_RVALUE_REFS 1
#endif
#define CEREAL_RAPIDJSON_HAS_CXX11_NOEXCEPT 0


#ifdef __GNUC__
#if __GNUC__ >= 8
#pragma GCC diagnostic ignored "-Wclass-memaccess"
#endif
#endif

#ifdef __clang__
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wunused-private-field"
#endif

#include "cereal/cereal.hpp"
#include "cereal/archives/json.hpp"
#include "cereal/archives/binary.hpp"
#include "cereal/archives/portable_binary.hpp"
#include "cereal/types/string.hpp"
#include "cereal/types/vector.hpp"
#include "cereal/types/map.hpp"
#include "cereal/types/memory.hpp"
#include "cereal/types/polymorphic.hpp"

#ifdef __GNUC__
#if __GNUC__ >= 8
#pragma GCC diagnostic pop
#endif
#endif

#ifdef __clang__
#pragma clang diagnostic pop
#endif

/**
* @namespace lbcrypto
* The namespace of lbcrypto
*/
namespace lbcrypto {

	using SerialItem = rapidjson::Value;
	using Serialized = rapidjson::Document;

	class Serializable
	{
	public:
		virtual ~Serializable() {}

		enum Type {JSON,BINARY,PORTABLEBINARY};

		/**
		* Serialize the object into a Serialized
		* @param serObj is used to store the serialized result. It MUST be a rapidjson Object (SetObject());
		* @return true if successfully serialized
		*/
		virtual bool Serialize(Serialized* serObj) const = 0;

		virtual std::string SerializedObjectName() const { return ""; } // FIXME =0

		/**
		 * SerializeWithoutContext serializes the object but does NOT include the context -
		 * used in places where the object is included in a context
		 *
		 * @param serObj is used to store the serialized result. It MUST be a rapidjson Object (SetObject());
		 * @return true if successfully serialized
		 */
		virtual bool SerializeWithoutContext(Serialized* serObj) const {
			return Serialize(serObj);
		}

		/**
		* Populate the object from the deserialization of the Serialized
		* @param serObj contains the serialized object
		* @return true on success
		*/
		virtual bool Deserialize(const Serialized& serObj) = 0;
	};

	template<typename T>
	inline std::string CallSerObjName(const std::shared_ptr<T> obj) {
		return obj->SerializedObjectName();
	}

	template<typename T>
	inline std::string CallSerObjName(const T& obj) {
		return obj.SerializedObjectName();
	}

	/**
	 * SERIALIZE - macro to serialize OBJ into STREAM using serialization SERTYPE
	 * @param OBJ - the object to be serialized; cereal requires archiver functions
	 * @param WITHNAME - the label to use for the object to be serialized
	 * @param STREAM - the ostream to save the serialization to
	 * @param SERTYPE - a Serializable::Type
	 */
#define SERIALIZEWITHNAME(OBJ, WITHNAME, STREAM, SERTYPE) {				\
		if( SERTYPE == Serializable::Type::JSON ) {						\
			cereal::JSONOutputArchive archive( STREAM );            	\
			archive( cereal::make_nvp(WITHNAME, OBJ) );					\
		}																\
		else if( SERTYPE == Serializable::Type::BINARY ) {				\
			cereal::BinaryOutputArchive archive( STREAM );				\
			archive( cereal::make_nvp(WITHNAME, OBJ) );					\
		}																\
		else if( SERTYPE == Serializable::Type::PORTABLEBINARY ) {		\
			cereal::PortableBinaryOutputArchive archive( STREAM );		\
			archive( cereal::make_nvp(WITHNAME, OBJ) );					\
		}																\
	}

#define SERIALIZE(OBJ, STREAM, SERTYPE) {								\
		std::string label = CallSerObjName(OBJ);						\
		SERIALIZEWITHNAME(OBJ, label, STREAM, SERTYPE);					\
	}

#define DESERIALIZEWITHNAME(OBJ, WITHNAME, STREAM, SERTYPE) {			\
		if( SERTYPE == Serializable::Type::JSON ) {						\
			cereal::JSONInputArchive archive( STREAM );					\
			archive( cereal::make_nvp(WITHNAME, OBJ) );					\
		}																\
		else if( SERTYPE == Serializable::Type::BINARY ) {				\
			cereal::BinaryInputArchive archive( STREAM );				\
			archive( cereal::make_nvp(WITHNAME, OBJ) );					\
		}																\
		else if( SERTYPE == Serializable::Type::PORTABLEBINARY ) {		\
			cereal::PortableBinaryInputArchive archive( STREAM );		\
			archive( cereal::make_nvp(WITHNAME, OBJ) );					\
		}																\
	}

//helper template to stream vector contents provided T has an stream operator<< 
template < typename T >
std::ostream& operator << (std::ostream& os, const std::vector<T>& v)
{
    os << "[";
    for (auto i = v.begin(); i!= v.end(); ++i){
      os << " " << *i;
    }
    os << " ]";
    return os;
 };

}

#endif
