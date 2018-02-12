
/**
 * @file serializablehelper.h Helper methods for serialization.
 * @author  TPOC: palisade@njit.edu
 *
 * @copyright Copyright (c) 2017, New Jersey Institute of Technology
 * (NJIT) All rights reserved.  Redistribution and use in source and
 * binary forms, with or without modification, are permitted provided
 * that the following conditions are met:

 * 1. Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.

 * 2. Redistributions in binary form must reproduce the above
 * copyright notice, this list of conditions and the following
 * disclaimer in the documentation and/or other materials provided
 * with the distribution.

 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */ 

#ifndef LBCRYPTO_TDSERIALIZABLEHELPER_H
#define LBCRYPTO_TDSERIALIZABLEHELPER_H

// serializable helper for trapdoor objects
#include "utils/serializable.h"

#include "utils/rapidjson/document.h"
#include "utils/rapidjson/pointer.h"
#include "utils/rapidjson/reader.h"
#include "utils/rapidjson/writer.h"
#include "utils/rapidjson/filereadstream.h"
#include "utils/rapidjson/filewritestream.h"
#include "utils/rapidjson/error/en.h"
#include "utils/rapidjson/prettywriter.h"
#include "utils/rapidjson/stringbuffer.h"
#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <unordered_map>
#include <map>
#include <iterator>
#include <algorithm>

#include "math/backend.h"
#include "math/matrix.h"
#include "lattice/poly.h"
#include "lattice/dcrtpoly.h"
#include "sampling/trapdoor.h"

#define RAPIDJSON_NO_SIZETYPEDEFINE

namespace lbcrypto {

  class TDSerializableHelper {

  public:
    // class method declarations go here, right now there are only templates
  };

  /** 
   * Helper template Adds the contents of an STL vector<RLWETrapdoorPair<foo>>
   * to a serialized Palisade object as a nested JSON data structure
   * foo must be a pointer to a serializable object as the function uses the 
   * foo->Serialize method to serialize.
   * @param vectorName 
   * @param typeName of element within the vector
   * @param inVector the STL vector to be serialized
   * @param *serObj the serial object to be modfied, if not a serial object
   * then it is made a serial object
   * throws a Palisade serialize_error on error
   * @return void  
   */
  
  template<typename T>
    void SerializeVectorOfRLWETrapdoorPair(const std::string& vectorName, const std::string& typeName, const std::vector<RLWETrapdoorPair<T>> &inVector, Serialized* serObj) {

    //make sure the input is a rapidjson object
    if( ! serObj->IsObject() )
      serObj->SetObject();
    
    //make top level member
    Serialized topser(rapidjson::kObjectType, &serObj->GetAllocator());
    //add top member components
    topser.AddMember("Container", "VectorOfRLWETrapdoorPair", serObj->GetAllocator());
    topser.AddMember("Typename", typeName, serObj->GetAllocator());
    topser.AddMember("Length", std::to_string(inVector.size()), serObj->GetAllocator());

    // make member container for all elements
    Serialized serElements(rapidjson::kObjectType, &serObj->GetAllocator());

    for( size_t i=0; i<inVector.size(); i++ ) {//for each element
      //serialize the ith element
      Serialized oneEl(rapidjson::kObjectType, &serObj->GetAllocator());
      

      std::string elName  = "R_Matrix_"+std::to_string(i);
      SerializeMatrix(elName, typeName, inVector[i].m_r, &oneEl);

      elName  = "E_Matrix_"+std::to_string(i);
      SerializeMatrix(elName, typeName, inVector[i].m_e, &oneEl);

      //add it with the index as a key to the member container
      SerialItem key( std::to_string(i), serObj->GetAllocator() );
      serElements.AddMember(key, oneEl.Move(), serObj->GetAllocator());
    }

    //add the member container to the top level
    topser.AddMember("Members", serElements.Move(), serObj->GetAllocator());

    //add the top level to the inpupt serial item
    serObj->AddMember(SerialItem(vectorName, serObj->GetAllocator()), topser, serObj->GetAllocator());
  }



  /** 
   * Helper template Fills an STL vector<<matrix<foo>> with the contents of a 
   *  a serialized Palisade object made with SerializeVectorOfMatrix()
   * foo must be a serializable object as the function uses the 
   * foo.DeSerialize method to serialize.
   * @param vectorName name of vector
   * @param typeName of element within the matrix
   * @param outVector the STL  Vector to contain the result 
   * @param it an iterator into the serial object to be deserialised
   * throws a Palisade deserialize_error on error
   * @return true if successful 
   */

  //todo: should be made a void return

  template<typename T>
    bool DeserializeVectorOfRLWETrapdoorPair(const std::string& VectorName, const std::string& typeName, const SerialItem::ConstMemberIterator& it, vector<RLWETrapdoorPair<T>>* outVector /*, std::function<unique_ptr<T>(void)> alloc_function */) {
   
    bool dbg_flag = false;
    
    DEBUG("Searching for Typename");
    SerialItem::ConstMemberIterator mIt = it->value.FindMember("Typename");
    if( mIt == it->value.MemberEnd() ) {
      PALISADE_THROW(lbcrypto::deserialize_error, "could not find Typename  ");
    }

    DEBUG("Searching for "<<typeName);   
    if( mIt->value.GetString() != typeName ) {
      PALISADE_THROW(lbcrypto::deserialize_error,
		     "Wrong type name found: "+ string(mIt->value.GetString())
		     + "expected :" +typeName );
    }
    DEBUG("Found "<<typeName);      

    DEBUG("Searching for Length");   
    mIt = it->value.FindMember("Length");
    if( mIt == it->value.MemberEnd() ) {
      PALISADE_THROW(lbcrypto::deserialize_error, "could not find Length");
        
    
    }

    DEBUG("Found "<< std::stoi(mIt->value.GetString()));      
    size_t length = std::stoi(mIt->value.GetString());
    
    outVector->clear();
    //outVector->resize( std::stoi(mIt->value.GetString()) );
   
    mIt = it->value.FindMember("Members");
    if( mIt == it->value.MemberEnd() ){
      PALISADE_THROW(lbcrypto::deserialize_error, "could not find Members");
    }
    DEBUG("found members");
    const SerialItem& members = mIt->value;
    DEBUG("looping over members");
    //loop over entire vector
    for( size_t i=0; i<length; i++ ) {
      std::string keystring = std::to_string(i);

      //find this key (the index)
      DEBUG(" Searching for "<<keystring);
      Serialized::ConstMemberIterator eIt = members.FindMember(keystring);
      if( eIt == members.MemberEnd() ) {
	PALISADE_THROW(lbcrypto::deserialize_error, "could not find vector entry "+to_string(i));
      }
      DEBUG(" found "<<keystring);
      
      RLWETrapdoorPair<T> tpair(Matrix<T>([](){ return make_unique<T>(); }, 0,0),
				Matrix<T>([](){ return make_unique<T>(); }, 0,0));
      
      for (usint pair_ix = 0; pair_ix < 2; pair_ix++) {
      //within the key's member, find the sub member with the typename
      //and point to it with s2.
	string matrix_name("");
	
	if (pair_ix == 0) {
	  matrix_name = "R_Matrix_"+to_string(i);
	}else{
	  matrix_name = "E_Matrix_"+to_string(i);
	}
	
	DEBUG(" Searching for "<<matrix_name);
	SerialItem::ConstMemberIterator s2 = eIt->value.FindMember(matrix_name);
	if( s2 == eIt->value.MemberEnd() ){
	  PALISADE_THROW(lbcrypto::deserialize_error,
			 "could not find matrix name "+ matrix_name);
	}
	DEBUG("Found "<<matrix_name);
	
	// within s2,
	Serialized ser(rapidjson::kObjectType);
	SerialItem k( typeName, ser.GetAllocator() );
	SerialItem v( s2->value, ser.GetAllocator() );
	DEBUGEXP(i);
	if (s2->value.IsString()) {
	  DEBUGEXP(s2->value.GetString());
	}
	if (s2->value.IsUint64()){ 
	  DEBUGEXP(s2->value.GetUint64());
	}
	ser.AddMember(k, v, ser.GetAllocator());
	
	//now deserialize the Matrix at in s2
	std::string mat_name = "Matrix";
	//std::string elemname = (outVector->at(i)).GetElementName(); fails for T==BitInt
	std::string elem_name = typeName;
	DEBUG("Calling DeserializeMatrix of pair_ix "<<pair_ix);
	
	auto pT = make_shared<Matrix<T>>([](){ return make_unique<T>(); }, 0,0); 
	bool rc = DeserializeMatrix(mat_name, elem_name, s2, pT.get());
	if (rc) {
	  DEBUG("Deserialized matrix at index "<<i);
	} else {
	  PALISADE_THROW(lbcrypto::deserialize_error, "Deserialization of Matrix "+to_string(i)+" failed internally");
	}
	if (pair_ix == 0) {
	  tpair.m_r = *pT;
	}else{
	  tpair.m_e = *pT;
	}
      }
      outVector->push_back(tpair); //store the pointer to the Matrix<T> into the vector location
    }
    return true;
  }

  #if 0
  
  // TODO: These functions appear to be used only in
  // benchmark/src/diffSnapshot.cpp they should be documented and
  // possibly moved to another file in utils?
  
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
#endif
}

#endif
