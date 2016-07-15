/**
 * @file
 * @author  TPOC: Dr. Kurt Rohloff <rohloff@njit.edu>,
 *	Programmers: Dr. Yuriy Polyakov, <polyakov@njit.edu>, Gyana Sahu <grs22@njit.edu>
 * @version 00_03
 *
 * @section LICENSE
 * 
 * Copyright (c) 2015, New Jersey Institute of Technology (NJIT)
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met: 1. Redistributions of source code must retain the above
 * copyright notice, this list of conditions and the following
 * disclaimer.  2. Redistributions in binary form must reproduce the
 * above copyright notice, this list of conditions and the following
 * disclaimer in the documentation and/or other materials provided
 * with the distribution.  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT
 * HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY,
 * OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY
 * OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
 * USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
 * DAMAGE.
 *
 * @section DESCRIPTION
 *
 * This file contains the cpp implementation of  ubintvec, a <vector> of ubint, with associated math operators.
 * NOTE: this has been refactored so that implied modulo (ring)  aritmetic is in mbintvec
 *
 */

#include "mubintvec.h"

namespace exp_int32 {

  //CTORS
  // basic constructor
  template<class bint_el_t>
  mubintvec<bint_el_t>::mubintvec(){
    this->m_modulus = 0;
    m_modulus_state = GARBAGE;
  }

  // Basic constructor for specifying the length of the vector.
  template<class bint_el_t>
  mubintvec<bint_el_t>::mubintvec(const usint length){
    this->m_data.resize(length);

    //this->m_data = new bint_el_t*[m_length];
    for (usint i = 0; i < length; i++){
      this->m_data[i] = bint_el_t::ZERO;
    }
    m_modulus = 0;
    m_modulus_state = GARBAGE;

  }
  // Basic constructor for specifying the length of the vector and modulus.
  template<class bint_el_t>
  mubintvec<bint_el_t>::mubintvec(const usint length, const usint &modulus){
    this->m_data.resize(length);
    for (usint i = 0; i < length; i++){
      this->m_data[i] = bint_el_t::ZERO;
    }
    m_modulus = modulus;
    m_modulus_state = INITIALIZED;
  }

  // Basic constructor for specifying the length of the vector and modulus.
  template<class bint_el_t>
  mubintvec<bint_el_t>::mubintvec(const usint length, const bint_el_t &modulus){
    this->m_data.resize(length);
    for (usint i = 0; i < length; i++){
      this->m_data[i] = bint_el_t::ZERO;
    }
    m_modulus = modulus;
    m_modulus_state = INITIALIZED;
  }

  // Basic constructor for specifying the length of the vector and modulus.
  template<class bint_el_t>
  mubintvec<bint_el_t>::mubintvec(const usint length, const std::string &modulus){
    this->m_data.resize(length);
    for (usint i = 0; i < length; i++){
      this->m_data[i] = bint_el_t::ZERO;
    }
    m_modulus = modulus;
    m_modulus_state = INITIALIZED;
  }


  //
  // constructor specifying the mubintvec as a vector of strings and modulus
  template<class bint_el_t>
  mubintvec<bint_el_t>::mubintvec(const std::vector<std::string> &s, const bint_el_t &modulus) {
    this->m_data.resize(s.size());
    for (usint i = 0; i < s.size(); i++){
      this->m_data[i] = bint_el_t(s[i]);
    }
    m_modulus = bint_el_t(modulus);
    m_modulus_state = INITIALIZED;
  }

 //constructor specifying the mubintvec as a vector of strings with string modulus
  template<class bint_el_t>
  mubintvec<bint_el_t>::mubintvec(const std::vector<std::string> &s, const std::string &modulus) {
    this->m_data.resize(s.size());
    for (usint i = 0; i < s.size(); i++){
      this->m_data[i] = bint_el_t(s[i]);
    }
    m_modulus = bint_el_t(modulus);
    m_modulus_state = INITIALIZED;
  }


  //copy constructor
  template<class bint_el_t>
  mubintvec<bint_el_t>::mubintvec(const mubintvec &in_bintvec){
    //todo: redo
    usint length = in_bintvec.m_data.size();
    this->m_data.resize(length);
    for(usint i=0;i < length;i++){
      this->m_data[i]= in_bintvec.m_data[i];
    }
    m_modulus = in_bintvec.m_modulus;
    m_modulus_state = INITIALIZED;
  }

  template<class bint_el_t>
  mubintvec<bint_el_t>::mubintvec(mubintvec &&in_bintvec){
    this->m_data.swap(in_bintvec.m_data);
    if (in_bintvec.m_data.size()>0)
      in_bintvec.m_data.clear();
    m_modulus = in_bintvec.m_modulus;
    m_modulus_state = in_bintvec.m_modulus_state;
  }


  //ASSIGNMENT copy allocator const mubinvec to mubinvec
  //will resize target vector
  //will overwrite target modulus
  template<class bint_el_t>
  const mubintvec<bint_el_t>& mubintvec<bint_el_t>::operator=(const mubintvec &rhs){
    if(this!=&rhs){
      if(this->m_data.size()==rhs.m_data.size()){
        for (usint i = 0; i < this->m_data.size(); i++){
          *this->m_data[i] = *rhs.m_data[i];
        }
      }
      else{
       this->m_data.resize(rhs.m_data.size());
        for (usint i = 0; i < this->m_data.size(); i++){
          this->m_data[i] = *rhs.m_data[i];
        }
      }
      this->m_modulus = rhs.m_modulus;
      this->m_modulus_state = rhs.m_modulus_state;
    }

    return *this;
  }

  // move copy allocator
  template<class bint_el_t>
  const mubintvec<bint_el_t>& mubintvec<bint_el_t>::operator=(mubintvec &&rhs){

    if(this!=&rhs){
      this->m_data.swap(rhs.m_data); //swap the two vector contents,
      if (rhs.m_data.size()>0)
	rhs.m_data.clear();
      this->m_modulus = rhs.m_modulus;
      this->m_modulus_state = rhs.m_modulus_state;
    }

    return *this;

  }

  //desctructor
  template<class bint_el_t>
  mubintvec<bint_el_t>::~mubintvec(){
    //std::cout<<"destructor called for vector of size: "<<this->m_data.size()<<"  "<<std::endl;
    this->m_data.clear();
  }

  //ACCESSORS
  //stream <<
  template<class bint_el_t_c>
  std::ostream& operator<<(std::ostream& os, const mubintvec<bint_el_t_c> &ptr_obj){

    os<<std::endl;
    for(usint i=0;i<ptr_obj.m_data.size();i++){
      os<<ptr_obj.m_data[i] <<std::endl;
    }

    os<<"modulus: "<<ptr_obj.m_modulus;
    os <<std::endl;

    return os;
  }

  //modulus accessors
  template<class bint_el_t>
  void mubintvec<bint_el_t>::SetModulus(const usint& value){
    m_modulus= bint_el_t(value);
    m_modulus_state = INITIALIZED;
  }
  
  template<class bint_el_t>
  void mubintvec<bint_el_t>::SetModulus(const bint_el_t& value){
    m_modulus= value;
    m_modulus_state = INITIALIZED;
  }
  
  
  template<class bint_el_t>
  void mubintvec<bint_el_t>::SetModulus(const std::string& value){
    m_modulus= bint_el_t(value);
    m_modulus_state = INITIALIZED;
  }
  
  
  template<class bint_el_t>
  const bint_el_t& mubintvec<bint_el_t>::GetModulus() const{
    if (m_modulus_state != INITIALIZED)
      throw std::logic_error("GetModulus() on uninitialized mubintvec");

    return(&m_modulus);
  }
  
  //Math functions
  // Mod
  template<class bint_el_t>
  mubintvec<bint_el_t> mubintvec<bint_el_t>::Mod(const bint_el_t& modulus) const{
    mubintvec ans(*this);
    for(usint i=0;i<this->m_data.size();i++){
      ans.m_data[i] = ans.m_data[i].Mod(modulus);
    }
    ans.m_modulus = modulus;
    ans. m_modulus_state = INITIALIZED;
    return ans;
  }

  // %=
  // method to vector with scalar
  template<class bint_el_t>
  const mubintvec<bint_el_t>& mubintvec<bint_el_t>::operator%=(const bint_el_t& modulus) {

    *this = *this.Mod(modulus);
    return *this;

  }




    template<class bint_el_t>
  mubintvec<bint_el_t> mubintvec<bint_el_t>::ModAdd(const bint_el_t &b) const{
    mubintvec ans(*this);
    for(usint i=0;i<this->m_data.size();i++){
      ans.m_data[i] = ans.m_data[i]->ModAdd(b, ans.m_modulus);
    }
    return ans;
  }

  // method to subtract scalar from vector
  template<class bint_el_t>
  mubintvec<bint_el_t> mubintvec<bint_el_t>::ModSub(const bint_el_t &b) const{
    mubintvec ans(*this);
    for(usint i=0;i<this->m_data.size();i++){
      ans.m_data[i] = ans.m_data[i]->ModSub(b, ans.m_modulus);
    }
    return ans;
  }


  // method to multiply vector by scalar
  template<class bint_el_t>
  mubintvec<bint_el_t> mubintvec<bint_el_t>::ModMul(const bint_el_t &b) const{
    mubintvec ans(*this);
    for(usint i=0;i<this->m_data.size();i++){
      ans.m_data[i] = ans.m_data[i]->ModMul(b, ans.m_modulus);
    }
    return ans;
  }

  // vector elementwise add
  template<class bint_el_t>
  mubintvec<bint_el_t> mubintvec<bint_el_t>::ModAdd(const mubintvec &b) const{
    
    mubintvec ans(*this);
    if(this->m_modulus!=b.m_modulus){
      throw std::logic_error("mubintvec adding vectors of different moduli");
    } else if(this->m_data.size()!=b.m_data.size()){
      throw std::logic_error("mubintvec adding vectors of different lengths");
    } else {
      for(usint i=0;i<ans.m_data.size();i++){
	ans.m_data[i] = ans.m_data[i].ModAdd(b.m_data[i], ans.m_modulus);
      }
      return ans;
    }
  }

  // vector elementwise subtract
  template<class bint_el_t>
  mubintvec<bint_el_t> mubintvec<bint_el_t>::ModSub(const mubintvec &b) const{
    
    mubintvec ans(*this);
    if(this->m_modulus!=b.m_modulus){
      throw std::logic_error("mubintvec subtracting vectors of different moduli");
    } else if(this->m_data.size()!=b.m_data.size()){
      throw std::logic_error("mubintvec subtracting vectors of different lengths");
    } else {

      for(usint i=0;i<ans.m_data.size();i++){
	ans.m_data[i] = ans.m_data[i].ModSub(b.m_data[i],ans.m_modulus);
      }
      return ans;
    }
  }

  // vector elementwise multiply
  template<class bint_el_t>
  mubintvec<bint_el_t> mubintvec<bint_el_t>::ModMul(const mubintvec &b) const{
    
    mubintvec ans(*this);
    if(this->m_modulus!=b.m_modulus){
      throw std::logic_error("mubintvec multiplying vectors of different moduli");
    }else if(this->m_data.size()!=b.m_data.size()){
      throw std::logic_error("mubintvec multiplying vectors of different lengths");
    } else {
      for(usint i=0;i<ans.m_data.size();i++){
        ans.m_data[i] = ans.m_data[i].ModMul(b.m_data[i],ans.m_modulus);
      }
      return ans;
    }
  }

  // assignment operators

  template<class bint_el_t>
  const mubintvec<bint_el_t>& mubintvec<bint_el_t>::operator+=(const mubintvec &b) {
    if(this->m_modulus!=b.m_modulus){
      throw std::logic_error("mubintvec += vectors of different moduli");
    }else if(this->m_data.size()!=b.m_data.size()){
      throw std::logic_error("mubintvec += vectors of different lengths");
    }

    *this = *this + b;
    return *this;
  }

  template<class bint_el_t>
  const mubintvec<bint_el_t>& mubintvec<bint_el_t>::operator-=(const mubintvec &b) {
    if(this->m_modulus!=b.m_modulus){
      throw std::logic_error("mubintvec -= vectors of different moduli");
    }else if(this->m_data.size()!=b.m_data.size()){
      throw std::logic_error("mubintvec -= vectors of different lengths");
    }
    *this = *this - b;
    return *this;
  }

  // JSON FACILITY - SetIdFlag Operation
  template<class bint_el_t>
  std::unordered_map <std::string, std::unordered_map <std::string, std::string>> mubintvec<bint_el_t>::SetIdFlag(std::unordered_map <std::string, std::unordered_map <std::string, std::string>> serializationMap, std::string flag) const {

    //Place holder

    return serializationMap;
  }

  // JSON FACILITY - Serialize Operation
  template<class bint_el_t>
  std::unordered_map <std::string, std::unordered_map <std::string, std::string>> mubintvec<bint_el_t>::Serialize(std::unordered_map <std::string, std::unordered_map <std::string, std::string>> serializationMap, std::string fileFlag) const {

    std::unordered_map <std::string, std::string> bbvMap;

    //bbvMap.emplace("Modulus", this->GetModulus().ToString());

    std::string pkBufferString;
    bint_el_t pkVectorElem;
    usint pkVectorLength = 0;
    std::string pkVectorElemVal;
    pkVectorLength = this->GetLength();
    for (int i = 0; i < pkVectorLength; i++) {
      pkVectorElem = this->GetValAtIndex(i);

      pkVectorElemVal = pkVectorElem.ToString();

      pkBufferString += pkVectorElemVal;
      if (i != (pkVectorLength - 1)) {
	pkBufferString += "|";
      }
    }
    bbvMap.emplace("VectorValues", pkBufferString);

    serializationMap.emplace("bintvec", bbvMap);

    return serializationMap;
  }

  // JSON FACILITY - Deserialize Operation
  template<class bint_el_t>
  void mubintvec<bint_el_t>::Deserialize(std::unordered_map <std::string, std::unordered_map <std::string, std::string>> serializationMap) {

    std::unordered_map<std::string, std::string> bbvMap = serializationMap["bintvec"];

    //bint_el_t bbiModulus(bbvMap["Modulus"]);
    //this->SetModulus(bbiModulus);

    std::string vectorVals = bbvMap["VectorValues"];
    bint_el_t vectorElem;
    std::string vectorElemVal;
    usint i = 0;
    while (vectorVals.find("|", 0)) {
      size_t pos = vectorVals.find("|", 0);
      vectorElemVal = vectorVals.substr(0, pos);

      std::string::size_type posTrim = vectorElemVal.find_last_not_of(' ');
      if (posTrim != std::string::npos) {
	if (vectorElemVal.length() != posTrim + 1) {
	  vectorElemVal.erase(posTrim + 1);
	}
	posTrim = vectorElemVal.find_first_not_of(' ');
	if (posTrim != 0) {
	  vectorElemVal.erase(0, posTrim);
	}
      }
      else {
	vectorElemVal = "";
      }

      vectorElem.SetValue(vectorElemVal);
      vectorVals.erase(0, pos + 1);
      this->SetValAtIndex(i, vectorElem);
      i++;

      if (i == this->GetLength()) {
	break;
      }
    }
  }


} // namespace lbcrypto ends
 
