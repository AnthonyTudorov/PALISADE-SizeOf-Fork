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

#include "ubintvec.h"
//#include "../nbtheory.h"


namespace exp_int32 {

  //CTORS
  // basic constructor
  template<class bint_el_t>
  ubintvec<bint_el_t>::ubintvec(){
  }

  // Basic constructor for specifying the length of the vector.
  template<class bint_el_t>
  ubintvec<bint_el_t>::ubintvec(usint length){
    m_data.resize(length);

    for (usint i = 0; i < length; i++){
      m_data[i] = bint_el_t::ZERO;
    }
  }

  // constructor specifying the ubintvec as a vector of strings
  template<class bint_el_t>
  ubintvec<bint_el_t>::ubintvec(std::vector<std::string> &s){
    m_data.resize(s.size());
    for (usint i = 0; i < s.size(); i++){
      m_data[i] = bint_el_t(s[i]);
    }
  }

  //copy constructor
  template<class bint_el_t>
  ubintvec<bint_el_t>::ubintvec(const ubintvec &in_bintvec){
    //todo: redo
    usint length = in_bintvec.m_data.size();
    m_data.resize(length);
    for(usint i=0;i < length;i++){
      m_data[i]= in_bintvec.m_data[i];
    }
  }

  template<class bint_el_t>
  ubintvec<bint_el_t>::ubintvec(ubintvec &&in_bintvec){
    m_data = in_bintvec.m_data;
    in_bintvec.m_data.clear();
  }



  //ASSIGNMENT copy allocator const binvec to binvec
  //will resize target vector
  template<class bint_el_t>
  const ubintvec<bint_el_t>& ubintvec<bint_el_t>::operator=(const ubintvec &rhs){
    if(this!=&rhs){
      if(this->m_data.size()==rhs.m_data.size()){
        for (usint i = 0; i < this->m_data.size(); i++){
          *this->m_data[i] = *rhs.m_data[i];
        }
      }
      else{
        m_data.resize(rhs.m_data.size());
        for (usint i = 0; i < m_data.size(); i++){
          m_data[i] = *rhs.m_data[i];
        }
      }
    }

    return *this;
  }

  // move copy allocator
  template<class bint_el_t>
  const ubintvec<bint_el_t>& ubintvec<bint_el_t>::operator=(ubintvec &&rhs){

    if(this!=&rhs){
     this->m_data.swap(rhs.m_data); //swap the two vector contents,
     if (rhs.m_data.size()>0)
          rhs.m_data.clear();
    }

    return *this;

  }

  //desctructor
  template<class bint_el_t>
  ubintvec<bint_el_t>::~ubintvec(){
    //std::cout<<"destructor called for vector of size: "<<this->m_data.size()<<"  "<<std::endl;
    m_data.clear();
  }

  //ACCESSORS
  //stream <<
  template<class bint_el_t_c>
  std::ostream& operator<<(std::ostream& os, const ubintvec<bint_el_t_c> &ptr_obj){

    os<<std::endl;
    for(usint i=0;i<ptr_obj.m_data.size();i++){
      os<<ptr_obj.m_data[i] <<std::endl;
    }

    return os;
  }


  // Set value at index from ubint
  template<class bint_el_t>
  void ubintvec<bint_el_t>::SetValAtIndex(usint index, const bint_el_t& value){

    if(!this->IndexCheck(index)){
      throw std::logic_error("ubintvec index out of range");
    }
    else{
      this->m_data.at(index) = value; //todo use at since it checks bounds
    }
  }

  // set value at index from string
  template<class bint_el_t>
  void ubintvec<bint_el_t>::SetValAtIndex(usint index, const std::string& str){
    if(!this->IndexCheck(index)){
      throw std::logic_error("ubintvec index out of range");
    }
    else{
      this->m_data.at(index).SetValue(str);
    }
  }

  template<class bint_el_t>
  const bint_el_t& ubintvec<bint_el_t>::GetValAtIndex(usint index) const{
    if(!this->IndexCheck(index)){
      throw std::logic_error("ubintvec index out of range");
    }
    return this->m_data[index];
  }




  //todo: deprecate this.
  template<class bint_el_t>
  usint ubintvec<bint_el_t>::GetLength() const{
    return this->m_data.size();
  }

  //todo: deprecate this.
  template<class bint_el_t>
  usint ubintvec<bint_el_t>::size() const{
    return this->m_data.size();
  }

  //Math functions
  // Mod
  template<class bint_el_t>
  ubintvec<bint_el_t> ubintvec<bint_el_t>::Mod(const bint_el_t& modulus) const{
    ubintvec ans(*this);
    for(usint i=0;i<this->m_data.size();i++){
      ans.m_data[i] = ans.m_data[i].Mod(modulus);
    }
    return ans;
  }

    // %=
  // method to vector with scalar
  template<class bint_el_t>
  const ubintvec<bint_el_t>& ubintvec<bint_el_t>::operator%=(const bint_el_t& modulus) {

    *this = *this.Mod(modulus);
    return *this;

  }



  // method to add scalar to vector
  template<class bint_el_t>
  ubintvec<bint_el_t> ubintvec<bint_el_t>::Add(const bint_el_t &b) const{
	ubintvec ans(*this);
    for(usint i=0;i<this->m_data.size();i++){
      ans.m_data[i] = ans.m_data[i]->Add(b);
    }
    return ans;
  }

  // method to subtract scalar from vector
  template<class bint_el_t>
  ubintvec<bint_el_t> ubintvec<bint_el_t>::Sub(const bint_el_t &b) const{
    ubintvec ans(*this);
    for(usint i=0;i<this->m_data.size();i++){
      ans.m_data[i] = ans.m_data[i]->Sub(b);
    }
    return ans;
  }


  // method to multiply vector by scalar
  template<class bint_el_t>
  ubintvec<bint_el_t> ubintvec<bint_el_t>::Mul(const bint_el_t &b) const{
    ubintvec ans(*this);
    for(usint i=0;i<this->m_data.size();i++){
      ans.m_data[i] = ans.m_data[i]->Mul(b);
    }
    return ans;
  }

  // vector elementwise add
  template<class bint_el_t>
  ubintvec<bint_el_t> ubintvec<bint_el_t>::Add(const ubintvec &b) const{
    
    ubintvec ans(*this);
    if(this->m_data.size()!=b.m_data.size()){
      throw std::logic_error("ubintvec adding vectors of different lengths");
    } else {
      for(usint i=0;i<ans.m_data.size();i++){
    	  ans.m_data[i] = ans.m_data[i].Add(b.m_data[i]);
      }
      return ans;
    }
  }

  // vector elementwise subtract
  template<class bint_el_t>
  ubintvec<bint_el_t> ubintvec<bint_el_t>::Sub(const ubintvec &b) const{
    
    ubintvec ans(*this);
    if(this->m_data.size()!=b.m_data.size()){
      throw std::logic_error("ubintvec subtracting vectors of different lengths");
    } else {

      for(usint i=0;i<ans.m_data.size();i++){
    	  ans.m_data[i] = ans.m_data[i].Sub(b.m_data[i]);
      }
      return ans;
    }
  }

  // vector elementwise multiply
  template<class bint_el_t>
  ubintvec<bint_el_t> ubintvec<bint_el_t>::Mul(const ubintvec &b) const{
    
    ubintvec ans(*this);
    if(this->m_data.size()!=b.m_data.size()){
      throw std::logic_error("ubintvec multiplying vectors of different lengths");
    } else {
      for(usint i=0;i<ans.m_data.size();i++){
        ans.m_data[i] = ans.m_data[i].Mul(b.m_data[i]);
      }
      return ans;
    }
  }

  // vector scalar modulo addition
  template<class bint_el_t>
  ubintvec<bint_el_t> ubintvec<bint_el_t>::ModAdd(const bint_el_t &b, const bint_el_t &modulus) const{
    ubintvec ans(*this);
    for(usint i=0;i<ans.m_data.size();i++){
      ans.m_data[i] = ans.m_data[i].ModAdd(b, modulus);
    }
    
    return ans;
  }
  
  // vector scalar modulo subtraction
  template<class bint_el_t>
  ubintvec<bint_el_t> ubintvec<bint_el_t>::ModSub(const bint_el_t &b, const bint_el_t &modulus) const{
    ubintvec ans(*this);
    for(usint i=0;i<ans.m_data.size();i++){
      ans.m_data[i] = ans.m_data[i].ModSub(b, modulus);
    }
    return ans;
  }

  // vector scalar modulo multiplication
  template<class bint_el_t>
  ubintvec<bint_el_t> ubintvec<bint_el_t>::ModMul(const bint_el_t &b, const bint_el_t &modulus) const{
    ubintvec ans(*this);
    for(usint i=0;i<ans.m_data.size();i++){
      ans.m_data[i] = ans.m_data[i].ModMul(b, modulus);
    }
    return ans;
  }
  


  // vector vector modulo addition
  template<class bint_el_t>
  ubintvec<bint_el_t> ubintvec<bint_el_t>::ModAdd(const ubintvec<bint_el_t> &b, const bint_el_t &modulus) const{
    ubintvec ans(*this);
    if(this->m_data.size()!=b.m_data.size()){
      throw std::logic_error("ubintvec ModAdd vectors of different lengths");
    } else {
      for(usint i=0;i<ans.m_data.size();i++){
	ans.m_data[i] = ans.m_data[i].ModAdd(b.m_data[i], modulus);
      }
      return ans;
    }
  }
  
  // vector vector modulo subtraction
  template<class bint_el_t>
  ubintvec<bint_el_t> ubintvec<bint_el_t>::ModSub(const ubintvec<bint_el_t> &b, const bint_el_t &modulus) const{
    ubintvec ans(*this);
    if(this->m_data.size()!=b.m_data.size()){
      throw std::logic_error("ubintvec ModSub vectors of different lengths");
    } else {
      for(usint i=0;i<ans.m_data.size();i++){
	ans.m_data[i] = ans.m_data[i].ModSub(b.m_data[i], modulus);
      }
      return ans;
    }
  }

  // vector vector modulo multiplication
  template<class bint_el_t>
  ubintvec<bint_el_t> ubintvec<bint_el_t>::ModMul(const ubintvec<bint_el_t> &b, const bint_el_t &modulus) const{
    ubintvec ans(*this);
    if(this->m_data.size()!=b.m_data.size()){
        throw std::logic_error("ubintvec ModMul vectors of different lengths");
    } else {
      for(usint i=0;i<ans.m_data.size();i++){
	ans.m_data[i] = ans.m_data[i].ModMul(b.m_data[i], modulus);
      }
      return ans;
    }
  }

  // assignment operators

  template<class bint_el_t>
  const ubintvec<bint_el_t>& ubintvec<bint_el_t>::operator+=(const ubintvec &b) {

    if(this->m_data.size()!=b.m_data.size()){
      throw std::logic_error("ubintvec += vectors of different lengths");
    }

    for(usint i=0;i<this->m_data.size();i++){
      this->m_data[i] = this->m_data[i].Add(b.m_data[i]);
    }
    return *this;

  }

  template<class bint_el_t>
  const ubintvec<bint_el_t>& ubintvec<bint_el_t>::operator-=(const ubintvec &b) {

    if(this->m_data.size()!=b.m_data.size()){
      throw std::logic_error("ubintvec -= vectors of different lengths");
    }

    for(usint i=0;i<this->m_data.size();i++){
      *this->m_data[i] = this->m_data[i]->Sub(*b.m_data[i]);
    }
    return *this;

  }


  //Gets the ind
  template<class bint_el_t>
  ubintvec<bint_el_t> ubintvec<bint_el_t>::GetDigitAtIndexForBase(usint index, usint base) const{
    ubintvec ans(*this);
    for(usint i=0;i<this->m_data.size();i++){
      *ans.m_data[i] = bint_el_t(ans.m_data[i]->GetDigitAtIndexForBase(index,base));
    }

    return ans;
  }

  // JSON FACILITY - SetIdFlag Operation
  template<class bint_el_t>
  std::unordered_map <std::string, std::unordered_map <std::string, std::string>> ubintvec<bint_el_t>::SetIdFlag(std::unordered_map <std::string, std::unordered_map <std::string, std::string>> serializationMap, std::string flag) const {

    //Place holder

    return serializationMap;
  }

  // JSON FACILITY - Serialize Operation
  template<class bint_el_t>
  std::unordered_map <std::string, std::unordered_map <std::string, std::string>> ubintvec<bint_el_t>::Serialize(std::unordered_map <std::string, std::unordered_map <std::string, std::string>> serializationMap, std::string fileFlag) const {

    std::unordered_map <std::string, std::string> bbvMap;

    //bbvMap.emplace("Modulus", this->GetModulus().ToString());

    std::string pkBufferString;
    bint_el_t pkVectorElem;
    usint pkVectorLength = 0;
    std::string pkVectorElemVal;
    pkVectorLength = GetLength();
    for (int i = 0; i < pkVectorLength; i++) {
      pkVectorElem = GetValAtIndex(i);

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
  void ubintvec<bint_el_t>::Deserialize(std::unordered_map <std::string, std::unordered_map <std::string, std::string>> serializationMap) {

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

  //Private functions
  template<class bint_el_t>
  bool ubintvec<bint_el_t>::IndexCheck(usint length) const{
    if(length>this->m_data.size())
      return false;
    return true;
  }

} // namespace lbcrypto ends
