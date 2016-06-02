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
 * This file contains the cpp implementation of  bintvec, a <vector> of bint, with associated math operators.
 * NOTE: this has been refactored so that implied modulo (ring)  aritmetic is in mbintvec
 *
 */

#include "bintvec.h"
//#include "../nbtheory.h"


namespace exp_int32 {

  //CTORS
  // basic constructor
  template<class bint_el_t>
  bintvec<bint_el_t>::bintvec(){
    this->m_length = 0;
    m_data = NULL;
  }

  // Basic constructor for specifying the length of the vector.
  template<class bint_el_t>
  bintvec<bint_el_t>::bintvec(usint length){
    //todo change to vector
    this->m_length = length;

    this->m_data = new bint_el_t*[m_length];
    for (usint i = 0; i < m_length; i++){
      m_data[i] = new bint_el_t();
    }
  }


  template<class bint_el_t>
  bintvec<bint_el_t>::bintvec(const bintvec &in_bintvec){

    m_length = in_bintvec.m_length;
    m_data = new bint_el_t*[m_length];
    for(usint i=0;i<m_length;i++){
      m_data[i]= new bint_el_t(*in_bintvec.m_data[i]);
    }

  }

  template<class bint_el_t>
  bintvec<bint_el_t>::bintvec(bintvec &&in_bintvec){
    m_data = in_bintvec.m_data;
    m_length = in_bintvec.m_length;
    in_bintvec.m_data = NULL;
  }

  //ASSIGNMENT OPERATOR
  template<class bint_el_t>
  bintvec<bint_el_t>& bintvec<bint_el_t>::operator=(const bintvec &rhs){
    if(this!=&rhs){
      if(this->m_length==rhs.m_length){
	for (usint i = 0; i < m_length; i++){
	  *this->m_data[i] = *rhs.m_data[i];
	}
      }
      else{
	//throw std::logic_error("Trying to copy vectors of different size");
	delete m_data;
	m_length = rhs.m_length;
	m_data = new bint_el_t*[m_length];
	for (usint i = 0; i < m_length; i++){
	  m_data[i] = new bint_el_t(*rhs.m_data[i]);
	}
      }
    }

    return *this;
  }

  template<class bint_el_t>
  bintvec<bint_el_t>& bintvec<bint_el_t>::operator=(bintvec &&rhs){

    if(this!=&rhs){

      if(m_data!=NULL){
	for(usint i=0;i<m_length;i++)
	  delete m_data[i];
	delete []m_data;
      }
      m_data = rhs.m_data;
      m_length = rhs.m_length;
      rhs.m_data = NULL;
    }

    return *this;

  }

  template<class bint_el_t>
  bintvec<bint_el_t>::~bintvec(){
    //std::cout<<"destructor called for vector of size: "<<this->m_length<<"  "<<std::endl;
    if(m_data!=NULL){
      for(usint i=0;i<m_length;i++){
	delete  m_data[i];
      }
      delete [] m_data;
    }

  }

  //ACCESSORS
  template<class bint_el_t_c>
  std::ostream& operator<<(std::ostream& os, const bintvec<bint_el_t_c> &ptr_obj){

    os<<std::endl;
    for(usint i=0;i<ptr_obj.m_length;i++){
      os<<*ptr_obj.m_data[i] <<std::endl;
    }

    return os;
  }

  template<class bint_el_t>
  void bintvec<bint_el_t>::SetValAtIndex(usint index, const bint_el_t& value){

    if(!this->IndexCheck(index)){
      std::cout<<"Invalid index input \n";
    }
    else{
      *this->m_data[index] = value;
    }
  }

  template<class bint_el_t>
  void bintvec<bint_el_t>::SetValAtIndex(usint index, const std::string& str){
    if(!this->IndexCheck(index)){
      std::cout<<"Invalid index input \n";
    }
    else{
      this->m_data[index]->SetValue(str);
    }
  }

  template<class bint_el_t>
  const bint_el_t& bintvec<bint_el_t>::GetValAtIndex(usint index) const{
    if(!this->IndexCheck(index)){
      std::cout<<"Invalid index input \n";
      return (bint_el_t)NULL;
    }
    return *this->m_data[index];
  }


  template<class bint_el_t>
  usint bintvec<bint_el_t>::GetLength() const{
    return this->m_length;
  }

  template<class bint_el_t>
  bintvec<bint_el_t> bintvec<bint_el_t>::Mod(const bint_el_t& modulus) const{
    bintvec ans(*this);
    for(usint i=0;i<this->m_length;i++){
      *ans.m_data[i] = ans.m_data[i]->Mod(modulus);
    }
    return ans;
  }



  // method to add scalar to vector
  template<class bint_el_t>
  bintvec<bint_el_t> bintvec<bint_el_t>::Add(const bint_el_t &b) const{
	bintvec ans(*this);
    for(usint i=0;i<this->m_length;i++){
      *ans.m_data[i] = ans.m_data[i]->Add(b);
    }
    return ans;
  }

  // method to subtract scalar from vector
  template<class bint_el_t>
  bintvec<bint_el_t> bintvec<bint_el_t>::Sub(const bint_el_t &b) const{
    bintvec ans(*this);
    for(usint i=0;i<this->m_length;i++){
      *ans.m_data[i] = ans.m_data[i]->Sub(b);
    }
    return ans;
  }

  template<class bint_el_t>
  const bintvec<bint_el_t>& bintvec<bint_el_t>::operator+=(const bintvec &b) {

    if(this->m_length!=b.m_length){
      std::cout<<" Invalid argument \n";
      return (bintvec)NULL;
    }

    for(usint i=0;i<this->m_length;i++){
      *this->m_data[i] = this->m_data[i]->ModAdd(*b.m_data[i],this->m_modulus);
    }
    return *this;

  }

  template<class bint_el_t>
  const bintvec<bint_el_t>& bintvec<bint_el_t>::operator-=(const bintvec &b) {

    if(this->m_length!=b.m_length){
      std::cout<<" Invalid argument \n";
      return (bintvec)NULL;
    }

    for(usint i=0;i<this->m_length;i++){
      *this->m_data[i] = this->m_data[i]->ModSub(*b.m_data[i],this->m_modulus);
    }
    return *this;

  }


  //Gets the ind
  template<class bint_el_t>
  bintvec<bint_el_t> bintvec<bint_el_t>::GetDigitAtIndexForBase(usint index, usint base) const{
    bintvec ans(*this);
    for(usint i=0;i<this->m_length;i++){
      *ans.m_data[i] = bint_el_t(ans.m_data[i]->GetDigitAtIndexForBase(index,base));
    }

    return ans;
  }

  // JSON FACILITY - SetIdFlag Operation
  template<class bint_el_t>
  std::unordered_map <std::string, std::unordered_map <std::string, std::string>> bintvec<bint_el_t>::SetIdFlag(std::unordered_map <std::string, std::unordered_map <std::string, std::string>> serializationMap, std::string flag) const {

    //Place holder

    return serializationMap;
  }

  // JSON FACILITY - Serialize Operation
  template<class bint_el_t>
  std::unordered_map <std::string, std::unordered_map <std::string, std::string>> bintvec<bint_el_t>::Serialize(std::unordered_map <std::string, std::unordered_map <std::string, std::string>> serializationMap, std::string fileFlag) const {

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
  void bintvec<bint_el_t>::Deserialize(std::unordered_map <std::string, std::unordered_map <std::string, std::string>> serializationMap) {

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
  bool bintvec<bint_el_t>::IndexCheck(usint length) const{
    if(length>this->m_length)
      return false;
    return true;
  }

} // namespace lbcrypto ends
