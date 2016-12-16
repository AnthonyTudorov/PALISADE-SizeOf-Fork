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

#include "../../utils/serializable.h"
#include "gmpintvec.h"


namespace NTL {

  // constructor specifying the myvec as a vector of strings
  template<class myT>
  myVec<myT>::myVec(std::vector<std::string> &s){
    this->SetLength(s.size());
    for (usint i = 0; i < s.size(); i++){
      (*this)[i] = myT(s[i]);
    }
  }
  

  //Assignment with initializer list of myZZ
  // note, resizes the vector to the length of the initializer list
  template<class myT>
  const myVec<myT>& myVec<myT>::operator=(std::initializer_list<myT> rhs){
    usint len = rhs.size();
    clear(*this);
    for(usint i=0;i<len;i++){ // this loops over each entry
      if(i<len) {
	//this->push_back(myT(*(rhs.begin()+i)));
	this->append(myT(*(rhs.begin()+i)));
      } else {
	//this->push_back(myT::ZERO);
	this->append(myT::ZERO);
      }
    }
    return *this;
  }

  //Assignment with initializer list of usints
  template<class myT>
  const myVec<myT>& myVec<myT>::operator=(std::initializer_list<usint> rhs){
    usint len = rhs.size();
    clear(*this);
    for(usint i=0;i<len;i++){ // this loops over each entry
      if(i<len) {
	this->push_back( myT(*(rhs.begin()+i)));
      } else {
	this->push_back(myT::ZERO);
      }
    }
    return *this;
  }

  //Assignment with initializer list of strings
  template<class myT>
  const myVec<myT>& myVec<myT>::operator=(std::initializer_list<std::string> rhs){
    usint len = rhs.size();
    clear(*this);
    for(usint i=0;i<len;i++){ // this loops over each entry
      if(i<len) {
	this->push_back( myT(*(rhs.begin()+i)));
      } else {
	this->push_back(myT::ZERO);
      }
    }
    return *this;
  }

  // Set value at index from ubint
  template<class myT>
  void myVec<myT>::SetValAtIndex(usint index, const myT& value){
    if(!this->IndexCheck(index)){
      throw std::logic_error("myVec index out of range");
    }
    else{
      this->at(index) = myZZ(value);
    }
  }


  // set value at index from string
  template<class myT>
  void myVec<myT>::SetValAtIndex(usint index, const std::string& str){
    if(!this->IndexCheck(index)){
      throw std::logic_error("myVec index out of range");
    }
    else{
      this->at(index) = myZZ(str);
    }
  }
  // set value at index from const char*
  template<class myT>
  void myVec<myT>::SetValAtIndex(usint index, const char * str){
    if(!this->IndexCheck(index)){
      throw std::logic_error("myVec index out of range");
    }
    else{
      this->at(index) = myZZ(str);
    }
  }

  template<class myT>
  const myT& myVec<myT>::GetValAtIndex(size_t index) const{
    if(!this->IndexCheck(index)){
      throw std::logic_error("myVec index out of range");
    }
    return this->at(index);
  }

  //Private functions
  template<class myT>
  bool myVec<myT>::IndexCheck(usint length) const{
    if(length>this->length())
      return false;
    return true;
  }



} // namespace NTL ends
