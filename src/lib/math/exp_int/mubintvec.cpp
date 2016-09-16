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
#include "mubintvec.h"

#include "time.h"
#include <chrono>

#include "../../utils/debug.h"

namespace exp_int {

  //CTORS
  // basic constructor
  template<class ubint_el_t>
  mubintvec<ubint_el_t>::mubintvec(){
    bool dbg_flag = false;
    this->m_modulus = 0;
    m_modulus_state = GARBAGE;
    DEBUG("mubintvec ctor()");
  }

  // Basic constructor for specifying the length of the vector.
  template<class ubint_el_t>
  mubintvec<ubint_el_t>::mubintvec(const usint length){
    bool dbg_flag = false;
    this->m_data.resize(length);

    //this->m_data = new ubint_el_t*[m_length];
    for (usint i = 0; i < length; i++){
      this->m_data[i] = ubint_el_t::ZERO;
    }
    m_modulus = 0;
    m_modulus_state = GARBAGE;
    DEBUG("mubintvec ctor(usint length)"<<length);
  }
  // Basic constructor for specifying the length of the vector and modulus.
  template<class ubint_el_t>
  mubintvec<ubint_el_t>::mubintvec(const usint length, const usint &modulus){
    bool dbg_flag = false;
    this->m_data.resize(length);
    for (usint i = 0; i < length; i++){
      this->m_data[i] = ubint_el_t::ZERO;
    }
    m_modulus = modulus;
    m_modulus_state = INITIALIZED;
    this->Mod(modulus);

    DEBUG("mubintvec CTOR( length "<<length<< " modulus usint) "<<modulus);
  }

  // Basic constructor for specifying the length of the vector and modulus.
  template<class ubint_el_t>
  mubintvec<ubint_el_t>::mubintvec(const usint length, const ubint_el_t &modulus){
    bool dbg_flag = false;
    this->m_data.resize(length);
    for (usint i = 0; i < length; i++){
      this->m_data[i] = ubint_el_t::ZERO;
    }
    m_modulus = modulus;
    m_modulus_state = INITIALIZED;
    this->Mod(modulus);
    DEBUG("mubintvec CTOR (length "<<length<< " modulus ubint) "<<modulus.ToString());
  }

  // Baspic constructor for specifying the length of the vector and modulus.
  template<class ubint_el_t>
  mubintvec<ubint_el_t>::mubintvec(const usint length, const std::string &modulus){
    bool dbg_flag = false;
    this->m_data.resize(length);
    for (usint i = 0; i < length; i++){
      this->m_data[i] = ubint_el_t::ZERO;
    }
    m_modulus = modulus;
    m_modulus_state = INITIALIZED;
    DEBUG("mubintvec CTOR (length "<<length<< " modulus string) "<<modulus);
  }


  //
  // constructor specifying the mubintvec as a vector of strings and modulus
  template<class ubint_el_t>
  mubintvec<ubint_el_t>::mubintvec(const std::vector<std::string> &s, const ubint_el_t &modulus) {
    bool dbg_flag = false;
    this->m_data.resize(s.size());
    for (usint i = 0; i < s.size(); i++){
      this->m_data[i] = ubint_el_t(s[i]);
    }
    m_modulus = ubint_el_t(modulus);
    m_modulus_state = INITIALIZED;

    this->Mod(modulus);
    DEBUG("mubintvec CTOR (strvec length "<<s.size()<< " modulus ubint) "<<modulus.ToString());
  }

 //constructor specifying the mubintvec as a vector of strings with string modulus
  template<class ubint_el_t>
  mubintvec<ubint_el_t>::mubintvec(const std::vector<std::string> &s, const std::string &modulus) {
    bool dbg_flag = false;
    this->m_data.resize(s.size());
    for (usint i = 0; i < s.size(); i++){
      this->m_data[i] = ubint_el_t(s[i]);
    }
    m_modulus = ubint_el_t(modulus);
    m_modulus_state = INITIALIZED;
    this->Mod(modulus);
    DEBUG("mubintvec CTOR (strvec length "<<s.size()<< " modulus string) "<<modulus);
  }

  //
  // constructor specifying the mubintvec as an ubintvec and no modulus
  template<class ubint_el_t>
  mubintvec<ubint_el_t>::mubintvec(const ubintvec<ubint_el_t> &b) {
    bool dbg_flag = false;
    this->m_data.resize(b.size());
    //this->m_data = b.m_data; for some reason this did not work, even though
    //we inheret from ubintvec and it is protected... 
    for(auto i = 0; i< b.size(); i++){
      this->m_data[i] = b.GetValAtIndex(i);
    }

    m_modulus = ubint_el_t(0);
    m_modulus_state = GARBAGE;
    DEBUG("mubintvec CTOR from ubint no modulus length "<<b.size());    
  }

  //
  // constructor specifying the mubintvec as an ubintvec and usint modulus
  template<class ubint_el_t>
  mubintvec<ubint_el_t>::mubintvec(const ubintvec<ubint_el_t> &b, const usint &modulus) {
    bool dbg_flag = false;
    this->m_data.resize(b.size());
    //this->m_data = b.m_data; for some reason this did not work, even though
    //we inheret from ubintvec
    for(auto i = 0; i< b.size(); i++){
      this->m_data[i] = b.GetValAtIndex(i);
    }


    m_modulus = ubint_el_t(modulus);
    m_modulus_state = INITIALIZED;
    this->Mod(m_modulus);
    DEBUG("mubintvec CTOR (ubintvec length "<<b.size()<< " modulus usint) "<<modulus);
  }

 //constructor specifying the mubintvec as an ubintvec with string modulus
  template<class ubint_el_t>
  mubintvec<ubint_el_t>::mubintvec(const ubintvec<ubint_el_t> &b, const std::string &modulus) {
    bool dbg_flag = false;
    this->m_data.resize(b.size());
    //this->m_data = b.m_data; for some reason this did not work, even though
    //we inheret from ubintvec
    for(auto i = 0; i< b.size(); i++){
      this->m_data[i] = b.GetValAtIndex(i);

    }


    m_modulus = ubint_el_t(modulus);
    m_modulus_state = INITIALIZED;
    this->Mod(m_modulus);
    DEBUG("mubintvec CTOR (ubintvec length "<<b.size()<< " modulus string) "<<modulus);
  }


 //constructor specifying the mubintvec as an ubintvec with ubint modulus
  template<class ubint_el_t>
  mubintvec<ubint_el_t>::mubintvec(const ubintvec<ubint_el_t> &b, const ubint_el_t &modulus) {
    bool dbg_flag = false;
    this->m_data.resize(b.size());
    //this->m_data = b.m_data; for some reason this did not work, even though
    //we inheret from ubintvec
    for(auto i = 0; i< b.size(); i++){
      this->m_data[i] = b.GetValAtIndex(i);
    }

    m_modulus = modulus;
    m_modulus_state = INITIALIZED;
    this->Mod(m_modulus);
    DEBUG("mubintvec CTOR (ubintvec length "<<b.size()<< " modulus ubint) "<<modulus.ToString());
  }

  //copy constructor
  template<class ubint_el_t>
  mubintvec<ubint_el_t>::mubintvec(const mubintvec &in_bintvec){
    bool dbg_flag = false;
    //todo: redo
    usint length = in_bintvec.m_data.size();
    this->m_data.resize(length);
    for(usint i=0;i < length;i++){
      this->m_data[i]= in_bintvec.m_data[i];
    }
    m_modulus = in_bintvec.m_modulus;
    m_modulus_state = INITIALIZED;

    DEBUG("mubintvec copy CTOR length "<<length<< " modulus "<<m_modulus.ToString());
  }

  template<class ubint_el_t>
  mubintvec<ubint_el_t>::mubintvec(mubintvec &&in_bintvec){
    bool dbg_flag = false;
    this->m_data = in_bintvec.m_data;
      in_bintvec.m_data.clear();
    m_modulus = in_bintvec.m_modulus;
    m_modulus_state = in_bintvec.m_modulus_state;

    DEBUG("mubintvec move CTOR length "<<this->m_data.size()<< " modulus "<<m_modulus.ToString());

  }


  //ASSIGNMENT copy allocator const mubinvec to mubinvec
  //if two vectors are different sized, then it will resize target vector
  //unlike BigBinaryVector which just throws.
  //will overwrite target modulus
  template<class ubint_el_t>
  const mubintvec<ubint_el_t>& mubintvec<ubint_el_t>::operator=(const mubintvec &rhs){
    bool dbg_flag = false;
    if(this!=&rhs){
      if(this->m_data.size()==rhs.m_data.size()){
        for (usint i = 0; i < this->m_data.size(); i++){
          this->m_data[i] = rhs.m_data[i];
        }
      }
      else{
       this->m_data.resize(rhs.m_data.size());
        for (usint i = 0; i < this->m_data.size(); i++){
          this->m_data[i] = rhs.m_data[i];
        }
      }
      this->m_modulus = rhs.m_modulus;
      this->m_modulus_state = rhs.m_modulus_state;
    }

    return *this;
    DEBUG("mubintvec assignment copy CTOR length "<<this->m_data.size()<< " modulus "<<m_modulus.ToString());


  }


  //Assignment with initializer list of ubints
  // note, resizes the vector to the length of the initializer list
  template<class ubint_el_t>
  const mubintvec<ubint_el_t>& mubintvec<ubint_el_t>::operator=(std::initializer_list<ubint_el_t> rhs){
    bool dbg_flag = false;
    usint len = rhs.size();
    this->m_data.clear();

    for(usint i=0;i<len;i++){ // this loops over each entry
      if(i<len) {
	this->m_data.push_back( ubint_el_t(*(rhs.begin()+i)));
      } else {
	this->m_data.push_back(ubint_el_t::ZERO);
      }
    }
    if (this->m_modulus_state == INITIALIZED) {
      this->Mod(this->m_modulus);
    }
    return *this;
    DEBUG("mubintvec assignment copy CTOR ubint init list length "<<this->m_data.size());
  }

  //Assignment with initializer list of usints
  template<class ubint_el_t>
  const mubintvec<ubint_el_t>& mubintvec<ubint_el_t>::operator=(std::initializer_list<usint> rhs){
    bool dbg_flag = false;
    usint len = rhs.size();
    this->m_data.clear();
    for(usint i=0;i<len;i++){ // this loops over each entry
      if(i<len) {
	this->m_data.push_back( ubint_el_t(*(rhs.begin()+i)));
      } else {
	this->m_data.push_back(ubint_el_t::ZERO);
      }
    }
    if (this->m_modulus_state == INITIALIZED) {
      this->Mod(this->m_modulus);
    }
    return *this;
    DEBUG("mubintvec assignment copy CTOR usint init list length "<<this->m_data.size());
  }

  //Assignment with initializer list of sints, note, negative values cause 
  // an exception to throw
  //todo: add throw
  template<class ubint_el_t>
  const mubintvec<ubint_el_t>& mubintvec<ubint_el_t>::operator=(std::initializer_list<sint> rhs){
    bool dbg_flag = false;
    usint len = rhs.size();
    this->m_data.clear();
    for(usint i=0;i<len;i++){ // this loops over each entry
      if(i<len) {
	this->m_data.push_back( ubint_el_t(*(rhs.begin()+i)));
      } else {
	this->m_data.push_back(ubint_el_t::ZERO);
      }
    }
    if (this->m_modulus_state == INITIALIZED) {
      this->Mod(this->m_modulus);
    }
    return *this;
    DEBUG("mubintvec assignment copy CTOR sint init list length "<<this->m_data.size());
  }

  //Assignment with initializer list of strings
  template<class ubint_el_t>
  const mubintvec<ubint_el_t>& mubintvec<ubint_el_t>::operator=(std::initializer_list<std::string> rhs){
    bool dbg_flag = false;
    usint len = rhs.size();
    this->m_data.clear();
    for(usint i=0;i<len;i++){ // this loops over each entry
      if(i<len) {
	this->m_data.push_back( ubint_el_t(*(rhs.begin()+i)));
      } else {
	this->m_data.push_back(ubint_el_t::ZERO);
      }
    }
    if (this->m_modulus_state == INITIALIZED) {
      this->Mod(this->m_modulus);
    }
    return *this;
    DEBUG("mubintvec assignment copy CTOR string init list length "<<this->m_data.size());
  }

  // move copy allocator
  template<class ubint_el_t>
  const mubintvec<ubint_el_t>& mubintvec<ubint_el_t>::operator=(mubintvec &&rhs){
    bool dbg_flag = false;

    if(this!=&rhs){
      this->m_data.swap(rhs.m_data); //swap the two vector contents,
      if (rhs.m_data.size()>0)
	rhs.m_data.clear();
      this->m_modulus = rhs.m_modulus;
      this->m_modulus_state = rhs.m_modulus_state;
    }

    return *this;
    DEBUG("mubintvec move copy CTOR length "<<this->m_data.size()<< " modulus "<<m_modulus.ToString());
  }

  //desctructor
  template<class ubint_el_t>
  mubintvec<ubint_el_t>::~mubintvec(){
    //std::cout<<"destructor called for vector of size: "<<this->m_data.size()<<"  "<<std::endl;
    this->m_data.clear();
  }

  //ACCESSORS
  //stream <<
  template<class ubint_el_t_c>
  std::ostream& operator<<(std::ostream& os, const mubintvec<ubint_el_t_c> &ptr_obj){

    os<<std::endl;
    for(usint i=0;i<ptr_obj.m_data.size();i++){
      os<<ptr_obj.m_data[i] <<std::endl;
    }

    os<<"modulus: "<<ptr_obj.m_modulus;
    os <<std::endl;

    return os;
  }

  //modulus accessors
  template<class ubint_el_t>
  void mubintvec<ubint_el_t>::SetModulus(const usint& value){
    m_modulus= ubint_el_t(value);
    m_modulus_state = INITIALIZED;
  }
  
  template<class ubint_el_t>
  void mubintvec<ubint_el_t>::SetModulus(const ubint_el_t& value){
    m_modulus= value;
    m_modulus_state = INITIALIZED;
  }
  
  
  template<class ubint_el_t>
  void mubintvec<ubint_el_t>::SetModulus(const std::string& value){
    m_modulus= ubint_el_t(value);
    m_modulus_state = INITIALIZED;
  }

  
  template<class ubint_el_t>
  void mubintvec<ubint_el_t>::SetModulus(const mubintvec& value){
    m_modulus= ubint_el_t(value.GetModulus());
    m_modulus_state = INITIALIZED;
  }
  
  
  template<class ubint_el_t>
  const ubint_el_t& mubintvec<ubint_el_t>::GetModulus() const{
    if (m_modulus_state != INITIALIZED)
      throw std::logic_error("GetModulus() on uninitialized mubintvec");

    return(m_modulus);
  }


  /**Switches the integers in the vector to values corresponding to the new modulus
   *  Algorithm: Integer i, Old Modulus om, New Modulus nm, delta = abs(om-nm):
   *  Case 1: om < nm
   *  if i > i > om/2
   *  i' = i + delta
   *  Case 2: om > nm
   *  i > om/2
   *  i' = i-delta
   */	
  template<class ubint_el_t>
  void mubintvec<ubint_el_t>::SwitchModulus(const ubint_el_t& newModulus) {
	
    ubint_el_t oldModulus(this->m_modulus);
    ubint_el_t n;
    ubint_el_t oldModulusByTwo(oldModulus>>1);
    ubint_el_t diff ((oldModulus > newModulus) ? (oldModulus-newModulus) : (newModulus - oldModulus));
    for(usint i=0; i< this->GetLength(); i++) {
      n = this->GetValAtIndex(i);
      if(oldModulus < newModulus) {
	if(n > oldModulusByTwo) {
	  this->SetValAtIndex(i, n.ModAdd(diff, newModulus));
	} else {
	  this->SetValAtIndex(i, n.Mod(newModulus));
	}
      } else {
	if(n > oldModulusByTwo) {
	  this->SetValAtIndex(i, n.ModSub(diff, newModulus));
	} else {
	  this->SetValAtIndex(i, n.Mod(newModulus));
	}
      }
    }
    this->SetModulus(newModulus);
  }


  
  //Math functions
  // Mod
  template<class ubint_el_t>
  mubintvec<ubint_el_t> mubintvec<ubint_el_t>::Mod(const ubint_el_t& modulus) const{
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
  template<class ubint_el_t>
  const mubintvec<ubint_el_t>& mubintvec<ubint_el_t>::operator%=(const ubint_el_t& modulus) {

    *this = this->Mod(modulus);
    return *this;

  }

  //method to mod by two
  template<class ubint_el_t>
  mubintvec<ubint_el_t> mubintvec<ubint_el_t>::ModByTwo() const {

    mubintvec ans(this->GetLength(),this->GetModulus());
    ubint_el_t halfQ(this->GetModulus() >> 1);
    for (usint i = 0; i<ans.GetLength(); i++) {
      if (this->GetValAtIndex(i)>halfQ) {
	if (this->GetValAtIndex(i).Mod(ubint_el_t::TWO) == ubint_el_t::ONE)
	  ans.SetValAtIndex(i, ubint_el_t::ZERO);
	else
	  ans.SetValAtIndex(i, ubint_el_t::ONE);
      }
      else {
	if (this->GetValAtIndex(i).Mod(ubint_el_t::TWO) == ubint_el_t::ONE)
	  ans.SetValAtIndex(i, ubint_el_t::ONE);
	else
	  ans.SetValAtIndex(i, ubint_el_t::ZERO);
      }
      
    }
    return ans;
  }

  // method to add scalar to vector element at index i

  template<class ubint_el_t>
  mubintvec<ubint_el_t> mubintvec<ubint_el_t>::ModAddAtIndex(usint i, const ubint_el_t &b) const{
    if(i > this->GetLength()-1) {
      std::string errMsg = "mubintvec::ModAddAtIndex. Index is out of range. i = " + i;
      throw std::runtime_error(errMsg);
    }
    mubintvec ans(*this);
    ans.m_data[i] = ans.m_data[i].ModAdd(b, this->m_modulus);
    return ans;
  }

  // method to add scalar to vector
    template<class ubint_el_t>
  mubintvec<ubint_el_t> mubintvec<ubint_el_t>::ModAdd(const ubint_el_t &b) const{
    mubintvec ans(*this);
    for(usint i=0;i<this->m_data.size();i++){
      ans.m_data[i] = ans.m_data[i].ModAdd(b, ans.m_modulus);
    }
    return ans;
    }
    
    template<class ubint_el_t>
  mubintvec<ubint_el_t> mubintvec<ubint_el_t>::Add(const ubint_el_t &b) const{ //overload of ModAdd
    mubintvec ans(*this);
    ans = ans.ModAdd(b);
    return ans;
  }


  // +=  operator to add scalar to vector
  template<class ubint_el_t>
  const mubintvec<ubint_el_t>& mubintvec<ubint_el_t>::operator+=(const ubint_el_t& b) {

    *this = this->ModAdd(b);
    return *this;

  }


  // method to subtract scalar from vector
  template<class ubint_el_t>
  mubintvec<ubint_el_t> mubintvec<ubint_el_t>::ModSub(const ubint_el_t &b) const{
    mubintvec ans(*this);
    for(usint i=0;i<this->m_data.size();i++){
      ans.m_data[i] = ans.m_data[i].ModSub(b, ans.m_modulus);
    }
    return ans;
  }

  // method to subtract scalar from vector
  template<class ubint_el_t>
  mubintvec<ubint_el_t> mubintvec<ubint_el_t>::Sub(const ubint_el_t &b) const{ //overload of Modsub()
    mubintvec ans(*this);
    ans = ans.ModSub(b);
    return ans;
  }

  // -=  operator to subtract scalar from vector
  template<class ubint_el_t>
  const mubintvec<ubint_el_t>& mubintvec<ubint_el_t>::operator-=(const ubint_el_t& b) {

    *this = this->ModSub(b);
    return *this;

  }

  // method to multiply vector by scalar
  template<class ubint_el_t>
  mubintvec<ubint_el_t> mubintvec<ubint_el_t>::ModMul(const ubint_el_t &b) const{
    mubintvec ans(*this);
    for(usint i=0;i<this->m_data.size();i++){
      ans.m_data[i] = ans.m_data[i].ModMul(b, ans.m_modulus);
    }
    return ans;
  }

 // method to multiply vector by scalar
  template<class ubint_el_t>
  mubintvec<ubint_el_t> mubintvec<ubint_el_t>::Mul(const ubint_el_t &b) const{ //overload of ModMul()
    mubintvec ans(*this);
    ans = ans.ModMul(b);
    return ans;
  }



  // *=  operator to multiply  scalar from vector
  template<class ubint_el_t>
  const mubintvec<ubint_el_t>& mubintvec<ubint_el_t>::operator*=(const ubint_el_t& b) {

    *this = this->ModMul(b);
    return *this;

  }

template<class ubint_el_t>
  mubintvec<ubint_el_t> mubintvec<ubint_el_t>::ModExp(const ubint_el_t &b) const{
    mubintvec ans(*this);
    for(usint i=0;i<this->m_data.size();i++){
      ans.m_data[i] = ans.m_data[i].ModExp(b, ans.m_modulus);
    }
    return ans;
  }


  template<class ubint_el_t>
  mubintvec<ubint_el_t> mubintvec<ubint_el_t>::ModInverse() const{

    mubintvec ans(*this);
    //std::cout << ans << std::endl;
    for(usint i=0;i<this->m_data.size();i++){
      //std::cout << ans.m_data[i] << std::endl;
      //ans.m_data[i].PrintValueInDec();
      ans.m_data[i] = ans.m_data[i].ModInverse(this->m_modulus);
    }
    return ans;

}

    
 // method to exponentiate vector by scalar 
  template<class ubint_el_t>
  mubintvec<ubint_el_t> mubintvec<ubint_el_t>::Exp(const ubint_el_t &b) const{ //overload of ModExp()
    mubintvec ans(*this);
    ans = ans.ModExp(b);
    return ans;
  }

  // vector elementwise add
  template<class ubint_el_t>
  mubintvec<ubint_el_t> mubintvec<ubint_el_t>::ModAdd(const mubintvec &b) const{
    
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

  template<class ubint_el_t>
  mubintvec<ubint_el_t> mubintvec<ubint_el_t>::Add(const mubintvec &b) const{ //overload of ModAdd
    mubintvec ans(*this);
    ans = ans.ModAdd(b);
    return ans;
  }

  // vector elementwise subtract
  template<class ubint_el_t>
  mubintvec<ubint_el_t> mubintvec<ubint_el_t>::ModSub(const mubintvec &b) const{
    
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

  template<class ubint_el_t>
  mubintvec<ubint_el_t> mubintvec<ubint_el_t>::Sub(const mubintvec &b) const{ //overload of ModSub
    mubintvec ans(*this);
    ans = ans.ModSub(b);
    return ans;
  }


  // vector elementwise multiply
  template<class ubint_el_t>
  mubintvec<ubint_el_t> mubintvec<ubint_el_t>::ModMul(const mubintvec &b) const{
    
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



  template<class ubint_el_t>
  mubintvec<ubint_el_t> mubintvec<ubint_el_t>::Mul(const mubintvec &b) const{ //overload of ModMul
    mubintvec ans(*this);
    ans = ans.ModMul(b);
    return ans;
  }

  // assignment operators

  template<class ubint_el_t>
  const mubintvec<ubint_el_t>& mubintvec<ubint_el_t>::operator+=(const mubintvec &b) {
    if(this->m_modulus!=b.m_modulus){
      throw std::logic_error("mubintvec += vectors of different moduli");
    }else if(this->m_data.size()!=b.m_data.size()){
      throw std::logic_error("mubintvec += vectors of different lengths");
    }

    *this = *this + b;
    return *this;
  }

  template<class ubint_el_t>
  const mubintvec<ubint_el_t>& mubintvec<ubint_el_t>::operator-=(const mubintvec &b) {
    if(this->m_modulus!=b.m_modulus){
      throw std::logic_error("mubintvec -= vectors of different moduli");
    }else if(this->m_data.size()!=b.m_data.size()){
      throw std::logic_error("mubintvec -= vectors of different lengths");
    }
    *this = *this - b;
    return *this;
  }


  template<class ubint_el_t>
  const mubintvec<ubint_el_t>& mubintvec<ubint_el_t>::operator*=(const mubintvec &b) {
    if(this->m_modulus!=b.m_modulus){
      throw std::logic_error("mubintvec -= vectors of different moduli");
    }else if(this->m_data.size()!=b.m_data.size()){
      throw std::logic_error("mubintvec -= vectors of different lengths");
    }
    *this = *this * b;
    return *this;
  }


  //Gets the ind
  template<class ubint_el_t>
  mubintvec<ubint_el_t> mubintvec<ubint_el_t>::GetDigitAtIndexForBase(usint index, usint base) const{
    mubintvec ans(*this);
    for(usint i=0; i < this->m_data.size(); i++){
      ans.m_data[i] = ubint_el_t(ans.m_data[i].GetDigitAtIndexForBase(index,base));
    }

    return ans;
  }


  //new serialize and deserialise operations
  //todo: not tested just added to satisfy compilier
  //currently using the same map as bigBinaryVector, with modulus. 

  // JSON FACILITY - Serialize Operation
  template<class bin_el_t>
  bool mubintvec<bin_el_t>::Serialize(lbcrypto::Serialized* serObj, const std::string) const {

    if( !serObj->IsObject() )
      return false;

    lbcrypto::SerialItem bbvMap(rapidjson::kObjectType);
    bbvMap.AddMember("Modulus", this->GetModulus().ToString(), serObj->GetAllocator()); 

    usint pkVectorLength = this->m_data.size();
    if( pkVectorLength > 0 ) {
      std::string pkBufferString = this->m_data.at(0).Serialize();
      for (int i = 1; i < pkVectorLength; i++) {
	pkBufferString += "|";
	pkBufferString += this->m_data.at(i).Serialize();
      }
      bbvMap.AddMember("VectorValues", pkBufferString, serObj->GetAllocator());
    }
    serObj->AddMember("mubintvec", bbvMap, serObj->GetAllocator());
    return true;
  }

  // JSON FACILITY - SetIdFlag...
  // Note, untested.. completely!
  template<class ubint_el_t>
  bool mubintvec<ubint_el_t>::SetIdFlag(lbcrypto::Serialized* serObj, const std::string flag) const { 
    return true; 
  }

  // JSON FACILITY - Deserialize Operation
  template<class ubint_el_t>
  bool mubintvec<ubint_el_t>::Deserialize(const lbcrypto::Serialized& serObj) {

    lbcrypto::Serialized::ConstMemberIterator mIter = serObj.FindMember("mubintvec");
    if( mIter == serObj.MemberEnd() )
      return false;

    lbcrypto::SerialItem::ConstMemberIterator vIt;
    if( (vIt = mIter->value.FindMember("Modulus")) == mIter->value.MemberEnd() )
    return false;
    ubint_el_t bbiModulus(vIt->value.GetString());

    if( (vIt = mIter->value.FindMember("VectorValues")) == mIter->value.MemberEnd() )
      return false;

    this->SetModulus(bbiModulus);

    this->m_data.clear();

    ubint_el_t vectorElem;
    //usint ePos = 0;
    const char *vp = vIt->value.GetString();
    while( *vp != '\0' ) {
      vp = vectorElem.Deserialize(vp);
      //this->SetValAtIndex(ePos++, vectorElem);
      this->m_data.push_back(vectorElem);
      if( *vp == '|' )
	vp++;
    }

    return true;
  }


} // namespace lbcrypto ends
 
