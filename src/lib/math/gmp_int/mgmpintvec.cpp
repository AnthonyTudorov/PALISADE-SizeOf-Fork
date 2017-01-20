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
#include "mgmpintvec.h"

#include "time.h"
#include <chrono>

#include "../../utils/debug.h"

namespace NTL {

  // constructor specifying the myvec as a vector of strings
  template<class myT>
  myVecP<myT>::myVecP(std::vector<std::string> &s){
    usint len = s.size();
    this->SetLength(len);
    for (usint i = 0; i < len; i++){
      (*this)[i] = myT(s[i]);
    }
    this->m_modulus_state = UNINITIALIZED;
	
  }

  //Assignment with initializer list of myZZ
  // note, resizes the vector to the length of the initializer list
  template<class myT>
  const myVecP<myT>& myVecP<myT>::operator=(std::initializer_list<myT> rhs){
    bool dbg_flag = false;
    DEBUG("in op=initializerlist <myT>");
    usint len = rhs.size();
    this->SetLength(len);
    for(usint i=0;i<len;i++){ // this loops over each entry
      (*this)[i] =  myT(*(rhs.begin()+i));
    }
    if (this->m_modulus_state == INITIALIZED) {
      this->Mod(this->m_modulus);
    }
    return *this;
    DEBUG("mubintvec assignment copy CTOR ubint init list length "<<this->m_data.size());
  }

  //Assignment with initializer list of usints
  template<class myT>
  const myVecP<myT>& myVecP<myT>::operator=(std::initializer_list<usint> rhs){
    bool dbg_flag = false;
    DEBUG("in op=initializerlist <myT>");
    usint len = rhs.size();
    this->SetLength(len);
    for(usint i=0;i<len;i++){ // this loops over each entry
      (*this)[i] =  myT(*(rhs.begin()+i));
    }
    if (this->m_modulus_state == INITIALIZED) {
      this->Mod(this->m_modulus);
    }
    return *this;
    DEBUG("mubintvec assignment copy CTOR usint init list length "<<this->m_data.size());
  }


  //Assignment with initializer list of strings
  template<class myT>
  const myVec<myT>& myVec<myT>::operator=(std::initializer_list<std::string> rhs){
    bool dbg_flag = false;
    DEBUG("in op=initializerlist <string>");
    usint len = rhs.size();
    this->SetLength(len);
    for(usint i=0;i<len;i++){ // this loops over each entry
      (*this)[i] =  myT(*(rhs.begin()+i));
    }
    if (this->m_modulus_state == INITIALIZED) {
      this->Mod(this->m_modulus);
    }
    return *this;
    DEBUG("mubintvec assignment copy CTOR string init list length "<<this->m_data.size());
  }

  //Assignment with initializer list of const char *
  //not sure why this isn't taken care of by string above
  template<class myT>
  const myVecP<myT>& myVecP<myT>::operator=(std::initializer_list<const char *> rhs){
    bool dbg_flag = false;
    DEBUG("in op=initializerlist const char*");
    usint len = rhs.size();
    this->SetLength(len);
    for(usint i=0;i<len;i++){ // this loops over each entry
      (*this)[i] =  myT(*(rhs.begin()+i));
    } 
    if (this->m_modulus_state == INITIALIZED) {
      this->Mod(this->m_modulus);
    }
    return *this;
  }
//&&&***
#if 0
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
#endif  

  template<class myT>
  const myVecP<myT>& myVecP<myT>::operator=(const myT &rhs){
    bool dbg_flag = false;
    DEBUG("in op=const myT&");
    this->SetLength(1);
    (*this)[0] = rhs;
    this->SetModulus(rhs.GetModulus());
    return *this;
  }

  template<class myT>
  const myVecP<myT>& myVecP<myT>::operator=(myT &rhs){
    bool dbg_flag = false;
    DEBUG("in op=myT&");
    this->SetLength(1);
    (*this)[0] =rhs;
    this->SetModulus(rhs.GetModulus()); 
       return *this;
  }

  template<class myT>
  const myVecP<myT>& myVecP<myT>::operator=(unsigned int &rhs){
    bool dbg_flag = false;
    DEBUG("in op=usint&");
    this->SetLength(1);
    (*this)[0] =rhs;
    this->SetModulus(rhs.GetModulus());
        return *this;
  }

  template<class myT>
  const myVecP<myT>& myVecP<myT>::operator=(unsigned int rhs){
    bool dbg_flag = false;
    DEBUG("in op=usint");
    this->SetLength(1);
    (*this)[0] =rhs;
        this->SetModulus(rhs.GetModulus());
    return *this;
  }

  //desctructor
  template<class myT>
  myVecP<myT>::~myVecP(){
    //std::cout<<"destructor called for vector of size: "<<this->m_data.size()<<"  "<<std::endl;
    NTL_NAMESPACE::clear(this->m_modulus);
  }

  template<class myT>
  void myVec<myT>::clear(myVec<myT>& x){
    //sets all elements to zero, but does not change length
    bool dbg_flag = false;
    DEBUG("in clear myVec");
    //using NTL_NAMESPACE::clear;
    long n = x.length();
    long i;
    for (i = 0; i < n; i++){
      NTL_NAMESPACE::clear(x[i]);  
    }
    NTL_NAMESPACE::clear(this->m_modulus);
  }

#if 0
//not enabled yet

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
  #endif

/// ARITHMETIC FUNCTIONS
  
  //Math functions
  // modulus
  

  template<class myT>
  myVecP<myT> myVecP<myT>::operator%( const myT& b) const
  {
    unsigned int n = this->length();
    myVecP<myT> res(n);
    for (unsigned int i = 0; i < n; i++){
      res[i] = (*this)[i]%b;
    }
    return(res);
  }

  
  template<class ubint_el_t>
  mubintvec<ubint_el_t> mubintvec<ubint_el_t>::Mod(const ubint_el_t& modulus) const{

    // previous version
    //mubintvec ans(*this);
    //for(usint i=0;i<this->m_data.size();i++){
    //  ans.m_data[i] = ans.m_data[i].Mod(modulus);
    //}
    //ans.m_modulus = modulus;
    //ans. m_modulus_state = INITIALIZED;
    //return ans;

	if (modulus == ubint_el_t::TWO)
		return this->ModByTwo();
	else
	{

		mubintvec ans(*this);
		ubint_el_t halfQ(this->GetModulus() >> 1);
		for (usint i = 0; i<this->m_data.size(); i++) {
			ans.m_data[i] = ans.m_data[i].Mod(modulus);
			if (this->GetValAtIndex(i)>halfQ) {
				ans.m_data[i] = ans.m_data[i].ModSub(this->GetModulus(), modulus);
				//ans.SetValAtIndex(i, this->GetValAtIndex(i).ModSub(this->GetModulus(), modulus));
			}
			else {
				ans.m_data[i] = ans.m_data[i].Mod(modulus);
			}
		}
		ans.m_modulus = modulus;
		ans.m_modulus_state = INITIALIZED;
		return ans;

	}

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

//arithmetic. 

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
#ifdef NO_BARRETT //non barrett way
    mubintvec ans(*this);
    for(usint i=0;i<this->m_data.size();i++){
      ans.m_data[i] = ans.m_data[i].ModMul(b, ans.m_modulus);
    }
    return ans;
#else

    mubintvec ans(*this);

    //Precompute the Barrett mu parameter
    ubint_el_t temp(ubint_el_t::ONE);

    temp<<=2*this->GetModulus().GetMSB()+3;

    ubint_el_t mu = temp.DividedBy(m_modulus);

    //Precompute the Barrett mu values
    /*ubint temp;
      uschar gamma;
      uschar modulusLength = this->GetModulus().GetMSB() ;
      ubint mu_arr[BARRETT_LEVELS+1];
      for(usint i=0;i<BARRETT_LEVELS+1;i++) {
      temp = ubint::ONE;
      gamma = modulusLength*i/BARRETT_LEVELS;
      temp<<=modulusLength+gamma+3;
      mu_arr[i] = temp.DividedBy(this->GetModulus());
      }*/

    for(usint i=0;i<this->m_data.size();i++){
      //std::cout<< "before data: "<< ans.m_data[i]<< std::endl;
      ans.m_data[i] = ans.m_data[i].ModBarrettMul(b,this->m_modulus,mu);
      //std::cout<< "after data: "<< ans.m_data[i]<< std::endl;
    }

    return ans;


#endif
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
#ifdef NO_BARRETT
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

#else // bartett way

    if((this->m_data.size()!=b.m_data.size()) || this->m_modulus!=b.m_modulus ){
      throw std::logic_error("ModMul called on mubintvecs with different parameters.");
    }
    
    mubintvec ans(*this);
    
    //Precompute the Barrett mu parameter
    ubint_el_t temp(ubint_el_t::ONE);
    temp<<=2*this->GetModulus().GetMSB()+3;
    ubint_el_t mu = temp.Div(this->GetModulus());
    
    //Precompute the Barrett mu values
    /*BigBinaryInteger temp;
      uschar gamma;
      uschar modulusLength = this->GetModulus().GetMSB() ;
      BigBinaryInteger mu_arr[BARRETT_LEVELS+1];
      for(usint i=0;i<BARRETT_LEVELS+1;i++) {
      temp = BigBinaryInteger::ONE;
      gamma = modulusLength*i/BARRETT_LEVELS;
      temp<<=modulusLength+gamma+3;
      mu_arr[i] = temp.DividedBy(this->GetModulus());
      }*/
    
    for(usint i=0;i<ans.m_data.size();i++){
      //ans.m_data[i] = ans.m_data[i].ModMul(b.m_data[i],this->m_modulus);
      ans.m_data[i] = ans.m_data[i].ModBarrettMul(b.m_data[i],this->m_modulus,mu);
    }
    return ans;

#endif
  }
  

  template<class ubint_el_t>
  mubintvec<ubint_el_t> mubintvec<ubint_el_t>::Mul(const mubintvec &b) const{ //overload of ModMul
    mubintvec ans(*this);
    ans = ans.ModMul(b);
    return ans;
  }

  template<class ubint_el_t>
  mubintvec<ubint_el_t> mubintvec<ubint_el_t>::MultiplyAndRound(const ubint_el_t &p, const ubint_el_t &q) const {

	  mubintvec ans(*this);
	  ubint_el_t halfQ(this->m_modulus >> 1);
	  for (usint i = 0; i<this->m_data.size(); i++) {
		  if (ans.m_data[i] > halfQ) {
			  ubint_el_t temp = this->m_modulus - ans.m_data[i];
			  ans.m_data[i] = this->m_modulus - temp.MultiplyAndRound(p, q);
		  }
		  else
			  ans.m_data[i] = ans.m_data[i].MultiplyAndRound(p, q).Mod(this->m_modulus);
	  }
	  return ans;
  }

  template<class ubint_el_t>
  mubintvec<ubint_el_t> mubintvec<ubint_el_t>::DivideAndRound(const ubint_el_t &q) const {
	  mubintvec ans(*this);
	  for (usint i = 0; i<this->m_data.size(); i++) {
		  ans.m_data[i] = ans.m_data[i].DivideAndRound(q);
	  }
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
#if 0
	//this has not  been touched
  //new serialize and deserialise operations
  //todo: not tested just added to satisfy compilier
  //currently using the same map as bigBinaryVector, with modulus. 

  // JSON FACILITY - Serialize Operation
  template<class bin_el_t>
  bool mubintvec<bin_el_t>::Serialize(lbcrypto::Serialized* serObj) const {

    if( !serObj->IsObject() )
      return false;

    lbcrypto::SerialItem bbvMap(rapidjson::kObjectType);
    bbvMap.AddMember("Modulus", this->GetModulus().ToString(), serObj->GetAllocator()); 

    size_t pkVectorLength = this->m_data.size();
    if( pkVectorLength > 0 ) {
      std::string pkBufferString = this->m_data.at(0).Serialize();
      for (size_t i = 1; i < pkVectorLength; i++) {
	pkBufferString += "|";
	pkBufferString += this->m_data.at(i).Serialize();
      }
      bbvMap.AddMember("VectorValues", pkBufferString, serObj->GetAllocator());
    }
    serObj->AddMember("mubintvec", bbvMap, serObj->GetAllocator());
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
#endif

} // namespace NTL ends
 
