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

  //define the static vriables
  template<class myT>
  myZZ myVecP<myT>::m_OTM = 0;

  template<class myT>
  typename myVecP<myT>::OTMState myVecP<myT>::m_OTM_state = GARBAGE;

  // constructors without moduli

  //%%%%


  //constructors with moduli
  //ctor myZZ moduli
  template<class myT>
  myVecP<myT>::myVecP(unsigned int n, myZZ const &q): Vec<myT>(INIT_SIZE,n)
  {
    this->SetModulus(q);
  }
  
  template<class myT>
  myVecP<myT>::myVecP(INIT_SIZE_TYPE, long n, const myZZ &q): Vec<myT>(INIT_SIZE,n)
  {
    this->SetModulus(q);
  }
  
  template<class myT>
  myVecP<myT>::myVecP(INIT_SIZE_TYPE, long n, const myT& a, const myZZ &q): Vec<myT>(INIT_SIZE,n)
  {
    for (auto i = 0; i < n; i++){
      (*this)[i] = a;
    }
    this->SetModulus(q);
  }
  
  //copy with myZZ moduli
  template<class myT>
  myVecP<myT>::myVecP(NTL::Vec<myT> &a, myZZ &q): Vec<myT>(a)
  {
    this->SetModulus(q);
    for (auto i = 0; i < this->length(); i++){
      (*this)[i] %= q;
    }
  }
  template<class myT>
  myVecP<myT>::myVecP(const NTL::Vec<myT> &a, myZZ &q): Vec<myT>(a)
  {
    this->SetModulus(q);
    for (auto i = 0; i < this->length(); i++){
      (*this)[i] %= q;
    }
  }

  template<class myT>
  myVecP<myT>::myVecP(NTL::Vec<ZZ> &a, myZZ &q): Vec<ZZ>(a)
  {
    this->SetModulus(q);
    for (auto i = 0; i < this->length(); i++){
      (*this)[i] %= q;
    }
  }

  template<class myT>
  myVecP<myT>::myVecP(const NTL::Vec<ZZ> &a, myZZ &q): Vec<ZZ>(a)
  {
    this->SetModulus(q);
    for (auto i = 0; i < this->length(); i++){
      (*this)[i] %= q;
    }
  }

  template<class myT>
  myVecP<myT>::myVecP(NTL::Vec<ZZ_p> &a, myZZ &q): Vec<ZZ_p>(a)
  {
    this->SetModulus(q);
    for (auto i = 0; i < this->length(); i++){
      (*this)[i] %= q;
    }
  }

  template<class myT>
  myVecP<myT>::myVecP(const NTL::Vec<ZZ_p> &a, myZZ &q): Vec<ZZ_p>(a)
  {
    this->SetModulus(q);
    for (auto i = 0; i < this->length(); i++){
      (*this)[i] %= q;
    }
  }
  
  //ctor with char * moduli
  template<class myT>
  myVecP<myT>::myVecP(usint n, const char *sq):Vec<myT>(INIT_SIZE, n)
  { 
    this->SetModulus(myZZ(sq)); 
  };

  template<class myT>
  myVecP<myT>::myVecP(INIT_SIZE_TYPE, long n, const char *sq):Vec<myT>(INIT_SIZE, n) 
  { 
    this->SetModulus(myZZ(sq)); 
  };

  template<class myT>
  myVecP<myT>::myVecP(INIT_SIZE_TYPE, long n, const myT& a, const char *sq):Vec<myT>(INIT_SIZE, n) 
  { 
    this->SetModulus(myZZ(sq)); 
    for (auto i = 0; i < n; i++){
      (*this)[i] = a%this->m_getOTM();
    }
  };
  
  //copy with char * moduli
  template<class myT>
  myVecP<myT>::myVecP(NTL::Vec<myT> &a, const char *sq):Vec<myT>(a) 
  {
    this->SetModulus(myZZ(sq)); 
  };

  template<class myT>
  myVecP<myT>::myVecP(const NTL::Vec<myT> &a, const char *sq):Vec<myT>(a) 
  { 
    this->SetModulus(myZZ(sq)); 
  };

  template<class myT>
  myVecP<myT>::myVecP(NTL::Vec<ZZ> &a, const char *sq):Vec<ZZ>(a) 
  { 
    this->SetModulus(myZZ(sq)); 
  };

  template<class myT>
  myVecP<myT>::myVecP(const NTL::Vec<ZZ> &a, const char *sq):Vec<ZZ>(a) 
  { 
    this->SetModulus(myZZ(sq)); 
  };

  template<class myT>
  myVecP<myT>::myVecP(NTL::Vec<ZZ_p> &a, const char *sq):Vec<ZZ_p>(a) 
  { 
    this->SetModulus(myZZ(sq)); 
  };

  template<class myT>
  myVecP<myT>::myVecP(const NTL::Vec<ZZ_p> &a, const char *sq):Vec<ZZ_p>(a) 
  { 
    this->SetModulus(myZZ(sq)); 
  };

    //ctor with usint moduli
  template<class myT>
  myVecP<myT>::myVecP(usint n, usint q):Vec<myT>(INIT_SIZE, n) 
  { 
    this->SetModulus(q); 
  };

  template<class myT>
  myVecP<myT>::myVecP(INIT_SIZE_TYPE, long n, usint q):Vec<myT>(INIT_SIZE, n) 
  { 
    this->SetModulus(q); 
  };

  template<class myT>
  myVecP<myT>::myVecP(INIT_SIZE_TYPE, long n, const myT& a, usint q):Vec<myT>(INIT_SIZE, n) 
  { 
    this->SetModulus(q); 
    for (auto i = 0; i < n; i++){
      (*this)[i] = a%q;
    }
  };

  //copy with unsigned int moduli
  template<class myT>
  myVecP<myT>::myVecP(NTL::Vec<myT> &a, const usint q):Vec<myT>(a) 
  { 
    this->SetModulus(q); 
    for (auto i = 0; i < this->length(); i++){
      (*this)[i] %=q;
    }
  };

  template<class myT>
  myVecP<myT>::myVecP(const NTL::Vec<myT> &a, const usint q):Vec<myT>(a) 
  { 
    this->SetModulus(q); 
    for (auto i = 0; i < this->length(); i++){
      (*this)[i] %=q;
    }
  };

  template<class myT>
  myVecP<myT>::myVecP(NTL::Vec<ZZ> &a, const usint q):Vec<ZZ>(a) 
  { 
    this->SetModulus(q); 
    for (auto i = 0; i < this->length(); i++){
      (*this)[i] %=q;
    }
  };

  template<class myT>
  myVecP<myT>::myVecP(const NTL::Vec<ZZ> &a, const usint q):Vec<ZZ>(a) 
  { 
    this->SetModulus(q); 
    for (auto i = 0; i < this->length(); i++){
      (*this)[i] %=q;
    }
  };

  template<class myT>
  myVecP<myT>::myVecP(NTL::Vec<ZZ_p> &a, const usint q):Vec<ZZ_p>(a) 
  { 
    this->SetModulus(q); 
    for (auto i = 0; i < this->length(); i++){
      (*this)[i] %=q;
    }
  };

  template<class myT>
  myVecP<myT>::myVecP(const NTL::Vec<ZZ_p> &a, const usint q):Vec<ZZ_p>(a) 
  { 
    this->SetModulus(q); 
    for (auto i = 0; i < this->length(); i++){
      (*this)[i] %=q;
    }
  };
  //%%%%


  // constructor specifying the myvec as a vector of strings
  template<class myT>
  myVecP<myT>::myVecP(std::vector<std::string> &s){
    usint len = s.size();
    this->SetLength(len);
    if (this->m_isOTMSet()) {    
      for (usint i = 0; i < len; i++){
	(*this)[i] = myT(s[i])%m_getOTM();
      }
      
    }else{
      std::string errMsg = "myVecP::myVecP(list of string) unset modulus";
      throw std::runtime_error(errMsg);
    }
    //m_modulus_state = GARBAGE; TODO figure out how to initialize?
    //should default to 0 == GARBAGE 
  }
  //constructors with moduli
  
  //Assignment with initializer list of myZZ
  // note, resizes the vector to the length of the initializer list
  template<class myT>
  const myVecP<myT>& myVecP<myT>::operator=(std::initializer_list<myT> rhs){
    bool dbg_flag = false;
    DEBUG("in op=initializerlist <myT>");
    usint len = rhs.size();
    this->SetLength(len);
    if (this->m_isOTMSet()) {
      for(usint i=0;i<len;i++){ // this loops over each entry
	(*this)[i] =  myT(*(rhs.begin()+i))%m_getOTM();
      }
    }else{
      std::string errMsg = "myVecP::operator=(list of myZZp) unset modulus";
      throw std::runtime_error(errMsg);
    }
    return *this;
    DEBUG("mubintvec assignment copy CTOR ubint init list length "<<this->length());
  }

  //Assignment with initializer list of usints
  template<class myT>
  const myVecP<myT>& myVecP<myT>::operator=(std::initializer_list<usint> rhs){
    bool dbg_flag = false;
    DEBUG("in op=initializerlist <myT>");
    usint len = rhs.size();
    this->SetLength(len);
    if (this->m_isOTMSet()) {
      for(usint i=0;i<len;i++){ // this loops over each entry
	(*this)[i] =  myZZ(*(rhs.begin()+i))%m_getOTM();
      }
    }else{
      std::string errMsg = "myVecP::operator=(list of usint) modulus";
      throw std::runtime_error(errMsg);
    }
      
    return *this;
    DEBUG("mubintvec assignment copy CTOR usint init list length "<<this->length());
  }


  //Assignment with initializer list of strings
  template<class myT>
  const myVecP<myT>& myVecP<myT>::operator=(std::initializer_list<std::string> rhs){
    bool dbg_flag = false;
    DEBUG("in op=initializerlist <string>");
    usint len = rhs.size();
    this->SetLength(len);
    if (this->m_isOTMSet()) {    
      for(usint i=0;i<len;i++){ // this loops over each entry
	(*this)[i] =  myT(*(rhs.begin()+i))%m_getOTM();
      }
    }else{
      std::string errMsg = "myVecP::operator=(lists string) unset modulus";
      throw std::runtime_error(errMsg);
    }

    return *this;
    DEBUG("mubintvec assignment copy CTOR string init list length "<<this->m_data.size());
  }

  //Assignment with initializer list of const char *
  //not sure why this isn't taken care of by string above
  template<class myT>
  const myVecP<myT>& myVecP<myT>::operator=(std::initializer_list<const char *> rhs){
    bool dbg_flag = true;
    DEBUG("in op=initializerlist const char*");
    usint len = rhs.size();
    this->SetLength(len);
    if (this->m_isOTMSet()) {
      for(usint i=0;i<len;i++){ // this loops over each entry
	(*this)[i] =  (myT(*(rhs.begin()+i)))%this->m_getOTM();
      } 
    }else{
      std::string errMsg = "myVecP::operator=(list char*) unset modulus";
      throw std::runtime_error(errMsg);
    }
    return *this;
  }
//&&&***
#if 0
  // move copy allocator
  template<class ubint_el_t>
  const myVecP<ubint_el_t>& myVecP<ubint_el_t>::operator=(myVecP &&rhs){
    bool dbg_flag = true;

    if(this!=&rhs){
      this->m_data.swap(rhs.m_data); //swap the two vector contents,
      if (rhs.m_data.size()>0)
	rhs.m_data.clear();
      this->SetModulus(rhs.GetModulus);
    }

    return *this;
    DEBUG("myVecP move copy CTOR length "<<this->m_data.size()<< " modulus "<<m_modulus.ToString());
  }
#endif  

  template<class myT>
  const myVecP<myT>& myVecP<myT>::operator=(const myT &rhs){
    bool dbg_flag = true;
    DEBUG("in op=const myT&");
    this->SetLength(1);
    this->SetModulus(rhs.GetModulus());
    (*this)[0] = rhs;

    return *this;
  }

  template<class myT>
  const myVecP<myT>& myVecP<myT>::operator=(myT &rhs){
    bool dbg_flag = true;
    DEBUG("in op=myT&");
    this->SetLength(1);
    (*this)[0] =rhs;
    this->SetModulus(rhs.GetModulus()); 
       return *this;
  }

  template<class myT>
  const myVecP<myT>& myVecP<myT>::operator=(unsigned int &rhs){
    bool dbg_flag = true;
    DEBUG("in op=usint&");
    this->SetLength(1);
    (*this)[0] =(unsigned int &)rhs;
    //this->m_modulus_state = GARBAGE; //TODO should be set to 0
    return *this;
  }

  template<class myT>
  const myVecP<myT>& myVecP<myT>::operator=(unsigned int rhs){
    bool dbg_flag = true;
    DEBUG("in op=usint");
    this->SetLength(1);
    (*this)[0] = (unsigned int)rhs;
    //this->m_modulus_state = GARBAGE; //TODO should be set to 0
    return *this;
  }

  //desctructor
  template<class myT>
  myVecP<myT>::~myVecP(){
    //std::cout<<"destructor called for vector of size: "<<this->m_data.size()<<"  "<<std::endl;
    //NTL_NAMESPACE::clear(this->m_OTM); don't clear as this is global?
  }

  template<class myT>
  void myVecP<myT>::clear(myVecP<myT>& x){
    //sets all elements to zero, but does not change length
    bool dbg_flag = true;
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
  std::ostream& operator<<(std::ostream& os, const myVecP<ubint_el_t_c> &ptr_obj){

    os<<std::endl;
    for(usint i=0;i<ptr_obj.m_data.size();i++){
      os<<ptr_obj.m_data[i] <<std::endl;
    }

    os<<"modulus: "<<ptr_obj.m_OTM;
    os <<std::endl;

    return os;
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
  void myVecP<ubint_el_t>::SwitchModulus(const ubint_el_t& newModulus) {
	
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
  myVecP<myT> myVecP<myT>::operator%( const myZZ& b) const
  {
    unsigned int n = this->length();
    myVecP<myT> res(n);
    for (unsigned int i = 0; i < n; i++){
      res[i] = (*this)[i]%b;
    }
    return(res);
  }

  
  template<class myT>
  myVecP<myT> myVecP<myT>::Mod(const myZZ& modulus) const{

    // previous version
    //myVecP ans(*this);
    //for(usint i=0;i<this->m_data.size();i++){
    //  ans.m_data[i] = ans.m_data[i].Mod(modulus);
    //}
    //ans.m_modulus = modulus;
    //ans. m_modulus_state = INITIALIZED;
    //return ans;

	if (modulus == myZZ::TWO)
		return this->ModByTwo();
	else
	{

		myVecP ans(*this);
		myT halfQ(this->GetModulus() >> 1);
		for (usint i = 0; i<this->length(); i++) {
			ans[i] = ans[i].Mod(modulus);
			if (this->GetValAtIndex(i)>halfQ) {
			  //TODO note: this may be mixed modulus math
			  ans[i] = ans[i].myZZ::ModSub(myZZ(this->GetModulus()), modulus);
				//ans.SetValAtIndex(i, this->GetValAtIndex(i).ModSub(this->GetModulus(), modulus));
			}
			else {
				ans[i] = ans[i].Mod(modulus);
			}
		}
		ans.SetModulus(modulus);
		return ans;

	}

  }

  // %=
  // method to vector with scalar
  // template<class myT> //was inlined in .h
  // const myVecP<myT>& myVecP<myT>::operator%=(const myZZ& modulus) {

  //   *this = this->Mod(modulus);
  //   return *this;

  // }

  //method to mod by two
  template<class myT>
  myVecP<myT> myVecP<myT>::ModByTwo() const {

    myVecP ans(this->GetLength(),this->GetModulus());
    myT halfQ(this->GetModulus() >> 1);
    for (usint i = 0; i<ans.GetLength(); i++) {
      if (this->GetValAtIndex(i)>halfQ) {
	if (this->GetValAtIndex(i).Mod(myZZ::TWO) == myZZ::ONE)
	  ans.SetValAtIndex(i, myZZ::ZERO);
	else
	  ans.SetValAtIndex(i, myZZ::ONE);
      }
      else {
	if (this->GetValAtIndex(i).Mod(myZZ::TWO) == myZZ::ONE)
	  ans.SetValAtIndex(i, myZZ::ONE);
	else
	  ans.SetValAtIndex(i, myZZ::ZERO);
      }
      
    }
    return ans;
  }

//arithmetic. 

  // method to add scalar to vector element at index i
#if 0
  template<class myT>
  myVecP<myT> myVecP<myT>::ModAddAtIndex(usint i, const myT &b) const{
    if(i > this->GetLength()-1) {
      std::string errMsg = "myVecP::ModAddAtIndex. Index is out of range. i = " + i;
      throw std::runtime_error(errMsg);
    }
    myVecP ans(*this);
    ans[i] = ans[i].ModAdd(b, this->m_getOTM());
    return ans;
  }
#endif

#if 0

  // method to add scalar to vector
    template<class myT>
  myVecP<myT> myVecP<myT>::ModAdd(const myT &b) const{
    myVecP ans(*this);
    for(usint i=0;i<this->length();i++){
      ans[i] = ans[i].ModAdd(b, ans.m_modulus);
    }
    return ans;
    }

    template<class myT>
  myVecP<myT> myVecP<myT>::Add(const myT &b) const{ //overload of ModAdd
    myVecP ans(*this);
    ans = ans.ModAdd(b);
    return ans;
  }



  // +=  operator to add scalar to vector
  template<class myT>
  const myVecP<myT>& myVecP<myT>::operator+=(const myT& b) {

    *this = this->ModAdd(b);
    return *this;

  }


  // method to subtract scalar from vector
  template<class myT>
  myVecP<myT> myVecP<myT>::ModSub(const myT &b) const{
    myVecP ans(*this);
    for(usint i=0;i<this->m_data.size();i++){
      ans.m_data[i] = ans.m_data[i].ModSub(b, ans.m_modulus);
    }
    return ans;
  }

  // method to subtract scalar from vector
  template<class myT>
  myVecP<myT> myVecP<myT>::Sub(const myT &b) const{ //overload of Modsub()
    myVecP ans(*this);
    ans = ans.ModSub(b);
    return ans;
  }

  // -=  operator to subtract scalar from vector
  template<class myT>
  const myVecP<myT>& myVecP<myT>::operator-=(const myT& b) {

    *this = this->ModSub(b);
    return *this;

  }

  // method to multiply vector by scalar
  template<class myT>
  myVecP<myT> myVecP<myT>::ModMul(const myT &b) const{
#ifdef NO_BARRETT //non barrett way
    myVecP ans(*this);
    for(usint i=0;i<this->m_data.size();i++){
      ans.m_data[i] = ans.m_data[i].ModMul(b, ans.m_modulus);
    }
    return ans;
#else

    myVecP ans(*this);

    //Precompute the Barrett mu parameter
    myT temp(myZZ::ONE);

    temp<<=2*this->GetModulus().GetMSB()+3;

    myT mu = temp.DividedBy(m_modulus);

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

  template<class myT>
  myVecP<myT> myVecP<myT>::Mul(const myT &b) const{ //overload of ModMul()
    myVecP ans(*this);
    ans = ans.ModMul(b);
    return ans;
  }



  // *=  operator to multiply  scalar from vector
  template<class myT>
  const myVecP<myT>& myVecP<myT>::operator*=(const myT& b) {

    *this = this->ModMul(b);
    return *this;

  }

template<class myT>
  myVecP<myT> myVecP<myT>::ModExp(const myT &b) const{
    myVecP ans(*this);
    for(usint i=0;i<this->m_data.size();i++){
      ans.m_data[i] = ans.m_data[i].ModExp(b, ans.m_modulus);
    }
    return ans;
  }


  template<class myT>
  myVecP<myT> myVecP<myT>::ModInverse() const{

    myVecP ans(*this);
    //std::cout << ans << std::endl;
    for(usint i=0;i<this->m_data.size();i++){
      //std::cout << ans.m_data[i] << std::endl;
      //ans.m_data[i].PrintValueInDec();
      ans.m_data[i] = ans.m_data[i].ModInverse(this->m_modulus);
    }
    return ans;

}

    
 // method to exponentiate vector by scalar 
  template<class myT>
  myVecP<myT> myVecP<myT>::Exp(const myT &b) const{ //overload of ModExp()
    myVecP ans(*this);
    ans = ans.ModExp(b);
    return ans;
  }

  // vector elementwise add
  template<class myT>
  myVecP<myT> myVecP<myT>::ModAdd(const myVecP &b) const{
    
    myVecP ans(*this);
    if(this->m_modulus!=b.m_modulus){
      throw std::logic_error("myVecP adding vectors of different moduli");
    } else if(this->m_data.size()!=b.m_data.size()){
      throw std::logic_error("myVecP adding vectors of different lengths");
    } else {
      for(usint i=0;i<ans.m_data.size();i++){
	ans.m_data[i] = ans.m_data[i].ModAdd(b.m_data[i], ans.m_modulus);
      }
      return ans;
    }
  }

  template<class myT>
  myVecP<myT> myVecP<myT>::Add(const myVecP &b) const{ //overload of ModAdd
    myVecP ans(*this);
    ans = ans.ModAdd(b);
    return ans;
  }

  

  // vector elementwise subtract
  template<class myT>
  myVecP<myT> myVecP<myT>::ModSub(const myVecP &b) const{
    
    myVecP ans(*this);
    if(this->m_modulus!=b.m_modulus){
      throw std::logic_error("myVecP subtracting vectors of different moduli");
    } else if(this->m_data.size()!=b.m_data.size()){
      throw std::logic_error("myVecP subtracting vectors of different lengths");
    } else {

      for(usint i=0;i<ans.m_data.size();i++){
	ans.m_data[i] = ans.m_data[i].ModSub(b.m_data[i],ans.m_modulus);
      }
      return ans;
    }
  }

  template<class myT>
  myVecP<myT> myVecP<myT>::Sub(const myVecP &b) const{ //overload of ModSub
    myVecP ans(*this);
    ans = ans.ModSub(b);
    return ans;
  }


  // vector elementwise multiply
  template<class myT>
  myVecP<myT> myVecP<myT>::ModMul(const myVecP &b) const{
#ifdef NO_BARRETT
    myVecP ans(*this);
    if(this->m_modulus!=b.m_modulus){
      throw std::logic_error("myVecP multiplying vectors of different moduli");
    }else if(this->m_data.size()!=b.m_data.size()){
      throw std::logic_error("myVecP multiplying vectors of different lengths");
    } else {
      for(usint i=0;i<ans.m_data.size();i++){
        ans.m_data[i] = ans.m_data[i].ModMul(b.m_data[i],ans.m_modulus);
      }
      return ans;
    }

#else // bartett way

    if((this->m_data.size()!=b.m_data.size()) || this->m_modulus!=b.m_modulus ){
      throw std::logic_error("ModMul called on myVecPs with different parameters.");
    }
    
    myVecP ans(*this);
    
    //Precompute the Barrett mu parameter
    myT temp(myZZ::ONE);
    temp<<=2*this->GetModulus().GetMSB()+3;
    myT mu = temp.Div(this->GetModulus());
    
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
  

  template<class myT>
  myVecP<myT> myVecP<myT>::Mul(const myVecP &b) const{ //overload of ModMul
    myVecP ans(*this);
    ans = ans.ModMul(b);
    return ans;
  }

  template<class myT>
  myVecP<myT> myVecP<myT>::MultiplyAndRound(const myT &p, const myT &q) const {

	  myVecP ans(*this);
	  myT halfQ(this->m_modulus >> 1);
	  for (usint i = 0; i<this->m_data.size(); i++) {
		  if (ans.m_data[i] > halfQ) {
			  myT temp = this->m_modulus - ans.m_data[i];
			  ans.m_data[i] = this->m_modulus - temp.MultiplyAndRound(p, q);
		  }
		  else
			  ans.m_data[i] = ans.m_data[i].MultiplyAndRound(p, q).Mod(this->m_modulus);
	  }
	  return ans;
  }

  template<class myT>
  myVecP<myT> myVecP<myT>::DivideAndRound(const myT &q) const {
	  myVecP ans(*this);
	  for (usint i = 0; i<this->m_data.size(); i++) {
		  ans.m_data[i] = ans.m_data[i].DivideAndRound(q);
	  }
	  return ans;
  }

  // assignment operators

  template<class myT>
  const myVecP<myT>& myVecP<myT>::operator+=(const myVecP &b) {
    if(this->m_modulus!=b.m_modulus){
      throw std::logic_error("myVecP += vectors of different moduli");
    }else if(this->m_data.size()!=b.m_data.size()){
      throw std::logic_error("myVecP += vectors of different lengths");
    }

    *this = *this + b;
    return *this;
  }

  template<class myT>
  const myVecP<myT>& myVecP<myT>::operator-=(const myVecP &b) {
    if(this->m_modulus!=b.m_modulus){
      throw std::logic_error("myVecP -= vectors of different moduli");
    }else if(this->m_data.size()!=b.m_data.size()){
      throw std::logic_error("myVecP -= vectors of different lengths");
    }
    *this = *this - b;
    return *this;
  }


  template<class myT>
  const myVecP<myT>& myVecP<myT>::operator*=(const myVecP &b) {
    if(this->m_modulus!=b.m_modulus){
      throw std::logic_error("myVecP -= vectors of different moduli");
    }else if(this->m_data.size()!=b.m_data.size()){
      throw std::logic_error("myVecP -= vectors of different lengths");
    }
    *this = *this * b;
    return *this;
  }

#endif    
#if 0
  //Gets the ind
  template<class myT>
  myVecP<myT> myVecP<myT>::GetDigitAtIndexForBase(usint index, usint base) const{
    myVecP ans(*this);
    for(usint i=0; i < this->m_data.size(); i++){
      ans.m_data[i] = myT(ans.m_data[i].GetDigitAtIndexForBase(index,base));
    }

    return ans;
  }
#endif
#if 0
	//this has not  been touched
  //new serialize and deserialise operations
  //todo: not tested just added to satisfy compilier
  //currently using the same map as bigBinaryVector, with modulus. 

  // JSON FACILITY - Serialize Operation
  template<class bin_el_t>
  bool myVecP<bin_el_t>::Serialize(lbcrypto::Serialized* serObj) const {

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
    serObj->AddMember("myVecP", bbvMap, serObj->GetAllocator());
    return true;
  }

  // JSON FACILITY - Deserialize Operation
  template<class myT>
  bool myVecP<myT>::Deserialize(const lbcrypto::Serialized& serObj) {

    lbcrypto::Serialized::ConstMemberIterator mIter = serObj.FindMember("myVecP");
    if( mIter == serObj.MemberEnd() )
      return false;

    lbcrypto::SerialItem::ConstMemberIterator vIt;
    if( (vIt = mIter->value.FindMember("Modulus")) == mIter->value.MemberEnd() )
    return false;
    myT bbiModulus(vIt->value.GetString());

    if( (vIt = mIter->value.FindMember("VectorValues")) == mIter->value.MemberEnd() )
      return false;

    this->SetModulus(bbiModulus);

    this->m_data.clear();

    myT vectorElem;
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




  //procedural addition why can't I inheret this?
  template<class myT>
  void  myVecP<myT>::add(myVecP<myT>& x, myVecP<myT> const& a, myVecP<myT> const& b) const
  {
    unsigned int n = a.length();
    if (b.length() != n) LogicError("myVecP<>vector add: dimension mismatch");

    x.SetLength(n);
    unsigned int i;
    for (i = 0; i < n; i++)
      x[i]=a[i]+b[i]; //inmplicit modulo add
    //todo make modulus explicit.
  }


  //////////////////////////////////////////////////
  // Set value at index from ubint
  template<class myT>
  void myVecP<myT>::SetValAtIndex(usint index, const myT& value){
    if(!this->IndexCheck(index)){
      throw std::logic_error("myVecP index out of range");
    }
    else{
      this->at(index) = myT(value);
    }
  }


  // set value at index from string
  template<class myT>
  void myVecP<myT>::SetValAtIndex(usint index, const std::string& str){
    if(!this->IndexCheck(index)){
      throw std::logic_error("myVecP index out of range");
    }
    else{
      this->at(index) = myT(str);
    }
  }
  // set value at index from const char*
  template<class myT>
  void myVecP<myT>::SetValAtIndex(usint index, const char * str){
    if(!this->IndexCheck(index)){
      throw std::logic_error("myVecP index out of range");
    }
    else{
      this->at(index) = myT(str);
    }
  }

  template<class myT>
  const myT& myVecP<myT>::GetValAtIndex(size_t index) const{
    if(!this->IndexCheck(index)){
      throw std::logic_error("myVecP index out of range");
    }
    return this->at(index);
  }

  //Private functions
  template<class myT>
  bool myVecP<myT>::IndexCheck(usint length) const{
    if(length>this->length())
      return false;
    return true;
  }



  template<class myT>
  void myVecP<myT>::m_setOTM(const myZZ &q) 
  {
    //should test first but for now just set
    ZZ_p::init(q);
    this->m_OTM = q;
    this->m_OTM_state = INITIALIZED;
  }

  template<class myT>
  bool myVecP<myT>::m_checkOTM(const myZZ &q) const 
  {
    if (m_OTM_state == GARBAGE){
      throw std::logic_error("myVecP<myT>::function() called with uninitialized OTM");
    }
    return (m_OTM == q);
  }

  template<class myT>
  bool myVecP<myT>::m_isOTMSet(void) const 
  {
    bool test =(m_OTM_state == INITIALIZED);
    if (!test){
      throw std::logic_error("myVecP<myT>::function() called with uninitialized OTM");
    }
    return (test);
  }

  template<class myT>
  myZZ& myVecP<myT>::m_getOTM(void) const 
  {
    if (m_OTM_state == GARBAGE){
      throw std::logic_error("myVecP<myT>::m_getOTM() called with uninitialized OTM");
    } else {
      return m_OTM;
    }
  }


} // namespace NTL ends
 
