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

#if MATHBACKEND == 6 //otherwise it tries to compile

#include "../../utils/serializable.h"
#include "mgmpintvec.h"

#include "time.h"
#include <chrono>

#include "../../utils/debug.h"

namespace NTL {

  // constructors without moduli
  //&&&
  //copy ctor with vector inputs
  //creation ctors without moduli are marked GARBAGE
  template<class myT>
  myVecP<myT>::myVecP(const myVecP<myT> &a) : Vec<myT>(INIT_SIZE, a.length()) 
  {
    bool dbg_flag = false;
    DEBUG("in myVecP(myVecP&) length "<<a.length());
    DEBUG("input vector "<<a);
    DEBUG("input modulus "<<a.GetModulus());
    this->CopyModulus(a);
#if 0
    for (auto i=0; i< a.length(); i++) {
      (*this)[i]=a[i];
    }
#else
    *this=a;
#endif
    DEBUG("output vector "<<*this);
    DEBUG("output modulus "<<this->GetModulus());

  }

  template<class myT>
  myVecP<myT>::myVecP(const myVec<myZZ> &a) : Vec<myT>(INIT_SIZE, a.length()) 
  {
    for (auto i=0; i< a.length(); i++) {
      (*this)[i]=a[i];
    }
    this->m_modulus_state == GARBAGE;
  }

  //movecopy ctor
  template<class myT>
  myVecP<myT>::myVecP(myVecP<myT> &&a) : Vec<myT>(INIT_SIZE, a.length()) 
  {
    bool dbg_flag = false;
    DEBUG("in myVecP copymove, myvecP<myT> alength "<<a.length());
    this->CopyModulus(a);
    this->move(a);
  }

  //movecopy ctor
  template<class myT>
  myVecP<myT>::myVecP(myVec<myZZ> &&a) : Vec<myT>(INIT_SIZE, a.length()) 
  {
    bool dbg_flag = false;
    DEBUG("in myVecP copymove myVec<myZZ>, alength "<<a.length());
    // wasn't able to use Victor's move(a);
    for (auto i=0; i< a.length(); i++) {
      (*this)[i]=a[i];
    }
    this->m_modulus_state = GARBAGE;
  }


  //constructors with moduli
  //ctor myZZ moduli
  template<class myT>
  myVecP<myT>::myVecP(const long n, const myZZ &q): Vec<myT>(INIT_SIZE,n)
  {
    bool dbg_flag = false;
    DEBUG("myVecP(n,ZZ) n:"<<n);
    DEBUG("q:"<<q);
    this->SetModulus(q);
    DEBUG("get modulus "<<GetModulus());
  }
  
  template<class myT>
  myVecP<myT>::myVecP(const INIT_SIZE_TYPE, const long n, const myZZ &q): Vec<myT>(INIT_SIZE,n)
  {
    this->SetModulus(q);
  }
  
  template<class myT>
  myVecP<myT>::myVecP(const INIT_SIZE_TYPE, const long n, const myT& a, const myZZ &q): Vec<myT>(INIT_SIZE,n)
  {
    for (auto i = 0; i < n; i++){
      (*this)[i] = a;
    }
    this->SetModulus(q);
  }

  template<class myT>
  myVecP<myT>::myVecP(const myVecP<myT> &a, const myZZ &q): Vec<myT>(a)
  {
    this->SetModulus(q);
    (*this) %= q;
  }

  template<class myT>
  myVecP<myT>::myVecP(const myVec<myZZ> &a, const myZZ &q) : Vec<myT>(INIT_SIZE, a.length()) 
  {
    this->SetModulus(q);
    for (auto i=0; i< a.length(); i++) {
      (*this)[i] = a[i]%q;  //must we do this since myZZ could be >=q
    }
  }

  //ctor with char * moduli
  template<class myT>
  myVecP<myT>::myVecP(usint n, const char *sq):Vec<myT>(INIT_SIZE, n)
  { 
    this->SetModulus(myZZ(sq)); 
  }

  template<class myT>
  myVecP<myT>::myVecP(INIT_SIZE_TYPE, long n, const char *sq):Vec<myT>(INIT_SIZE, n) 
  { 
    this->SetModulus(myZZ(sq)); 
  }

  template<class myT>
  myVecP<myT>::myVecP(INIT_SIZE_TYPE, long n, const myT& a, const char *sq):Vec<myT>(INIT_SIZE, n) 
  { 
    this->SetModulus(myZZ(sq)); 
    for (auto i = 0; i < n; i++){
      (*this)[i] = a%this->m_modulus;
    }
  }
  
  //copy with char * moduli
  template<class myT>
  myVecP<myT>::myVecP(const myVecP<myT> &a, const char *sq):Vec<myT>(a) 
  {
    this->SetModulus(myZZ(sq)); 
  }

  template<class myT>
  myVecP<myT>::myVecP(const myVec<myZZ> &a, const char *sq) : Vec<myT>(INIT_SIZE, a.length()) 
  {
    myZZ zzq(sq);
    this->SetModulus(zzq);
    for (auto i=0; i< a.length(); i++) {
      (*this)[i] = a[i]%zzq;  //must we do this since myZZ could be >=q
    }
  }

  //ctor with usint moduli
  template<class myT>
  myVecP<myT>::myVecP(usint n, usint q):Vec<myT>(INIT_SIZE, n) 
  { 
    this->SetModulus(q); 
  }

  template<class myT>
  myVecP<myT>::myVecP(INIT_SIZE_TYPE, long n, usint q):Vec<myT>(INIT_SIZE, n) 
  { 
    this->SetModulus(q); 
  }

  template<class myT>
  myVecP<myT>::myVecP(INIT_SIZE_TYPE, long n, const myT& a, usint q):Vec<myT>(INIT_SIZE, n) 
  { 
    this->SetModulus(q); 
    for (auto i = 0; i < n; i++){
      (*this)[i] = a%q;
    }
  }

  //copy with unsigned int moduli
  template<class myT>
  myVecP<myT>::myVecP(const myVecP<myT> &a, const usint q):Vec<myT>(a) 
  { 
    this->SetModulus(q); 
    for (auto i = 0; i < this->length(); i++){
      (*this)[i] %=q;
    }
  }

  template<class myT>
  myVecP<myT>::myVecP(const myVec<myZZ> &a, const usint q) : Vec<myT>(INIT_SIZE, a.length()) 
  {
    myZZ zzq(q);
    this->SetModulus(zzq);
    for (auto i=0; i< a.length(); i++) {
      (*this)[i] = a[i]%zzq;  //must we do this since myZZ could be >=q
    }
  }

  // constructor specifying the myvec as a vector of strings
  template<class myT>
  myVecP<myT>::myVecP(std::vector<std::string> &s){
    usint len = s.size();
    this->SetLength(len);
    for (usint i = 0; i < len; i++){
      (*this)[i] = myT(s[i]);
    }
    this->m_modulus_state = GARBAGE; 
  }

  // constructor specifying the myvec as a vector of strings with modulus
  template<class myT>
  myVecP<myT>::myVecP(std::vector<std::string> &s, const myZZ &q){
    usint len = s.size();
    this->SetLength(len);
    this->SetModulus(q);
    for (usint i = 0; i < len; i++){
      (*this)[i] = myT(s[i])%q;
    }
  }

  // constructor specifying the myvec as a vector of strings with modulus
  template<class myT>
  myVecP<myT>::myVecP(std::vector<std::string> &s, const char *sq){
    usint len = s.size();
    this->SetLength(len);
    myZZ zzq(sq);
    this->SetModulus(zzq);
    for (usint i = 0; i < len; i++){
      (*this)[i] = myT(s[i])%zzq;
    }
  }

  // constructor specifying the myvec as a vector of strings with modulus
  template<class myT>
  myVecP<myT>::myVecP(std::vector<std::string> &s, const usint q){
    usint len = s.size();
    this->SetLength(len);
    myZZ zzq(q);
    this->SetModulus(zzq);
    for (usint i = 0; i < len; i++){
      (*this)[i] = myT(s[i])%zzq;
    }
  }
  
  //Assignment with initializer list of myZZ
  // note, resizes the vector to the length of the initializer list
  //keeps current modulus
  template<class myT>
  const myVecP<myT>& myVecP<myT>::operator=(std::initializer_list<myT> rhs){
    bool dbg_flag = false;
    DEBUG("in op=initializerlist <myT>");
    usint len = rhs.size();
    this->SetLength(len);
    for(usint i=0;i<len;i++){ // this loops over each entry
      (*this)[i] =  myT(*(rhs.begin()+i));
    }
    return *this;
    DEBUG("mubintvec assignment copy CTOR ubint init list length "<<this->length());
  }

  //Assignment with initializer list of usints
  //keeps current modulus
  template<class myT>
  const myVecP<myT>& myVecP<myT>::operator=(std::initializer_list<usint> rhs){
    bool dbg_flag = false;
    DEBUG("in op=initializerlist <usint>");
    usint len = rhs.size();
    this->SetLength(len);
    for(usint i=0;i<len;i++){ // this loops over each entry
      (*this)[i] =  myZZ(*(rhs.begin()+i));
    }
    return *this;
    DEBUG("mubintvec assignment copy CTOR usint init list length "<<this->length());
  }

  //Assignment with initializer list of ints
  //keeps current modulus
  template<class myT>
  const myVecP<myT>& myVecP<myT>::operator=(std::initializer_list<int> rhs){
    bool dbg_flag = false;
    DEBUG("in op=initializerlist <int>");
    usint len = rhs.size();
    this->SetLength(len);
    for(usint i=0;i<len;i++){ // this loops over each entry
      (*this)[i] =  myZZ(*(rhs.begin()+i));
    }
    return *this;
    DEBUG("mubintvec assignment copy CTOR int init list length "<<this->length());
  }


  //Assignment with initializer list of strings
  //keeps current modulus
  template<class myT>
  const myVecP<myT>& myVecP<myT>::operator=(std::initializer_list<std::string> rhs){
    bool dbg_flag = false;
    DEBUG("in op=initializerlist <string>");
    usint len = rhs.size();
    this->SetLength(len);
    for(usint i=0;i<len;i++){ // this loops over each entry
      (*this)[i] =  myT(*(rhs.begin()+i));
    }
    return *this;
    DEBUG("mubintvec assignment copy CTOR string init list length "<<this->size());
  }

  //Assignment with initializer list of const char *
  //not sure why this isn't taken care of by string above
  //keeps current modulus
  template<class myT>
  const myVecP<myT>& myVecP<myT>::operator=(std::initializer_list<const char *> rhs)
  {
    bool dbg_flag = false;
    DEBUG("in op=initializerlist const char*");
    usint len = rhs.size();
    this->SetLength(len);
    for(usint i=0;i<len;i++){ // this loops over each entry
      (*this)[i] =  (myT(*(rhs.begin()+i)));
    } 
    return *this;
  }
  

  //keeps current modulus 
  //DESIGN QUESTION do we keep modulus or use modulus of rhs?
  template<class myT>
  const myVecP<myT>& myVecP<myT>::operator=(const myT &rhs)
  {
    bool dbg_flag = false;
    DEBUG("in op=const myT&");
    this->SetLength(1);
    (*this)[0] = rhs;
    ModulusCheck("myVecP::op=myT");
    return *this;
  }

  //keeps current modulus  
  template<class myT>
  const myVecP<myT>& myVecP<myT>::operator=(myT &rhs)
  {
    bool dbg_flag = false;
    DEBUG("in op=myT&");
    this->SetLength(1);
    (*this)[0] =rhs;
    ModulusCheck("myVecP::op=myT");
    return *this;
  }
  
  //keeps current modulus
  template<class myT>
  const myVecP<myT>& myVecP<myT>::operator=(unsigned int &rhs)
  {
    bool dbg_flag = false;
    DEBUG("in op=usint&");
    this->SetLength(1);
    (*this)[0] =(unsigned int &)rhs;
    return *this;
  }
  
  //keeps current modulus
  template<class myT>
  const myVecP<myT>& myVecP<myT>::operator=(unsigned int rhs){
    bool dbg_flag = false;
    DEBUG("in op=usint");
    this->SetLength(1);
    (*this)[0] = (unsigned int)rhs;
    return *this;
  }

  //do not keep current modulus but copies from rhs.
  template<class myT>
  const myVecP<myT>& myVecP<myT>::operator=(const myVecP<myT> &rhs)
  {
    bool dbg_flag = false;
    DEBUG("in op=const myVecP<myT>&");
    DEBUG("setting length "<<rhs.length());
    this->SetLength(rhs.length());
    DEBUG("setting length "<<rhs.length());
    this->CopyModulus(rhs);
    for (auto i = 0; i < rhs.length(); i++){
      (*this)[i] = rhs[i];
    }
    return *this;
  }
  
  //desctructor
  template<class myT>
  myVecP<myT>::~myVecP()
  {

  }

  template<class myT>
  void myVecP<myT>::clear(myVecP<myT>& x)
  {
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
  
  //not enabled yet
  
  //ACCESSORS
#if 0
  //stream <<
  template<class myT>
  std::ostream& operator<<(std::ostream& os, const myVecP<myT> &ptr_obj)
  {
    
    //os<<std::endl;
    //os<<ptr_obj;
    //os<<std::endl;
    for(usint i=0;i<ptr_obj.size();i++){
      os<<ptr_obj[i] <<", ";
    }
    os<<"modulus: "<<ptr_obj.GetModulus();
    //os <<std::endl;
    return os;
  }
#endif  
  
  //Switches the integers in the vector to values corresponding to the new modulus
  //*  Algorithm: Integer i, Old Modulus om, New Modulus nm, delta = abs(om-nm):
  // *  Case 1: om < nm
  // *  if i > i > om/2
  // *  i' = i + delta
  // *  Case 2: om > nm
  // *  i > om/2
  // *  i' = i-delta
  //	
  template<class myT>
  void myVecP<myT>::SwitchModulus(const myZZ& newModulus) 
  {

    bool dbg_flag = false;
    DEBUG("Switch modulus old mod :"<<this->m_modulus);
    DEBUG("Switch modulus old this :"<<*this);

    
    myZZ oldModulus(this->m_modulus);
    myZZ n;
    myZZ oldModulusByTwo(oldModulus>>1);
    myZZ diff ((oldModulus > newModulus) ? (oldModulus-newModulus) : (newModulus - oldModulus));
    DEBUG("Switch modulus diff :"<<diff);
#ifdef FORCE_NORMALIZATION
    //    if (newModulus > oldModulus) {
    //  this->SetModulus(newModulus); // set now in order to write correct numbers.
    //  }
#endif
    for (usint i=0; i< this->GetLength(); i++) {
      n = conv<myZZ>(this->GetValAtIndex(i));
      DEBUG("i,n "<<i<<" "<< n);
      if(oldModulus < newModulus) {
	if(n > oldModulusByTwo) {
	  DEBUG("s1 "<<n.ModAdd(diff, newModulus));
	  this->SetValAtIndexWithoutMod(i, n.ModAdd(diff, newModulus));
	} else {
	  DEBUG("s2 "<<n.Mod(newModulus));
	  this->SetValAtIndexWithoutMod(i, n.Mod(newModulus));
	}
      } else {
	if(n > oldModulusByTwo) {
	  DEBUG("s3 "<<n.ModSub(diff, newModulus));
	  this->SetValAtIndexWithoutMod(i, n.ModSub(diff, newModulus));
	} else {
	  DEBUG("s4 "<<n.Mod(newModulus));
	  this->SetValAtIndexWithoutMod(i, n.Mod(newModulus));
	}
      }
    }
    DEBUG("Switch modulus this before set :"<<*this);
    //if (newModulus < oldModulus) {
      this->SetModulus(newModulus); // set now to correct output
      //}
    DEBUG("Switch modulus new modulus :"<<this->m_modulus);
    DEBUG("Switch modulus new this :"<<*this);

  }
  
  /// ARITHMETIC FUNCTIONS
  
  //Math functions
  // modulus
  
  
  template<class myT>
  myVecP<myT> myVecP<myT>::operator%( const myZZ& b) const  
  {
    unsigned int n = this->length();
    myVecP<myT> res(n);
    res.CopyModulus(*this);
    for (unsigned int i = 0; i < n; i++){
      res[i] = (*this)[i]%b;
    }
    return(res);
  }
  
  
  template<class myT>
  myVecP<myT> myVecP<myT>::Mod(const myZZ& modulus) const
  {
    bool dbg_flag = false;
    // previous version
    //myVecP ans(*this);
    //for(usint i=0;i<this->m_data.size();i++){
    //  ans.m_data[i] = ans.m_data[i].Mod(modulus);
    //}
    //ans.m_modulus = modulus;
    //ans. m_modulus_state = INITIALIZED;
    //return ans;
    DEBUG("mubintvec MOD("<<modulus);
    if (modulus == myZZ::TWO) 
      return this->ModByTwo();
    else
      {
	myVecP ans(*this);
	ans.CopyModulus(*this);
	DEBUG("ans.size"<<ans.size());
	DEBUG("ans.modulus"<<ans.m_modulus);

	myZZ halfQ(this->GetModulus() >> 1);
	DEBUG("halfQ = "<<halfQ);

	for (usint i = 0; i<this->length(); i++) {
	  ans[i] = ans[i].Mod(modulus);
	  if (this->GetValAtIndex(i)>halfQ) {
	    DEBUG("woohoo at i="<<i);
	    //TODO note: this may be mixed modulus math BEWARE
	    myZZ tmp = ans[i]._ZZ_p__rep;
	    tmp = tmp.ModSub(myZZ(this->GetModulus()), modulus);
	    
	    DEBUG("tmp["<<i<<"]="<<tmp);
	    ans[i] = tmp;
	    //ans.SetValAtIndex(i, this->GetValAtIndex(i).ModSub(this->GetModulus(), modulus));
	  }
	  else {
	    ans[i] = ans[i].Mod(modulus);
	  }
	}
	DEBUG("ans.GetModulus() "<<ans.GetModulus());
	//ans.SetModulus(modulus);
	DEBUG("ans.GetModulus() "<<ans.GetModulus());
	
	for (usint i = 0; i<ans.length(); i++) {
	  DEBUG("ans ["<<i<<"] = "<<ans[i]);
	}
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
    myZZ halfQ(this->GetModulus() >> 1);
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
  
  //addition of scalar
  template<class myT>
  myVecP<myT> myVecP<myT>::operator+(myZZ const& b) const
  {
    unsigned int n = this->length();
    myVecP<myT> res(n);
    res.CopyModulus(*this);
    long i;
    for (i = 0; i < n; i++)
      //res[i] = (*this)[i]+b%m_modulus;
      res[i] = (*this)[i]+b;
    return(res);
  }
  
  //addition of vector
  template<class myT>
  myVecP<myT> myVecP<myT>::operator+(myVecP<myT> const& b) const
  {
    bool dbg_flag = false;
    DEBUG("in myVecP::operator+");
    ArgCheckVector(b, "myVecP operator+");
    myVecP<myT> res;
    res.CopyModulus(*this);
    myVecP<myT>::add(res, *this, b%m_modulus);
    //NTL_OPT_RETURN(myVecP<myT>, res);
    DEBUG("myVecP::operator+ returning modulus "<<res.m_modulus);
    return(res);
  }
  
  
  // method to add scalar to vector element at index i
  template<class myT>
  myVecP<myT> myVecP<myT>::ModAddAtIndex(usint i, const myZZ &b) const{
    if(i > this->GetLength()-1) {
      std::string errMsg = "myVecP::ModAddAtIndex. Index is out of range. i = " + i;
      throw std::runtime_error(errMsg);
    }
    myVecP ans(*this); //copy vector
    ModulusCheck("myVecP::ModAddAtIndex");
    //ans[i] = ans[i].ModAdd(b, this->m_modulus);
    ans[i] = ans[i]+b%m_modulus; //mod add is default 
    return ans;
  }

  
  //subtraction of scalar
  template<class myT>
  myVecP<myT> myVecP<myT>::operator-(const myZZ& b) const
  {
    unsigned int n = this->length();
    myVecP<myT> res(n);
    res.CopyModulus(*this);
    long i;
    for (i = 0; i < n; i++)
      res[i] = (*this)[i]-b%m_modulus;
    return(res);
  }

  //subtraction of vector
  //why can't I inheret this?
  template<class myT>
  myVecP<myT> myVecP<myT>::operator-(const myVecP<myT> &b) const
  {
    bool dbg_flag = false;
    DEBUG("in myVecP::operator-");
    ArgCheckVector(b, "myVecP::op-");
    myVecP<myT> res;
    res.CopyModulus(*this);
    myVecP<myT>::sub(res, *this, b);
    //NTL_OPT_RETURN(myVecP<myT>, res);
    DEBUG("myVecP::operator- returning modulus "<<res.m_modulus);
    return(res);
  }


  //multiplication vector by scalar
  template<class myT>
  myVecP<myT> myVecP<myT>::operator*(myZZ const& b) const
  {

    unsigned int n = this->length();
    myVecP<myT> res(n);
    res.CopyModulus(*this);
    long i;
    for (i = 0; i < n; i++)
      //res[i] = (*this)[i]*b%m_modulus;
      res[i] = (*this)[i]*b;
    return(res);
  }

  //multiplication vector vector (element wise)
  //why can't I inheret this?
  template<class myT>
  myVecP<myT> myVecP<myT>::operator*(myVecP<myT> const& b) const
  {
    bool dbg_flag = false;
    DEBUG("in myVecP::operator*");
    ArgCheckVector(b, "myVecP::operator*");
    myVecP<myT> res;
    res.CopyModulus(*this);
    myVecP<myT>::mul(res, *this, b);
    //NTL_OPT_RETURN(myVecP<myT>, res);
    DEBUG("myVecP::operator* returning modulus "<<res.m_modulus);
    return(res);
  }

  template<class myT>
  myVecP<myT> myVecP<myT>::ModExp(const myZZ &b) const
  {
    myVecP ans(*this);
    ModulusCheck("myVecP::ModExp");
    for(usint i=0;i<this->size();i++){
      ans[i] = ans[i].ModExp(b%m_modulus, ans.m_modulus);
    }
    return ans;
  }

  // method to exponentiate vector by scalar 
  template<class myT>
  myVecP<myT> myVecP<myT>::Exp(const myZZ &b) const //overload of ModExp()
  {
    myVecP ans(*this);
    ModulusCheck("myVecP::ModExp");
    ans = ans.ModExp(b%m_modulus);
    return ans;
  }
  
  template<class myT>
  myVecP<myT> myVecP<myT>::MultiplyAndRound(const myT &p, const myT &q) const 
  {
    ModulusCheck("myVecP::MultiplyAndRound");
    myVecP ans(*this);
    myT halfQ(this->m_modulus >> 1);
    for (usint i = 0; i<this->size(); i++) {
      if (ans[i] > halfQ) {
	myT temp = this->m_modulus - ans[i];
	ans[i] = this->m_modulus - temp.MultiplyAndRound(p, q);
      }
      else
	ans[i] = ans[i].MultiplyAndRound(p, q).Mod(this->m_modulus);
    }
    return ans;
  }

  template<class myT>
  myVecP<myT> myVecP<myT>::DivideAndRound(const myT &q) const {
    ModulusCheck("myVecP::DivideAndRound");
    myVecP ans(*this);
    for (usint i = 0; i<this->length(); i++) {
      ans[i] = ans[i].DivideAndRound(q);
    }
    return ans;
  }
  
  template<class myT>
  myVecP<myT> myVecP<myT>::ModInverse(void) const
  {
    ModulusCheck("myVecP::ModInverse");
    myVecP ans(*this);
    for(usint i=0;i<this->size();i++){
      ans[i] = ans[i].ModInverse(this->m_modulus);
    }
    return ans;
  }

  //not sure what this does..
  template<class myT>
  myVecP<myT> myVecP<myT>::GetDigitAtIndexForBase(usint index, usint base) const
  {
    myVecP ans(*this);
    for(usint i=0; i < this->size(); i++){
      ans[i] = myZZ_p(myZZ(ans[i]).GetDigitAtIndexForBase(index,base));
    }

    return ans;
  }

  //new serialize and deserialise operations
  //todo: not tested just added to satisfy compilier
  //currently using the same map as bigBinaryVector, with modulus. 

  // JSON FACILITY - Serialize Operation
  template<class myT>
  bool myVecP<myT>::Serialize(lbcrypto::Serialized* serObj) const 
  {
    if( !serObj->IsObject() )
      return false;

    lbcrypto::SerialItem bbvMap(rapidjson::kObjectType);
    bbvMap.AddMember("Modulus", this->GetModulus().ToString(), serObj->GetAllocator()); 

    size_t pkVectorLength = this->size();
    if( pkVectorLength > 0 ) {
      std::string pkBufferString = this->at(0).Serialize();
      for (size_t i = 1; i < pkVectorLength; i++) {
	pkBufferString += "|";
	pkBufferString += this->at(i).Serialize();
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
  if( (vIt = mIter->value.FindMember("VectorValues")) == 
    mIter->value.MemberEnd() )
      return false;
    clear(*this);
    this->SetModulus(bbiModulus);

    myT vectorElem;
    const char *vp = vIt->value.GetString();
    while( *vp != '\0' ) {
      vp = vectorElem.Deserialize(vp);
      this->push_back(vectorElem);
      if( *vp == '|' )
	vp++;
    }

    return true;
  }

  //procedural addition
  template<class myT>
  void  myVecP<myT>::add(myVecP<myT>& x, myVecP<myT> const& a, myVecP<myT> const& b) const
  {
    bool dbg_flag = false;
    a.ArgCheckVector(b, "myVecP::add()");
    unsigned int n = a.length();
    if (b.length() != n) LogicError("myVecP<>vector add: dimension mismatch");

    x.SetLength(n);
    unsigned int i;
    DEBUG("myvecp::add a mod "<<a.m_modulus<<" b mod "<<b.m_modulus);    
    DEBUG("myvecp::add a length "<<a.size()<<"b "<<b.size());
    //DEBUG("myvecp::add initial otm is: "<<ZZ_p::modulus());
    //ZZ_p::init(a.m_modulus);
    
    for (i = 0; i < n; i++){
      DEBUG("myvecp::add i:"<<i<<"a "<<a[i]<<" b "<<b[i]);

      x[i]=a[i]+b[i]; //inmplicit modulo add
    }
    DEBUG("myvecp::done");
    //todo make modulus explicit.
  }
//procedural subtraction
  template<class myT>
  void  myVecP<myT>::sub(myVecP<myT>& x, myVecP<myT> const& a, myVecP<myT> const& b) const
  {
    bool dbg_flag = false;

    a.ArgCheckVector(b, "myVecP::sub()");
    unsigned int n = a.length();
    if (b.length() != n) LogicError("myVecP<>vector sub: dimension mismatch");

    x.SetLength(n);
    unsigned int i;

    DEBUG("myvecp::sub a mod "<<a.m_modulus<<" b mod "<<b.m_modulus);
    DEBUG("myvecp::sub a length "<<a.size()<<"b "<<b.size());
    //DEBUG("myvecp::sub initial otm is: "<<ZZ_p::modulus());
    //ZZ_p::init(a.m_modulus);

    for (i = 0; i < n; i++){
      DEBUG("myvecp::sub i:"<<i<<"a "<<a[i]<<" b "<<b[i]);

      x[i]=a[i]-b[i]; //inmplicit modulo sub
    }
    DEBUG("myvecp::done");
    //todo make modulus explicit.
  }

//procedural multiplication (can;t inheret anyway. ours is element wise not dot product. 
  template<class myT>
  void  myVecP<myT>::mul(myVecP<myT>& x, myVecP<myT> const& a, myVecP<myT> const& b) const
  {
    bool dbg_flag = false;
    a.ArgCheckVector(b, "myVecP::mul()");
    unsigned int n = a.length();
    if (b.length() != n) LogicError("myVecP<>vector sub: dimension mismatch");

    x.SetLength(n);
    unsigned int i;

    DEBUG("myvecp::mul a mod "<<a.m_modulus<<" b mod "<<b.m_modulus);
    DEBUG("myvecp::mul a length "<<a.size()<<"b "<<b.size());
    //DEBUG("myvecp::sub initial otm is: "<<ZZ_p::modulus());
    //ZZ_p::init(a.m_modulus);

    for (i = 0; i < n; i++){
      DEBUG("myvecp::mul i:"<<i<<"a "<<a[i]<<" b "<<b[i]);

      x[i]=a[i]*b[i]; //inmplicit modulo mul
    }
    DEBUG("myvecp::done");
    //todo make modulus explicit.
  }


  //////////////////////////////////////////////////
  // Set value at index 
  template<class myT>
  void myVecP<myT>::SetValAtIndex(usint index, const myT& value){
    if(!this->IndexCheck(index)){
      throw std::logic_error("myVecP index out of range");
    }
    else{
      // must be set modulo
#ifdef FORCE_NORMALIZATION
      if (isModulusSet())
	this->at(index) = value%m_modulus;
      else //must be set directly
#endif
	this->at(index) = value;
    }
  }

  template<class myT>
  void myVecP<myT>::SetValAtIndex(usint index, const myZZ& value){
    if(!this->IndexCheck(index)){
      throw std::logic_error("myVecP index out of range");
    }
    else{
      // must be set modulo
#ifdef FORCE_NORMALIZATION
      if (isModulusSet())
	this->at(index) = myT(value)%m_modulus;
      else //must be set directly
#endif
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
      // must be set modulo
#ifdef FORCE_NORMALIZATION
      if (isModulusSet())
	this->at(index) = myT(str)%m_modulus;
      else //must be set directly
#endif
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
      // must be set modulo
#ifdef FORCE_NORMALIZATION
      if (isModulusSet())
	this->at(index) = myT(str)%m_modulus;
      else //must be set directly
#endif
	this->at(index) = myT(str);
    }
  }

  template<class myT>
  void myVecP<myT>::SetValAtIndexWithoutMod(usint index, const myZZ& value){
    if(!this->IndexCheck(index)){
      throw std::logic_error("myVecP index out of range");
    }
    else{
      //std::cout<<"Warning setting value to index without mod() first"<<std::endl;
	this->at(index) = myT(value);
    }
  }

  //DBC: could not get returning a & to work!!!
  template<class myT>
  const myZZ myVecP<myT>::GetValAtIndex(size_t index) const{
    bool dbg_flag = false;
    if(!this->IndexCheck(index)){
      throw std::logic_error("myVecP index out of range");
    }
    const myZZ tmp((this->at(index))._ZZ_p__rep);
    DEBUG("in GetValAtIndex("<<index<< ") = "<<tmp);
    return tmp;
  }

  //Private functions
  template<class myT>
  bool myVecP<myT>::IndexCheck(usint length) const{
    if(length>this->length())
      return false;
    return true;
  }

} // namespace NTL ends
 
template class NTL::myVecP<NTL::myZZ_p>; //instantiate template here
 
#endif //MATHBACKEND == 6