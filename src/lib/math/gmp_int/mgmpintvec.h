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
 * This file contains ubintvec, a <vector> of ubint, with associated
 * math operators.  
 * NOTE: this has been refactored so that implied modulo (ring)
 * aritmetic is in mbintvec
 *
 */

#ifndef LBCRYPTO_MATH_GMPINT_MGMPINTVEC_H
#define LBCRYPTO_MATH_GMPINT_MGMPINTVEC_H

#include <iostream>
#include <vector>

#include "../../utils/inttypes.h"
#include "../../utils/serializable.h"
#include <initializer_list>
#include "gmpintvec.h"
#include "mgmpint.h"

#if 1
#include <NTL/vector.h>
#include <NTL/vec_ZZ.h>
#include <NTL/SmartPtr.h>
#include <NTL/vec_ZZ_p.h>
#endif

/**
 * @namespace NTL
 * The namespace of this code
 */
namespace NTL {
  /**
   * @brief The class for representing vectors of ubint with associated modulo math
   */
  //note this inherits from gmpintvec

  //JSON FACILITY

  template<class myT>
    class myVecP : public NTL::Vec<myT> {
    //    class myVecP : public lbcrypto::Serializable


  public:
    //note gmpint.h puts constructor bodies here, 
    //mubint.h moves them to .cpp, so we may do that too. 


  myVecP(): Vec<myT>() {};
    //constructors without moduli
  myVecP(usint n): Vec<myT>(INIT_SIZE, n) {}; // adapter kit
  myVecP(INIT_SIZE_TYPE, long n): Vec<myT>(INIT_SIZE, n) {};
  myVecP(INIT_SIZE_TYPE, long n,  myT const& a): Vec<myT>(INIT_SIZE, n, a) {}; 


    //copy

    myVecP(const myVecP<myT> &a);

    // copy ctors with vector inputs
    myVecP(const myVec<myZZ> &a);

    ///movecopy
    myVecP(myVecP<myT> &&a);
    myVecP(myVec<myZZ> &&a);

    //constructors with moduli
    //ctor myZZ moduli
    myVecP(unsigned int n, myZZ const &q); //moved const
    myVecP(INIT_SIZE_TYPE, long n, const myZZ &q); //moved const
    myVecP(INIT_SIZE_TYPE, long n, const myT& a, const myZZ &q);

    //copy with myZZ moduli
    myVecP(const myVecP<myT> &a, myZZ &q);
    myVecP(const myVec<myZZ> &a, myZZ &q);

    //ctor with char * moduli
    myVecP(usint n, const char *sq);
    myVecP(INIT_SIZE_TYPE, long n, const char *sq);
    myVecP(INIT_SIZE_TYPE, long n, const myT& a, const char *sq);

    //copy with char * moduli

    //myVecP(NTL::Vec<myT> &a, const char *sq);
    myVecP(const myVecP<myT> &a, const char *sq);
    myVecP(const myVec<myZZ> &a, const char *sq);

    //ctor with usint moduli
    myVecP(usint n, usint q);
    myVecP(INIT_SIZE_TYPE, long n, usint q);
    myVecP(INIT_SIZE_TYPE, long n, const myT& a, usint q);

   //copy with unsigned int moduli
    myVecP(const myVecP<myT> &a, const usint q);
    myVecP(const myVec<myZZ> &a, const usint q);

    //destructor
     ~myVecP();

    //adapters
    myVecP(std::vector<std::string>& s); //without modulus
    
    myVecP(std::vector<std::string>& s, const myZZ &q); // with modulus
    myVecP(std::vector<std::string>& s, const char *sq); // with modulus
    myVecP(std::vector<std::string>& s, const usint q); // with modulusu

    const myVecP& operator=(const myVecP &a);


    const myVecP& operator=(std::initializer_list<myT> rhs);
    const myVecP& operator=(std::initializer_list<usint> rhs);
    const myVecP& operator=(std::initializer_list<std::string> rhs);
    const myVecP& operator=(std::initializer_list<const char *> rhs);
    const myVecP& operator=(myT &rhs);
    const myVecP& operator=(const myT &rhs);
    const myVecP& operator=(unsigned int &rhs);
    const myVecP& operator=(unsigned int rhs);

    void clear(myVecP& x); //why isn't this inhereted?

    inline usint size() {return this->length();};
    void SetValAtIndex(usint index, const myT&value);
    void SetValAtIndex(usint index, const char *s);
    void SetValAtIndex(usint index, const std::string& str);
    const myT& GetValAtIndex(size_t index) const;

    inline void push_back(const myT& a) { this->append(a);};

    static inline myVecP Single(const myZZ& val, const myZZ &modulus) {
      bool dbg_flag = false;
      DEBUG("single in");
      myVecP vec(1);
      DEBUG("a");
      vec.SetModulus(modulus);
      DEBUG("b");
      vec[0]=val;
      DEBUG("single out");
      return vec;
    };

    //comparison. 

    //arithmetic
    //scalar modulus

    myVecP operator%(const myZZ& b) const; 

    myVecP Mod(const myZZ& b) const; //defined in cpp

    myVecP ModByTwo() const; //defined in cpp

    //scalar modulo assignment
    inline myVecP& operator%=(const myZZ& a)
    { 
      for (auto i = 0; i < this->length(); i++){
	(*this)[i]%=a;
      }
      return *this;
    };

    //vector addition assignment
    inline myVecP& operator+=(const myVecP& a) {
      this->ArgCheckVector(a, "myVecP op +=");
      add(*this, *this, a);
      return *this;
    };

    //scalar addition assignment
    inline myVecP& operator+=(const myZZ& a)
    { 
      for (unsigned int i = 0; i < this->length(); i++){
	(*this)[i]=(*this)[i]+a; //+= not defined yet
      }
      return *this;
    };
    //moretodo
    myVecP operator+(myVecP const& b) const;
    myVecP operator+(myZZ const& b) const;

    inline myVecP Add(const myZZ& b) const { return (*this)+b;};
    inline myVecP ModAdd(const myZZ& b) const { return (*this)+b;};
    void add(myVecP& x, const myVecP& a, const myVecP& b) const; //define procedural

    //vector add
    inline myVecP Add(const myVecP& b) const { ArgCheckVector(b, "myVecP Add()"); return (*this)+b;};
    inline myVecP ModAdd(const myVecP& b) const { return (this->Add(b));};

    //Subtraction
    //vector subtraction assignment
    inline myVecP& operator-=(const myVecP& a) {
      ArgCheckVector(a, "myVecP -="); 
      sub(*this, *this, a);
      return *this;
    };

    //scalar subtraction assignment
    inline myVecP& operator-=(const myZZ& a)
    { 
      for (auto i = 0; i < this->length(); i++){
	(*this)[i]-=a;
      }
      return *this;
    };

    myVecP operator-(myVecP const& b) const;
    myVecP operator-(myZZ const& b) const;


    //scalar
    inline myVecP Sub(const myZZ& b) const { return (*this)-b;};
    inline myVecP ModSub(const myZZ& b) const { return (*this)-b;};

    //vector
    inline myVecP Sub(const myVecP& b) const {ArgCheckVector(b, "myVecP Sub()");  return (*this)-b;};
    inline myVecP ModSub(const myVecP& b) const { return (this->Sub(b));};

    //deprecated vector
    inline myVecP Minus(const myVecP& b) const { return (this->Sub(b));};

    void sub(myVecP& x, const myVecP& a, const myVecP& b) const; //define procedural

    //Multiplication
    //vector multiplication assignments
    inline myVecP& operator*=(const myVecP& a)
    { 
      ArgCheckVector(a, "myVecP *="); 
      mul(*this, *this, a);
      return *this;
    };

    //scalar multiplicatoin assignments
    inline myVecP& operator*=(const myZZ& a)
    { 
      for (auto i = 0; i < this->length(); i++){
	(*this)[i] = (*this)[i]*a; //try this for now. *= seems undefined
      }
      return *this;
    };

  
    myVecP operator*(myVecP const& b) const;
    myVecP operator*(myZZ const& a) const;

    //scalar
    inline myVecP Mul(const myZZ& b) const { return (*this)*b;};
    inline myVecP ModMul(const myZZ& b) const { return (*this)*b;};

    //vector
    inline myVecP Mul(const myVecP& b) const {ArgCheckVector(b, "myVecP Mul()"); return (*this)*b;};
    inline myVecP ModMul(const myVecP& b) const {return (this->Mul(b));};

    void mul(myVecP& x, const myVecP& a, const myVecP& b) const; //define procedural

#if 0 //unifdef as this gets modified, comes from gmpintvec
    //not tested yet

    //scalar then vector
    //note a more efficient means exists for these
    inline myVecP ModAdd(const myZZ& b, const myZZ& modulus) const {return ((*this)+b)%modulus;};
    inline myVecP ModAdd(const myVecP& b, const myZZ& modulus) const {return ((*this)+b)%modulus;};

    // note that modsub requires us to use the NTL signed subtraction 
    // rather than the Palisade unsigned subtraction     
    inline myVecP ModSub(const myZZ& b, const myZZ& modulus) const 
    {
      unsigned int n = this->length();
      myVecP<myT> res(n);
      for (unsigned int i = 0; i < n; i++){
	NTL_NAMESPACE::sub(res[i],(*this)[i],b);
	res[i] = res[i]%modulus;
      }
      return(res);
    };

    inline myVecP ModSub(const myZZ& b, const myZZ& modulus) const 
    {
      unsigned int n = this->length();
      myVecP<myT> res(n);
      for (unsigned int i = 0; i < n; i++){
	NTL_NAMESPACE::sub(res[i],(*this)[i],b);
	res[i] = res[i]%modulus;
      }
      return(res);
    };

    inline myVecP ModSub(const myVecP& b, const myZZ& modulus) const 
    {
      unsigned int n = this->length();
      myVecP<myT> res(n);
      for (unsigned int i = 0; i < n; i++){
	NTL_NAMESPACE::sub(res[i],(*this)[i],b[i]);
	res[i] = res[i]%modulus;
      }
      return(res);
    };

    inline myVecP ModMul(const myZZ& b, const myZZ& modulus) const {return ((*this)*b)%modulus;};
    inline myVecP ModMul(const myVecP& b, const myZZ& modulus) const {return ((*this)*b)%modulus;};


#endif



    //public modulus accessors
    inline bool isModulusSet(void) const{
      return(this->m_modulus_state == INITIALIZED);
    };

    //return true if both myVecP have same modulus
    inline bool SameModulus(const myVecP &a) const{
      return((this->m_modulus_state == a.m_modulus_state)&&
	     (this->m_modulus == a.m_modulus));
    };

    inline void SetModulus(const usint& value){
      bool dbg_flag = true;
      DEBUG("SetModulus(const usint& "<<value<<")");
      this->m_modulus= myZZ(value);
      this->m_modulus_state = INITIALIZED;
      DEBUG("this->modulus = "<<this->m_modulus);
      ZZ_p::init(this->m_modulus);
      this->Renormalize();
    };
  
    inline void SetModulus(const myZZ& value){
      bool dbg_flag = true;
      DEBUG("SetModulus(const myZZ& "<<value<<")");
      this->m_modulus= value;
      DEBUG("this->modulus = "<<this->m_modulus);
      this->m_modulus_state = INITIALIZED;
      ZZ_p::init(this->m_modulus);
      this->Renormalize();
    };

    //the following confuses the compiler?
    inline void SetModulus(const myZZ_p& value){
      bool dbg_flag = true;
      DEBUG("SetModulus(const myZZ_p& "<<value<<")");
      this->m_modulus= value.GetModulus();
      DEBUG("this->modulus = "<<this->m_modulus);
      this->m_modulus_state = INITIALIZED;
      ZZ_p::init(this->m_modulus);
      this->Renormalize();
    };

    inline void SetModulus(const std::string& value){
      bool dbg_flag = true;
      DEBUG("SetModulus(const string& "<<value<<")");
      this->m_modulus = myZZ(value);
      this->m_modulus_state = INITIALIZED;
      DEBUG("this->modulus = "<<this->m_modulus);
      ZZ_p::init(this->m_modulus);
      this->Renormalize();
    };
  
    inline void SetModulus(const myVecP& value){
      bool dbg_flag = true;
      DEBUG("SetModulus(const myVecP& "<<value<<")");
      this->m_modulus = value.GetModulus();
      this->m_modulus_state = INITIALIZED;
      DEBUG("this->modulus = "<<this->m_modulus);
      ZZ_p::init(this->m_modulus);
      this->Renormalize();
    };

    inline const myZZ& GetModulus() const{
      bool dbg_flag = true;
      if (this->isModulusSet()){
	DEBUG("GetModulus returns "<<this->m_modulus);
	return (this->m_modulus);
      }else{
	std::cout<<"myZZ GetModulus() on uninitialized modulus"<<std::endl;
	return 0;
      }
    };
    
    inline void CopyModulus(const myVecP& rhs){
      bool dbg_flag = true;
      DEBUG("CopyModulus(const myVecP& modulus is "<<rhs.m_modulus);
      DEBUG("CopyModulus(const myVecP& modulus_state is "<<rhs.m_modulus_state);
      this->m_modulus = rhs.m_modulus;
      this->m_modulus_state = rhs.m_modulus_state;
      ZZ_p::init(this->m_modulus);
    };

    inline size_t GetLength(void) const{ //deprecated by size()
      return this->length();
    };

    inline size_t size(void) const{
      return this->length();
    };


    //need to add comparison operators == and !=
    //note these should fail if the modulii are different!
    // inline sint Compare(const myVecP& a) const {return compare(this->_ZZ_p__rep,a._ZZ_p__rep); };
    // myvecP and myvecP
    inline bool operator==(const myVecP& b) const
    { 
      if ((this->SameModulus(b)) && 
	  (this->size()==b.size())) { 
	//loop over each entry and fail if !=
	for (auto i = 0; i < this->size(); ++i) {
	  if ((*this)[i]!=b[i]){
	    return false;
	  }
	}
	return true;// all entries ==
	
      }else{ //fails check of size and modulus
	return false;
      }
    };
    
    inline bool operator!=( const myVecP& b) const
    { return !(this->operator==(b)); };

    // myvecP and myvec<myZZ>
    inline bool operator==(const myVec<myZZ>& b) const
    { 
      if ((this->size()==b.length())) { //TODO: define size() for b
	//loop over each entry and fail if !=
	for (auto i = 0; i < this->size(); ++i) {
	  if ((*this)[i]!=b[i]){
	    return false;
	  }
	}
	return true;// all entries ==
	
      }else{ //fails check of size
	return false;
      }
    };
    
    inline bool operator!=( const myVec<myZZ>& b) const
    { return !(this->operator==(b)); };


    // inline long operator<( const myZZ_p& b) const
    // { return this->Compare(b) < 0; }
    // inline long operator>( const myZZ_p& b) const
    // { return this->Compare(b) > 0; }
    // inline long operator<=( const myZZ_p& b) const
    // { return this->Compare(b) <= 0; }
    // inline long operator>=( const myZZ_p& b) const
    // { return this->Compare(b) >= 0; }

#if 0
    // ostream 
    friend std::ostream& operator<<(std::ostream& os, const myVecP &ptr_obj);
#endif

  private:
    //utility function to check argument consistency for vector scalar fns
    inline void ArgCheckScalar(const myT &b, std::string fname) const {
      if(this->m_modulus!=b.GetModulus()) {
	throw std::logic_error(fname+" modulus vector modulus scalar op of different moduli");
      }
    };

    //utility function to check argument consistency for vector vector fns
    inline void ArgCheckVector(const myVecP &b, std::string fname) const {
      if(this->m_modulus!=b.m_modulus) {
	throw std::logic_error(fname+" modulus vector modulus vector op of different moduli");
      }else if(this->size()!=b.size()){
	throw std::logic_error(fname +" vectors of different lengths");
      }
    };

    //used to make sure all entries in this are <=current modulus
    inline void Renormalize(void) {
      bool dbg_flag = false;
      DEBUG("mgmpintvec Renormalize modulus"<<m_modulus);     
      DEBUG("mgmpintvec size"<< this->size());     
      //loop over each entry and fail if !=
      for (auto i = 0; i < this->size(); ++i) {
	(*this)[i] %=m_modulus;
	DEBUG("this ["<<i<<"] now "<< (*this)[i]);     
      }
    };
	

    myZZ m_modulus;
    enum ModulusState {
      GARBAGE,INITIALIZED //note different order, Garbage is the default state
    };
    //enum to store the state of the
    ModulusState m_modulus_state;

  protected:
    bool IndexCheck(usint) const;
  }; //template class ends



  //comparison operators with two operands must be defined outside the class
  //myVec<myZZ> and myVecP
  inline long operator==(const myVec<myZZ> &a, const myVecP<myZZ_p> &b) 
  {
    if ((a.length()==b.size())) { 
      //loop over each entry and fail if !=
      for (auto i = 0; i < a.length(); ++i) {
	if (a[i]!=b[i]){
	  return false;
	}
      }
      return true;// all entries ==
    }else{ //fails check of size
      return false;
    }
  };
  
  inline long operator!=(const myVec<myZZ> &a, const myVecP<myZZ_p> &b) 
  { return !(operator==(a,b)); };
  
  
} // namespace NTL ends

#endif // LBCRYPTO_MATH_GMPINT_MGMPINTVEC_H
