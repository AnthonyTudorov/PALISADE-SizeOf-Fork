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
  myVecP(INIT_SIZE_TYPE, long n,  myT const& a): Vec<myT>(INIT_SIZE, n, a) {};  //moved const
    //copy
  myVecP(NTL::Vec<myT> &a) : Vec<myT>(a) {};
  myVecP(const NTL::Vec<myT> &a) : Vec<myT>(a) {};
  myVecP(NTL::Vec<ZZ> &a) : Vec<ZZ>(a) {};
  myVecP(const NTL::Vec<ZZ> &a) : Vec<ZZ>(a) {};
  myVecP(NTL::Vec<ZZ_p> &a) : Vec<ZZ_p>(a) {};
  myVecP(const NTL::Vec<ZZ_p> &a) : Vec<ZZ_p>(a) {};

    ///movecopy
  myVecP(NTL::Vec<myT> &&a) : Vec<myT>(a) {};
  myVecP(NTL::Vec<ZZ> &&a) : Vec<ZZ>(a) {};
  myVecP(NTL::Vec<myZZ> &&a) : Vec<myZZ>(a) {};
  myVecP(NTL::Vec<ZZ_p> &&a) : Vec<ZZ_p>(a) {};
    ///%%%%

    //constructors with moduli
    //ctor myZZ moduli
    myVecP(unsigned int n, myZZ const &q); //moved const
    myVecP(INIT_SIZE_TYPE, long n, const myZZ &q); //moved const
    myVecP(INIT_SIZE_TYPE, long n, const myT& a, const myZZ &q);

    //copy with myZZ moduli
    myVecP(NTL::Vec<myT> &a, myZZ &q);
    myVecP(const NTL::Vec<myT> &a, myZZ &q);
    myVecP(NTL::Vec<ZZ> &a, myZZ &q);
    myVecP(const NTL::Vec<ZZ> &a, myZZ &q);
    myVecP(NTL::Vec<ZZ_p> &a, myZZ &q);
    myVecP(const NTL::Vec<ZZ_p> &a, myZZ &q);

    //ctor with char * moduli
    myVecP(usint n, const char *sq);
    myVecP(INIT_SIZE_TYPE, long n, const char *sq);
    myVecP(INIT_SIZE_TYPE, long n, const myT& a, const char *sq);

    //copy with char * moduli

    myVecP(NTL::Vec<myT> &a, const char *sq);
    myVecP(const NTL::Vec<myT> &a, const char *sq);
    myVecP(NTL::Vec<ZZ> &a, const char *sq);
    myVecP(const NTL::Vec<ZZ> &a, const char *sq);
    myVecP(NTL::Vec<ZZ_p> &a, const char *sq);
    myVecP(const NTL::Vec<ZZ_p> &a, const char *sq);

    //ctor with usint moduli
    myVecP(usint n, usint q);
    myVecP(INIT_SIZE_TYPE, long n, usint q);
    myVecP(INIT_SIZE_TYPE, long n, const myT& a, usint q);

   //copy with unsigned int moduli
    myVecP(NTL::Vec<myT> &a, const usint q);
    myVecP(const NTL::Vec<myT> &a, const usint q);
    myVecP(NTL::Vec<ZZ> &a, const usint q);
    myVecP(const NTL::Vec<ZZ> &a, const usint q);
    myVecP(NTL::Vec<ZZ_p> &a, const usint q);
    myVecP(const NTL::Vec<ZZ_p> &a, const usint q);
 
    ///%%%%

    //destructor
     ~myVecP();

    //adapters
    myVecP(std::vector<std::string>& s); //without modulus
    
    myVecP(std::vector<std::string>& s, myZZ &q); // with modulus
    myVecP(std::vector<std::string>& s, const char *sq); // with modulus
    myVecP(std::vector<std::string>& s, const usint q); // with modulusu




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

    static inline myVecP Single(const myT& val, const myT&modulus) {
      bool dbg_flag = true;
      DEBUG("single in");
      myVecP vec(1);
      vec.SetModulus(modulus);
      vec[0]=val;
      DEBUG("single out");
      return vec;
    }

    //comparison. 

    //arithmetic
    //scalar modulus

    myVecP operator%(const myZZ& b) const; 

    //inline myVecP Mod(const myZZ& b) const { return (*this)%b;};
    myVecP Mod(const myZZ& b) const; //fancy one defined in cpp


    myVecP ModByTwo() const; //defined in cpp

    //scalar modulo assignment
    inline myVecP& operator%=(const myZZ& a)
    { 
      unsigned int n = this->length();
      for (unsigned int i = 0; i < n; i++){
	(*this)[i]%=a;
      }
      return *this;

    };



    inline myVecP& operator+=(const myVecP& a) {
      add(*this, *this, a);
      return *this;
    };

    //scalar addition assignment
    inline myVecP& operator+=(const myT& a)
    { 
      unsigned int n = this->length();
      for (unsigned int i = 0; i < n; i++){
	(*this)[i]+=a;
      }
      return *this;
    };

    myVecP operator+(const myVecP& b) const;
    myVecP operator+(const myT& b) const;

    inline myVecP Add(const myT& b) const { return (*this)+b;};

    void add(myVecP& x, const myVecP& a, const myVecP& b) const; //define procedural

    //vector add
    inline myVecP Add(const myVecP& b) const { return (*this)+b;};

#if 0 //unifdef as this gets modified, comes from gmpintvec

    //Subtraction
    inline myVecP& operator-=(const myVecP& a)
    { 
      sub(*this, *this, a);
      return *this;
    };

    inline myVecP& operator-=(const myT& a)
    { 
      unsigned int n = this->length();
      for (unsigned int i = 0; i < n; i++){
	(*this)[i]-=a;
      }
      return *this;
    };

  
    myVecP operator-(const myVecP& b) const;
    myVecP operator-(const myT& a) const;

    //scalar
    inline myVecP Sub(const myT& b) const { return (*this)-b;};
    //vector
    inline myVecP Sub(const myVecP& b) const { return (*this)-b;};

    //deprecated vector
    inline myVecP Minus(const myVecP& b) const { return (*this)-b;};

    void sub(myVecP& x, const myVecP& a, const myVecP& b) const; //define procedural

    //Multiplication
    inline myVecP& operator*=(const myVecP& a)
    { 
      mul(*this, *this, a);
      return *this;
    };

    inline myVecP& operator*=(const myT& a)
    { 
      unsigned int n = this->length();
      for (unsigned int i = 0; i < n; i++){
	(*this)[i]*=a;
      }
      return *this;
    };

  
    myVecP operator*(const myVecP& b) const;
    myVecP operator*(const myT& a) const;
    //scalar
    inline myVecP Mul(const myT& b) const { return (*this)*b;};
    //vector
    inline myVecP Mul(const myVecP& b) const { return (*this)*b;};
    void mul(myVecP& x, const myVecP& a, const myVecP& b) const; //define procedural


    //not tested yet

    //scalar then vector
    //note a more efficient means exists for these
    inline myVecP ModAdd(const myT& b, const myZZ& modulus) const {return ((*this)+b)%modulus;};
    inline myVecP ModAdd(const myVecP& b, const myZZ& modulus) const {return ((*this)+b)%modulus;};

    // note that modsub requires us to use the NTL signed subtraction 
    // rather than the Palisade unsigned subtraction     
    inline myVecP ModSub(const myT& b, const myZZ& modulus) const 
    {
      unsigned int n = this->length();
      myVecP<myT> res(n);
      for (unsigned int i = 0; i < n; i++){
	NTL_NAMESPACE::sub(res[i],(*this)[i],b);
	res[i] = res[i]%modulus;
      }
      return(res);
    };

    inline myVecP ModSub(const myT& b, const myZZ& modulus) const 
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

    inline myVecP ModMul(const myT& b, const myZZ& modulus) const {return ((*this)*b)%modulus;};
    inline myVecP ModMul(const myVecP& b, const myZZ& modulus) const {return ((*this)*b)%modulus;};


#endif



    //public modulus accessors
    inline void SetModulus(const usint& value){
      this->m_setOTM(myZZ(value));
    };
  
    inline void SetModulus(const myZZ& value){
      this->m_setOTM(value);
    };

    //the following confuses the compiler?
    inline void SetModulus(const myZZ_p& value){
      this->m_setOTM(myZZ(value.myZZ_p::GetModulus()));
    };

    inline void SetModulus(const std::string& value){
      this->m_setOTM(myZZ(value));
    };
  
    inline void SetModulus(const myVecP& value){
      this->m_setOTM(myZZ(value.myVecP::GetModulus()));
    };

    inline const myZZ& GetModulus() const{
      return (this->m_getOTM());
    };

    inline size_t GetLength(void) const{ //deprecated by size()
      return this->length();
    };

    inline size_t size(void) const{
      return this->length();
    };



  private:
    void m_setOTM(const myZZ &q);
    bool m_checkOTM(const myZZ &q) const;
    bool m_isOTMSet() const;
    myZZ& m_getOTM(void) const;
    
  public: //since global?
    static myZZ m_OTM;
    
    enum OTMState {
      GARBAGE,INITIALIZED //note different order, Garbage is the default state
    };
    //enum to store the state of the
    static OTMState m_OTM_state;

  protected:
    bool IndexCheck(usint) const;
  }; //template class ends

} // namespace NTL ends

#endif // LBCRYPTO_MATH_GMPINT_MGMPINTVEC_H
