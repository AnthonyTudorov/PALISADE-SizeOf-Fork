﻿//LAYER 1 : PRIMITIVE DATA STRUCTURES AND OPERATIONS
/**
 * @file
 * @author  TPOC: Dr. Kurt Rohloff <rohloff@njit.edu>,
 * Programmers: Dr. Yuriy Polyakov, <polyakov@njit.edu>, Gyana Sahu
 * <grs22@njit.edu>
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
 *
 * This file contains the C++ code for implementing the main class for
 * big integers: gmpint which replaces BBI and uses NTLLL
 */

#define _SECURE_SCL 0 // to speed up VS


#include <iostream>
#include <fstream>
#include <sstream>
#include "gmpint.h"
#include "mgmpint.h"

namespace NTL {

  // constant log2 of limb bitlength
  const usint myZZ::m_log2LimbBitLength = Log2<NTL_ZZ_NBITS>::value;


  const myZZ myZZ::ZERO=myZZ(0L);
  const myZZ myZZ::ONE=myZZ(1);
  const myZZ myZZ::TWO=myZZ(2);
  const myZZ myZZ::THREE=myZZ(3);
  const myZZ myZZ::FOUR=myZZ(4);
  const myZZ myZZ::FIVE=myZZ(5);

  myZZ::myZZ():ZZ() {}
  myZZ::myZZ(int a): ZZ(a) {}
  myZZ::myZZ(long a): ZZ(a) {}
  myZZ::myZZ(unsigned long a): ZZ(a) {}
  myZZ::myZZ(const unsigned int &a): ZZ(a) {}
  myZZ::myZZ(unsigned int &a): ZZ(a) {}
  myZZ::myZZ(INIT_SIZE_TYPE, long k): ZZ(INIT_SIZE, k) {m_MSB=0; }
  myZZ::myZZ(std::string s): ZZ(conv<ZZ>(s.c_str())) {}
  myZZ::myZZ(const char *s): ZZ(conv<ZZ>(s)) {}

  myZZ::myZZ(NTL::ZZ &a): ZZ(a) {}
  myZZ::myZZ(const NTL::ZZ &a): ZZ(a) {}

  //myZZ::myZZ(const NTL::myZZ_p &a): ZZ(){*this = a._ZZ_p__rep;}
  myZZ::myZZ(const NTL::myZZ_p &a)
    : ZZ(a._ZZ_p__rep)
  {
    bool dbg_flag = false; 
    DEBUG("in ctor mzz(&mzzp)");
    DEBUG("a "<<a);
    DEBUG("arep "<<a._ZZ_p__rep);
    DEBUG("this "<<*this);
  };

#if 0
  myZZ::myZZ(NTL::ZZ &&a) : ZZ(a) {}
  //  myZZ::myZZ(const NTL::myZZ_p &&a): ZZ(){*this = a._ZZ_p__rep;}
  myZZ::myZZ(const NTL::myZZ_p &&a)
    : ZZ(a._ZZ_p__rep)
  {
    bool dbg_flag = false; 
    DEBUG("in ctor mzz(&&mzzp)");
    DEBUG("a "<<a);
    DEBUG("arep "<<a._ZZ_p__rep);
  };
#else
  myZZ::myZZ(NTL::ZZ &&a) : ZZ() {this->swap(a);}
  myZZ::myZZ(NTL::myZZ_p &&a): ZZ(){
    this->swap(a._ZZ_p__rep);
  }

#endif  

  void myZZ::SetValue(const std::string& str) 
  {
    *this = conv<ZZ>(str.c_str());
    SetMSB();
  }

  void myZZ::SetValue(const char *s)
  {
    *this = conv<ZZ>(s);
    SetMSB();
  }

  void myZZ::SetValue(const myZZ& a)
  {
    *this = a;
  }

  //this is the zero allocator for the palisade matrix class
  std::function<unique_ptr<myZZ>()> myZZ::Allocator = [](){
    return lbcrypto::make_unique<NTL::myZZ>();
   };

  usint myZZ::GetMSB() const {


    //note: originally I did not worry about this, and just set the 
    //MSB whenever this was called, but then that violated constness in the 
    // various libraries that used this heavily
    //this->SetMSB(); //note no one needs to SetMSB()
    //return m_MSB;

    //SO INSTEAD I am just regenerating the MSB each time
    size_t sz = this->size();
    usint MSB;
    //std::cout<<"size "<<sz <<" ";
    if (sz==0) { //special case for empty data
      MSB = 0;
      return(MSB);
    }

    MSB = (sz-1) * NTL_ZZ_NBITS; //figure out bit location of all but last limb
    const ZZ_limb_t *zlp = ZZ_limbs_get(*this);
    usint tmp = GetMSBLimb_t(zlp[sz-1]); //add the value of that last limb.

    MSB+=tmp;

    return(MSB);


  }

  void myZZ::SetMSB()
  {

    size_t sz = this->size();
    //std::cout<<"size "<<sz <<" ";
    if (sz==0) { //special case for empty data
      m_MSB = 0;
      return;
    }

    m_MSB = (sz-1) * NTL_ZZ_NBITS; //figure out bit location of all but last limb
    //std::cout<<"msb starts with "<<m_MSB<< " ";
    //could also try
    //m_MSB = NumBytes(*this)*8;
    const ZZ_limb_t *zlp = ZZ_limbs_get(*this);
    //for (usint i = 0; i < sz; i++){
    //std::cout<< "limb["<<i<<"] = "<<zlp[i]<<std::endl;
    //}

    usint tmp = GetMSBLimb_t(zlp[sz-1]); //add the value of that last limb.
    //std::cout<< "tmp = "<<tmp<<std::endl;
    m_MSB+=tmp;
    //std::cout<<"msb ends with "<<m_MSB<< " " <<std::endl;
  }

 // inline static usint GetMSBLimb_t(ZZ_limb_t x){
  usint myZZ::GetMSBLimb_t( ZZ_limb_t x) const {
    const usint bval[] =
    {0,1,2,2,3,3,3,3,4,4,4,4,4,4,4,4};

    uint64_t r = 0;
    if (x & 0xFFFFFFFF00000000) { r += 32/1; x >>= 32/1; }
    if (x & 0x00000000FFFF0000) { r += 32/2; x >>= 32/2; }
    if (x & 0x000000000000FF00) { r += 32/4; x >>= 32/4; }
    if (x & 0x00000000000000F0) { r += 32/8; x >>= 32/8; }
    return r + bval[x];
  }

  
  ///&&&
  //Splits the binary string to equi sized chunks and then populates the internal array values.
  myZZ myZZ::FromBinaryString(const std::string& vin){
    bool dbg_flag = false;		// if true then print dbg output
    DEBUG("FromBinaryString");

    std::string v = vin;
    // strip off leading spaces from the input string
    v.erase(0, v.find_first_not_of(' '));
    // strip off leading zeros from the input string
    v.erase(0, v.find_first_not_of('0'));

    if (v.size() == 0) {
      //caustic case of input string being all zeros
      v = "0"; //set to one zero
    }

    myZZ value;
    //value.clear(); //clear out all limbs
    clear(value); //clear out all limbs

    usint len = v.length();
    ///new code here

    const unsigned int bitsPerByte = 8;
    //parse out string 8 bits at a time into array of bytes
    vector<unsigned char> bytes;

    DEBUG("input string: "<<v);
    DEBUG("len/bitsperbyte = "<<len/bitsPerByte);
    //reverse the string to make code easier
    std::reverse(v.begin(), v.end());
    DEBUG("reversedinput string: "<<v);

    DEBUG("len = "<<len);
    for (auto i = 0; i < len; i+=bitsPerByte){
      std::string bits = v.substr(0, bitsPerByte);
      //reverse the bits
      std::reverse(bits.begin(), bits.end());
      DEBUG("i = "<<i<<" bits: "<<bits);
      int newlen = v.length()-bitsPerByte;
      size_t nbits;
      DEBUG("newlen = "<<newlen);      
      unsigned char byte = std::stoi(bits, &nbits, 2);
      DEBUG("byte = "<<(unsigned int)byte);
      bytes.push_back(byte);
      if (newlen<1)
	break;
      v = v.substr(bitsPerByte, newlen);
      DEBUG("input string now: "<<v);
   }
    DEBUG("bytes size now "<<bytes.size());
    for (auto it = bytes.begin(); it != bytes.end(); ++it){
	DEBUG("bytes ="<< (unsigned int)(*it));
    }
    ZZFromBytes(value, bytes.data(), bytes.size());
    DEBUG("value ="<<value);    
    return(value);

#if 0
    usint cntr = ceilIntByUInt(len);
    std::string val;

    Dlimb_t partial_value = 0;

    for (usint i = 0; i < cntr; i++) 	  {//loop over limbs

      if (len>((i + 1)*NTL_ZZ_NBITS))
	val = v.substr((len - (i + 1)*NTL_ZZ_NBITS), NTL_ZZ_NBITS);
      else
	val = v.substr(0, len%NTL_ZZ_NBITS);
      for (usint j = 0; j < val.length(); j++){
	partial_value += std::stoi(val.substr(j, 1));
	partial_value <<= 1;
      }
      partial_value >>= 1;
      value.m_value.push_back((limb_t)partial_value);
      partial_value = 0;
    }
    value.m_MSB = (cntr - 1)*NTL_ZZ_NBITS;
    value.m_MSB += GetMSBlimb_t(value.m_value.back());
    DEBUG("computed msb" << value.m_MSB);
    value.m_state = INITIALIZED;
    value.SetMSB();
    DEBUG("true msb" <<value.m_MSB);
    return value;
#else


#endif

  }

  //deprecated version needs renaming
  myZZ myZZ::BinaryStringToBigBinaryInt(const std::string& vin){ 
    myZZ ans;
    return ans.FromBinaryString(vin);
  }
  ///&&&a


  usint myZZ::GetDigitAtIndexForBase(usint index, usint base) const{

    usint digit = 0;
    usint newIndex = index; 
    for (usint i = 1; i < base; i = i*2)
      {
	digit += GetBitAtIndex(newIndex)*i;
	newIndex++;
      }
    return digit;

  }

  // returns the bit at the index into the binary format of the big integer, 
  // note that msb is 1 like all other indicies. 
  //TODO: this code could be massively simplified
  uschar myZZ::GetBitAtIndex(usint index) const{
    if(index<=0){
      std::cout<<"Invalid index \n";
      return 0;
    }
    else if (index > m_MSB)
      return 0;

#if 0
    limb_t result;
    sint idx =ceilIntByUInt(index)-1;//idx is the index of the limb array
    limb_t temp = this->m_value[idx];
    limb_t bmask_counter = index%m_limbBitLength==0? m_limbBitLength:index%m_limbBitLength;//bmask is the bit number in the 8 bit array
    limb_t bmask = 1;
    for(sint i=1;i<bmask_counter;i++)
      bmask<<=1;//generate the bitmask number
    result = temp&bmask;//finds the bit in  bit format
    result>>=bmask_counter-1;//shifting operation gives bit either 1 or 0
    return (uschar)result;
#else
    ZZ_limb_t result;
    const ZZ_limb_t *zlp = ZZ_limbs_get(*this); //get access to limb array
    sint idx =ceilIntByUInt(index)-1;//idx is the index of the limb array

    if (idx >= (this->size())){
      //std::cout <<"myZZ::GetBitAtIndex Warning idx > length"<<std::endl;
      return (uschar)0;
    }

    ZZ_limb_t temp = zlp[idx]; // point to correct limb
    ZZ_limb_t bmask_counter = index%NTL_ZZ_NBITS==0? NTL_ZZ_NBITS:index%NTL_ZZ_NBITS;//bmask is the bit number in the limb
    ZZ_limb_t bmask = 1;
    for(sint i=1;i<bmask_counter;i++)
      bmask<<=1;//generate the bitmask number
    result = temp&bmask;//finds the bit in  bit format
    result>>=bmask_counter-1;//shifting operation gives bit either 1 or 0
    return (uschar)result;
#endif
  }

  //optimized ceiling function after division by number of bits in the limb data type.
  usint myZZ::ceilIntByUInt( const ZZ_limb_t Number){
    //mask to perform bitwise AND
    static ZZ_limb_t mask = NTL_ZZ_NBITS-1;

    if(!Number)
      return 1;

    if((Number&mask)!=0)
      return (Number>>m_log2LimbBitLength)+1;
    else
      return Number>>m_log2LimbBitLength;
  }

  //adapter kit
  const myZZ& myZZ::zero() {return (ZZ::zero());}

  //palisade conversion methods
  usint myZZ::ConvertToUsint() const{
    bool dbg_flag = false;

    DEBUG("in myZZ::ConvertToUsint() this.size() "<<this->size());
    DEBUG("in myZZ::ConvertToUsint() this "<<*this);
    
 return (conv<usint>(*this)); }
  usint myZZ::ConvertToInt() const{
    bool dbg_flag = false;

    DEBUG("in myZZ::ConvertToInt() this.size() "<<this->size());
    DEBUG("in myZZ::ConvertToInt() this "<<*this);
    
 return (conv<usint>(*this)); }
  uint32_t myZZ::ConvertToUint32() const { return (conv<uint32_t>(*this));}

  uint64_t myZZ::ConvertToUint64() const{ return (conv<uint64_t>(*this));}
  float myZZ::ConvertToFloat() const{ return (conv<float>(*this));}
  double myZZ::ConvertToDouble() const{ return (conv<double>(*this));}
  long double myZZ::ConvertToLongDouble() const {
    std::cerr<<"can't convert to long double"<<std::endl; 
    return 0.0L;
  }

  std::ostream& operator<<(std::ostream& os, const myZZ& ptr_obj){
    bool dbg_flag = false;
    ZZ tmp = ptr_obj;
    DEBUG("in operator<< "<<tmp);

    os << tmp;
    return os;
  }
  
  
  const std::string myZZ::ToString() const
  {
    //todo Not sure if this string is safe, it may be ephemeral if not returned  by value.
    std::stringstream result("");
    result << *this;
    return result.str();
  }	

  myZZ myZZ::MultiplyAndRound(const myZZ &p, const myZZ &q) const
  {
    
    myZZ ans(*this);
    ans *= p;
    ans = ans.DivideAndRound(q);
    
    return ans;
    
  }
  myZZ myZZ::DivideAndRound(const myZZ &q) const 
  {
    bool dbg_flag = false;
    
    //check for garbage initialization and 0 condition
    //check for garbage initialization and 0 condition
    if(q==ZERO)
      throw std::logic_error("DivideAndRound() Divisor is zero");
    
    myZZ halfQ(q>>1);
    DEBUG("halfq "<<halfQ.ToString());
    
    if (*this < q) {
      if (*this <= halfQ)
	return myZZ(ZERO);
      else
	return myZZ(ONE);
    }
    //=============
    myZZ ans(0);
    myZZ rv(0);
    
    int f;
    
    DEBUG( "*this "<<this->ToString());
    DEBUG("q "<<q.ToString());
    
    
    DivRem(ans, rv, *this,q);
    
    //f = divqr_vect(ans, rv,  *this,  q);
    //if (f!= 0)
    ///throw std::logic_error("Divqr() error in DivideAndRound");
    
    //ans.NormalizeLimbs();
    //rv.NormalizeLimbs();
    
    ans.SetMSB();
    rv.SetMSB();
    DEBUG("ans "<<ans.ToString());
    DEBUG("rv "<<rv.ToString());
    DEBUG("ans "<<ans.ToString());
    DEBUG("rv "<<rv.ToString());
    //==============
    //Rounding operation from running remainder
    if (!(rv <= halfQ)) {
      ans += ONE;
      DEBUG("added1 ans "<<ans.ToString());
    }
    return ans;
  }
  
  
  //various operators on mixed operands
  
  myZZ myZZ::operator*(const myZZ_p &b) const {
    myZZ tmp;
    mul(tmp, *this, b._ZZ_p__rep);
    return tmp ;
  }
  
  myZZ& myZZ::operator*=(const myZZ_p &a) {
    *this = *this*(myZZ)a._ZZ_p__rep;
    return *this;
  }

  myZZ& myZZ::operator*=(const myZZ &a) {
    *this = *this*a;
    return *this;
  }


#if 0
  inline long myZZ::operator<(const myZZ_p& b) const
  { return b.Compare(*this) >= 0; };
  inline long myZZ::operator>(const myZZ_p& b) const
  { return b.Compare(*this) <= 0; };
  inline long myZZ::operator<=(const myZZ_p& b) const
  { return b.Compare(*this) > 0; }; 
  inline long myZZ::operator>=( const myZZ_p& b) const
  { return b.Compare(*this) < 0; };
  inline long myZZ::operator==(const myZZ_p& b) const
  { return b.Compare(*this) == 0; };
  inline long myZZ::operator!=(const myZZ_p& b) const
  { return b.Compare(*this) != 0; };
#endif


  //the following code is new serialize/deserialize code from
  // binint.cpp 
  // TODO: it has not been tested 
  // the array and the next
  // two functions convert a ubint in and out of a string of
  // characters the encoding is Base64-like: the first 5 6-bit
  // groupings are Base64 encoded, and the last 2 bits are A-D
  
  // Note this is, sadly, hardcoded for 32 bit integers and needs Some
  // Work to handle arbitrary sizes

  // precomputed shift amounts for each 6 bit chunk
  static const usint b64_shifts[] = { 0, 6, 12, 18, 24, 30 };
  static const usint B64MASK = 0x3F;

  // this for encoding...
  static char to_base64_char[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

  // and this for decoding...
  static inline unsigned int base64_to_value(char b64) {
    if( isupper(b64) )
      return b64 - 'A';
    else if( islower(b64) )
      return b64 - 'a' + 26;
    else if( isdigit(b64) )
      return b64 - '0' + 52;
    else if( b64 == '+' )
      return 62;
    else
      return 63;
  }

  /**
   * This function is only used for serialization
   *
   * The scheme here is to take each of the limb_ts in the
   * myZZ and turn it into 6 ascii characters. It's
   * basically Base64 encoding: 6 bits per character times 5 is the
   * first 30 bits. For efficiency's sake, the last two bits are encoded
   * as A,B,C, or D and the code is implemented as unrolled loops
   */
  const std::string myZZ::Serialize() const {

    std::string ans = "";
    //note limbs are now stored little endian in myZZ
    const ZZ_limb_t *zlp = ZZ_limbs_get(*this);
    for (auto i = 0; i<this->size(); ++i){
      ans += to_base64_char[((zlp[i]) >> b64_shifts[0]) & B64MASK];
      ans += to_base64_char[((zlp[i]) >> b64_shifts[1]) & B64MASK];
      ans += to_base64_char[((zlp[i]) >> b64_shifts[2]) & B64MASK];
      ans += to_base64_char[((zlp[i]) >> b64_shifts[3]) & B64MASK];
      ans += to_base64_char[((zlp[i]) >> b64_shifts[4]) & B64MASK];
      ans += (((zlp[i]) >> b64_shifts[5])&0x3) + 'A';
    }

    return ans;
  }

  /**
   * This function is only used for deserialization
   */

  const char * myZZ::Deserialize(const char *cp){
    clear(*this);

    vector<ZZ_limb_t> cv;

    while( *cp != '\0' && *cp != '|' ) {
      ZZ_limb_t converted =  base64_to_value(*cp++) << b64_shifts[0];
      converted |= base64_to_value(*cp++) << b64_shifts[1];
      converted |= base64_to_value(*cp++) << b64_shifts[2];
      converted |= base64_to_value(*cp++) << b64_shifts[3];
      converted |= base64_to_value(*cp++) << b64_shifts[4];
      converted |= ((*cp++ - 'A')&0x3) << b64_shifts[5];
      


      cv.push_back(converted);
    }
    ZZ_limbs_set(*this, cv.data(), cv.size());
    SetMSB();
    return cp;
  }

  

} // namespace NTL ends

