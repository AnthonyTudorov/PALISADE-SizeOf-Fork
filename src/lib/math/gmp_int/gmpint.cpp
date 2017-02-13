//LAYER 1 : PRIMITIVE DATA STRUCTURES AND OPERATIONS
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
 * big integers: ubint. Big integers are represented as arrays of
 * native usigned integers. The native integer type is supplied as a
 * template parameter.  Currently implementation based on uint32_t is
 * supported. One needs a native integer 2x the size of the chosen type for
 * certain math operations.
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

  myZZ::myZZ(const NTL::myZZ_p &a): ZZ(){*this = a._ZZ_p__rep;}

  myZZ::myZZ(NTL::ZZ &&a) : ZZ(a) {}
  myZZ::myZZ(const NTL::myZZ_p &&a): ZZ(){*this = a._ZZ_p__rep;}
  


  //this is the zero allocator for the palisade matrix class
  // std::function<unique_ptr<myZZ>> myZZ::Allocator = [](){
  //   return lbcrypto::make_unique<myZZ>();
  // };

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
  usint myZZ::GetMSBLimb_t( ZZ_limb_t x){
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
    bool dbg_flag = true;		// if true then print dbg output
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

    //parse out string 8 bits at a time into array of bytes
    vector<unsigned char> bytes;
    DEBUG("input string: "<<v);
    for (auto i = 0; i < len/sizeof(char); i+=sizeof(char)){
      std::string bits = v.substr(i, sizeof(char));
      DEBUG("i = "<<i<<" bits: "<<bits);
      int newlen = len-sizeof(char);
      size_t nbits;
      
      unsigned char byte = std::stoi(bits, &nbits, 2);
      DEBUG("byte = "<<byte);
      bytes.push_back(byte);
      v = v.substr(i+sizeof(char), newlen);
    }
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
  usint myZZ::ConvertToUsint() const{ return (conv<usint>(*this)); }
  usint myZZ::ConvertToInt() const{ return (conv<int>(*this)); }
  uint32_t myZZ::ConvertToUint32() const { return (conv<uint32_t>(*this));}

  uint64_t myZZ::ConvertToUint64() const{ return (conv<uint64_t>(*this));}
  float myZZ::ConvertToFloat() const{ return (conv<float>(*this));}
  double myZZ::ConvertToDouble() const{ return (conv<double>(*this));}
  long double myZZ::ConvertToLongDouble() const {
    std::cerr<<"can't convert to long double"<<std::endl; 
    return 0.0L;
  }
  
  const std::string myZZ::ToString() const
  {
    //todo Not sure if this string is safe, it may be ephemeral if not returned  by value.
    std::stringstream result("");
    result << *this;
    return result.str();
  }	


  //various operators on mixed operands
  inline myZZ operator*(const myZZ_p &b) const {
    myZZ_p tmp;
    mul(tmp, *this, b._ZZ_p__rep);
    return tmp ;
  }
  inline myZZ& operator*=(const myZZ_p &a) {
    *this = *this*a._ZZ_p__rep;
    return *this;
  }


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
   * ubint and turn it into 6 ascii characters. It's
   * basically Base64 encoding: 6 bits per character times 5 is the
   * first 30 bits. For efficiency's sake, the last two bits are encoded
   * as A,B,C, or D and the code is implemented as unrolled loops
   */
  const std::string myZZ::Serialize() const {

    std::string ans = "";
    //const uint_type *fromP;

    //	sint siz = (m_MSB%m_uintBitLength==0&&m_MSB!=0) ? (m_MSB/m_uintBitLength) : ((sint)m_MSB/m_uintBitLength +1);
    //int i;
    //note limbs are now stored little endian in ubint
    //for(i=m_nSize-1, fromP=m_value+i ; i>=m_nSize-siz ; i--,fromP--) {
    for (auto fromP = this->rep.begin(); fromP!=this->rep.end(); fromP++){
      ans += to_base64_char[((*fromP) >> b64_shifts[0]) & B64MASK];
      ans += to_base64_char[((*fromP) >> b64_shifts[1]) & B64MASK];
      ans += to_base64_char[((*fromP) >> b64_shifts[2]) & B64MASK];
      ans += to_base64_char[((*fromP) >> b64_shifts[3]) & B64MASK];
      ans += to_base64_char[((*fromP) >> b64_shifts[4]) & B64MASK];
      ans += (((*fromP) >> b64_shifts[5])&0x3) + 'A';
    }

    return ans;
  }

  /**
   * This function is only used for deserialization
   */

  const char * myZZ::Deserialize(const char *cp){
    clear(*this);

    while( *cp != '\0' && *cp != '|' ) {
      limb_t converted =  base64_to_value(*cp++) << b64_shifts[0];
      converted |= base64_to_value(*cp++) << b64_shifts[1];
      converted |= base64_to_value(*cp++) << b64_shifts[2];
      converted |= base64_to_value(*cp++) << b64_shifts[3];
      converted |= base64_to_value(*cp++) << b64_shifts[4];
      converted |= ((*cp++ - 'A')&0x3) << b64_shifts[5];
      this->rep().push_back(converted);
    }

    SetMSB();
    m_state = INITIALIZED;

    return cp;
  }

  

} // namespace NTL ends

