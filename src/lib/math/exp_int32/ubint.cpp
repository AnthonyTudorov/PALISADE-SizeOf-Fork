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


#include "ubint.h"

#include <iostream>
#include <fstream>
#include "time.h"
#include <chrono>

#include "../../utils/debug.h"


namespace exp_int32 {

  //constant static member variable initialization of 0
  template<typename limb_t>
  const ubint<limb_t> ubint<limb_t>::ZERO = ubint(0);

  //constant static member variable initialization of 1
  template<typename limb_t>
  const ubint<limb_t> ubint<limb_t>::ONE = ubint(1);

  //constant static member variable initialization of 2
  template<typename limb_t>
  const ubint<limb_t> ubint<limb_t>::TWO = ubint(2);

  //constant static member variable initialization of 3
  template<typename limb_t>
  const ubint<limb_t> ubint<limb_t>::THREE = ubint(3);

  //constant static member variable initialization of 4
  template<typename limb_t>
  const ubint<limb_t> ubint<limb_t>::FOUR = ubint(4);

  //constant static member variable initialization of 5
  template<typename limb_t>
  const ubint<limb_t> ubint<limb_t>::FIVE = ubint(5);

  //MOST REQUIRED STATIC CONSTANTS INITIALIZATION

  //constant static member variable initialization of m_uintBitLength which is equal to number of bits in the unit data type
  //permitted values: 8,16,32
  template<typename limb_t>
  //const uschar ubint<limb_t>::m_uintBitLength = UIntBitWidth<limb_t>::value;
const usint ubint<limb_t>::m_limbBitLength = sizeof(limb_t)*8;

  //constant static member variable initialization of m_logUintBitLength which is equal to log of number of bits in the unit data type
  //permitted values: 3,4,5
  template<typename limb_t>
  //const uschar ubint<limb_t>::m_log2LimbBitLength = LogDtype<limb_t>::value;
const usint ubint<limb_t>::m_log2LimbBitLength = Log2<m_limbBitLength>::value;

  //constant static member variable initialization of m_nSize which is size of the array of unit data type
  //template<typename limb_t>
  //const usint ubint<limb_t>::m_nSize = BITLENGTH%m_limbBitLength==0 ? BITLENGTH/m_limbBitLength : BITLENGTH/m_limbBitLength + 1;

  //constant static member variable initialization of m_uintMax which is maximum value of unit data type
  template<typename limb_t>
const usint ubint<limb_t>::m_MaxLimb = std::numeric_limits<limb_t>::max();

  //optimized ceiling function after division by number of bits in the limb data type.
  template<typename limb_t>
  usint ubint<limb_t>::ceilIntByUInt(const limb_t Number){
    //mask to perform bitwise AND
    static limb_t mask = m_limbBitLength-1;

    if(!Number)
      return 1;

    if((Number&mask)!=0)
      return (Number>>m_log2LimbBitLength)+1;
    else
      return Number>>m_log2LimbBitLength;
  }

  //CONSTRUCTORS
  template<typename limb_t>
  ubint<limb_t>::ubint()
  {
    // builds an uninitialized ubint
    // mostly used internal to the class
    bool dbg_flag = false;		// if true then print dbg output
    m_MSB=0;// initialize

    DEBUG("ctor()");
    DEBUG( "maxlimb "<<m_MaxLimb);

    DEBUG( "initial size "<< m_value.size());

    m_state = GARBAGE;
  }
  
  //todo: figure out how to share code between the following three ctors
  // https://isocpp.org/wiki/faq/templates#template-specialization
  template<typename limb_t>
  ubint<limb_t>::ubint(usint init){
    bool dbg_flag = false;		// if true then print dbg output

    //setting the MSB
    usint msb = 0;

    msb = GetMSB32(init); //todo: this really should be renamed to GetMSBUsint or something.
    DEBUG("ctor("<<init<<")");
    DEBUG( "msb " <<msb);
    DEBUG( "maxlimb "<<m_MaxLimb);

    DEBUG( "initial size "<< m_value.size());

    if (init <= m_MaxLimb) {
      //init fits in first limb entry
      m_value.clear(); // make sure it is empty to start
      m_value.push_back((limb_t)init);
      DEBUG("single limb size now "<<m_value.size());
    } else {
      usint ceilInt = ceilIntByUInt(msb);
      //setting the values of the array
      m_value.clear(); // make sure it is empty to start
      this->m_value.reserve(ceilInt);
      for(usint i= 0;i<ceilInt;++i){
        this->m_value.at(i) = (limb_t)init;
        init>>=m_limbBitLength;
      }
      DEBUG("mulit limb ceilIntByUInt ="<<ceilInt);
    }
    this->m_MSB = msb;
    m_state = INITIALIZED;

    DEBUG("final msb ="<<msb);
  }

  template<typename limb_t>
  ubint<limb_t>::ubint(sint sinit){
    bool dbg_flag = false;		// if true then print dbg output

    if (sinit<0)
      throw std::logic_error("ubint() initialized iwth signed number");		

    usint init = (usint) sinit;

    //setting the MSB
    usint msb = 0;

    msb = GetMSB32(init); //todo: this really should be renamed to GetMSBusint or something.
    DEBUG("ctor("<<init<<")");
    DEBUG( "msb " <<msb);
    DEBUG( "maxlimb "<<m_MaxLimb);

    DEBUG( "initial size "<< m_value.size());

    if (init <= m_MaxLimb) {
      //init fits in first limb entry
      m_value.clear(); // make sure it is empty to start
      m_value.push_back((limb_t)init);
      DEBUG("single limb size now "<<m_value.size());
    } else {
      usint ceilInt = ceilIntByUInt(msb);
      //setting the values of the array
      m_value.clear(); // make sure it is empty to start
      this->m_value.reserve(ceilInt);
      for(usint i= 0;i<ceilInt;++i){
        this->m_value.at(i) = (limb_t)init;
        init>>=m_limbBitLength;
      }
      DEBUG("mulit limb ceilIntByUInt ="<<ceilInt);
    }
    this->m_MSB = msb;
    m_state = INITIALIZED;

    DEBUG("final msb ="<<msb);
  }

  template<typename limb_t>
  ubint<limb_t>::ubint(uint64_t init){
    bool dbg_flag = false;		// if true then print dbg output

    //setting the MSB
    usint msb = 0;

    msb = GetMSB64(init);
    DEBUG("ctor(uint64_t:"<<init<<")");
    DEBUG( "msb " <<msb);
    DEBUG( "maxlimb "<<m_MaxLimb);

    DEBUG( "initial size "<< m_value.size());

    if (init <= m_MaxLimb) {
      //init fits in first limb entry
      m_value.clear(); // make sure it is empty to start
      m_value.push_back((limb_t)init);
      DEBUG("single limb size now "<<m_value.size());
    } else {
      usint ceilInt = ceilIntByUInt(msb);
      DEBUG("mulit limb ceilIntByUInt ="<<ceilInt);
      //setting the values of the array
      this->m_value.clear(); // make sure it is empty to start
      this->m_value.reserve(ceilInt);
      for(usint i= 0;i<ceilInt;++i){
	DEBUG("i " << i);
	m_value.push_back((limb_t)init);
	//DEBUG("value  " << this->m_value.at(i));
        init>>=m_limbBitLength;
	DEBUG("init now  " << init);
      }

    }
    this->m_MSB = msb;
    m_state = INITIALIZED;

    DEBUG("final msb ="<<msb);
  
  }

  template<typename limb_t>
  ubint<limb_t>::ubint(int64_t sinit){
    bool dbg_flag = false;		// if true then print dbg output
    if (sinit<0)
      throw std::logic_error("ubint() initialized with negative number");	

    uint64_t init = (uint64_t)sinit;

    //setting the MSB
    usint msb = 0;

    msb = GetMSB64(init);
    DEBUG("ctor(uunt64_t:"<<init<<")");
    DEBUG( "msb " <<msb);
    DEBUG( "maxlimb "<<m_MaxLimb);

    DEBUG( "initial size "<< m_value.size());

    if (init <= m_MaxLimb) {
      //init fits in first limb entry
      m_value.clear(); // make sure it is empty to start
      m_value.push_back((limb_t)init);
      DEBUG("single limb size now "<<m_value.size());
    } else {
      usint ceilInt = ceilIntByUInt(msb);
      //setting the values of the array
      this->m_value.clear(); // make sure it is empty to start
      this->m_value.reserve(ceilInt);
      for(usint i= 0;i<ceilInt;++i){
        this->m_value.at(i) = (limb_t)init;
        init>>=m_limbBitLength;
      }
      DEBUG("mulit limb ceilIntByUInt ="<<ceilInt);
    }
    this->m_MSB = msb;
    m_state = INITIALIZED;

    DEBUG("final msb ="<<msb);
  
}
  // ctor(string)
  template<typename limb_t>
  ubint<limb_t>::ubint(const std::string& str){
	    bool dbg_flag = false;		// if true then print dbg output

    DEBUG("ctor(str "<<str<<")");
    //memory allocation step
    //m_value = new limb_t[m_nSize]; //todosmartpointer
    //setting the array values from the string

    AssignVal(str);
    //state set
    m_state = INITIALIZED;
  	DEBUG("final msb ="<<this->m_MSB);
  }

  //copy constructor
  template<typename limb_t>
  ubint<limb_t>::ubint(const ubint& rhs){
    bool dbg_flag = false;		// if true then print dbg output

    DEBUG("copy ctor(&bint)");

    //memory allocation step
    this->m_MSB=rhs.m_MSB; //copy MSB

    //copy values
    this->m_value = rhs.m_value;
    //set state
    m_state = rhs.m_state;
    DEBUG("final msb ="<<this->m_MSB);
  }

    //move copy cconstructor
  template<typename limb_t>
  ubint<limb_t>::ubint(ubint &&rhs){
      bool dbg_flag = false;		// if true then print dbg output

    DEBUG("move copy ctor(&bint)");

    //copy MSB
    m_MSB = rhs.m_MSB;

    //swap (move) assignment
    m_value.swap(rhs.m_value);

    //set state
    m_state = rhs.m_state;

    //remove ref from bigInteger
    if (rhs.m_value.size()>0)
      rhs.m_value.clear(); //clears value
    //rhs.m_value.shrink_to_fit(); //clears value with reallocation.
  }

  //TODO figure out what this is for
  template<typename limb_t>
  std::function<unique_ptr<ubint<limb_t>>()> ubint<limb_t>::Allocator = [=](){
    return lbcrypto::make_unique<ubint<limb_t>>();
  };

  template<typename limb_t>
  ubint<limb_t>::~ubint()
  {	
    bool dbg_flag = false;		// if true then print dbg output

    DEBUG("dtor() m_value.size is "<<m_value.size());

    //memory deallocation
	  if (m_value.size()>0)
	    m_value.clear(); //clears value
    DEBUG("leaving dtor");
  }

  /**
   *Converts the ubint to a usint unsigned integer or returns the first
   *m_limbBitLength bits of the ubint.  Splits the ubint into bit length of uint data
   *type and then uses shift and add to form the  unsigned
   *integer.
   */
  template<typename limb_t>
  usint ubint<limb_t>::ConvertToUsint() const{
	  usint result;
	  if (m_value.size()==0)
	    throw std::logic_error("ConvertToUsint() on uninitialized bint");		       
	  if (sizeof(limb_t)>=sizeof(usint)){
		  result = m_value.at(0);
		  return result;
	  } else {
		  //Case where limb_t is less bits than usint
		  //set num to number of equisized chunks
		  //usint num = (8*sizeof(usint)) / m_limbBitLength;

		  usint ceilInt = ceilIntByUInt(m_MSB);
		  //copy the values by shift and add
		  for (usint i = 0; i < ceilInt; i++){
			  result += (this->m_value.at(i) << (m_limbBitLength*i));
		  }
		  return result;
	  }
  }

  template<typename limb_t>
  usint ubint<limb_t>::ConvertToInt() const{  //todo: deprecate this to Usint
   return this->ConvertToUsint();
  }

  // the following conversions all throw 
  //Converts the ubint to uint32_t using the std library functions.
  template<typename limb_t>
  uint32_t ubint<limb_t>::ConvertToUint32() const{
    return std::stoul(this->ToString());
  }

    //Converts the ubint to uint64_t using the std library functions.
  template<typename limb_t>
  uint64_t ubint<limb_t>::ConvertToUint64() const{
    return std::stoull(this->ToString());
  }

  //Converts the ubint to float using the std library functions.
  template<typename limb_t>
  float ubint<limb_t>::ConvertToFloat() const{
    return std::stof(this->ToString());
  }

  //Converts the ubint to double using the std library functions.
  template<typename limb_t>
  double ubint<limb_t>::ConvertToDouble() const{
    return std::stod(this->ToString());
  }

  //Converts the ubint to long double using the std library functions.
  template<typename limb_t>
  long double ubint<limb_t>::ConvertToLongDouble() const{
    return std::stold(this->ToString());
  }

  //copy allocator
  template<typename limb_t>
  const ubint<limb_t>&  ubint<limb_t>::operator=(const ubint &rhs){
	if(this!=&rhs){
      this->m_MSB=rhs.m_MSB;
      this->m_state = rhs.m_state;
      //copy vector
      this->m_value=rhs.m_value;
    }
    return *this;
  }
  // move copy allocator
  template<typename limb_t>
  const ubint<limb_t>&  ubint<limb_t>::operator=(ubint &&rhs){

    if(this!=&rhs){
      this->m_MSB = rhs.m_MSB;
      this->m_state = rhs.m_state;
      this->m_value.swap(rhs.m_value);
      //remove ref from bigInteger
      if (rhs.m_value.size()>0)
        rhs.m_value.clear();  //clears value
      //rhs.m_value.shrink_to_fit(); //clears value with reallocation.
    }
    return *this;
  }

  /**
   *	Left Shift is done by splitting the number of shifts into
   *1. Multiple of the bit length of limb data type.
   *	Shifting is done by the shifting the limb type numbers.
   *2. Shifts between 1 to bit length of limb data type.
   *   Shifting is done by using bit shift operations and carry over propagation.
   */
  template<typename limb_t>
  ubint<limb_t>  ubint<limb_t>::operator<<(usint shift) const{
    bool dbg_flag = false;
    //garbage check
	  if(m_state==State::GARBAGE)
		  throw std::logic_error("<< on uninitialized bint");
	  //trivial case
	  if(this->m_MSB==0)
		  return ubint(ZERO);

	  ubint ans(*this);

	  //compute the number of whole limb shifts
	  usint shiftByLimb = shift>>m_log2LimbBitLength;


	  //compute the remaining number of bits to shift
	  limb_t remainingShift = (shift&(m_limbBitLength-1));

	  DEBUG("l2lbl "<< m_log2LimbBitLength);
	  DEBUG("totalshift "<< shift);
	  DEBUG("shiftByLimb "<<shiftByLimb);
	  DEBUG("remainingShift "<<remainingShift);
	  DEBUG("size "<<m_value.size());

	  //first shift by the # remainingShift bits
	  if(remainingShift!=0){
		  limb_t oFlow = 0;
		  Dlimb_t temp = 0;
		  sint i;

		  DEBUG("m_MSB "<<m_MSB);
		  DEBUG("ilimit "<<ceilIntByUInt(m_MSB));


		  for(i=0; i<ceilIntByUInt(m_MSB); ++i){
	  	  DEBUG("bit shift ");
		    temp = ans.m_value.at(i);
			  temp <<=remainingShift;
			  ans.m_value.at(i) = (limb_t)temp + oFlow;
			  oFlow = temp >> m_limbBitLength;
		  }

		  if(oFlow) {//there is an overflow set of bits.
		    if (i<ans.m_value.size()){
		      ans.m_value.at(i) = oFlow;
		    } else {
		      ans.m_value.push_back(oFlow);
		    }
		  }
		  ans.m_MSB += remainingShift;

	  }

	  if(shiftByLimb!=0){
	    usint currentSize = ans.m_value.size();
	    DEBUG("CURRENT SIZE "<<currentSize);
	    ans.m_value.resize(currentSize+shiftByLimb); // allocate more storage
	          DEBUG("resize is  "<<ans.m_value.size());
	    for (sint i = currentSize-1; i>=0; i-- ) {  //shift limbs required # of indicies
	      DEBUG("to : "<<i+shiftByLimb<< "from "<<i );
	      ans.m_value.at(i+shiftByLimb) = ans.m_value.at(i);
	    }
	    //zero out the 'shifted in' limbs
	    for (sint i = shiftByLimb -1 ; i>=0; i-- ) {
	      DEBUG("clear : "<<i);
	      ans.m_value.at(i) = 0;
	    }
	    DEBUG("new size is  "<<ans.m_value.size());

	  }

	  ans.m_MSB += shiftByLimb*m_limbBitLength;
	  DEBUG("final MSB "<<ans.m_MSB);
	  //ans.SetMSB();
	  //DEBUG("final MSB check "<<ans.m_MSB);
	  return ans;

  }

  /**
   *	Left Shift is done by splitting the number of shifts into
   *1. Multiple of the bit length of limb data type.
   *	Shifting is done by the shifting the limb type numbers.
   *2. Shifts between 1 to bit length of limb data type.
   *   Shifting is done by using bit shift operations and carry over propagation.
   */
  template<typename limb_t>
  const ubint<limb_t>&  ubint<limb_t>::operator<<=(usint shift){
    if(m_state==State::GARBAGE)
      throw std::logic_error("Value not initialized");

    if(this->m_MSB==0) {
      return *this;
    } else {
      *this = *this << shift;
      return *this;
    }
  }

  /**Right Shift is done by splitting the number of shifts into
   *1. Multiple of the bit length of limb data type.
   *	Shifting is done by the shifting the limb type numbers in the array to the right.
   *2. Shifts between 1 to bit length of limb data type.
   *   Shifting is done by using bit shift operations and carry over propagation.
   */
  template<typename limb_t>
  ubint<limb_t>  ubint<limb_t>::operator>>(usint shift) const{
    bool dbg_flag = false;
	  //garbage check
	  if(m_state==State::GARBAGE)
		  throw std::logic_error("Value not initialized");

	  //trivial cases
	  if(this->m_MSB==0 || this->m_MSB <= shift)
		  return ubint(0);


	  ubint ans(*this);
	  //compute the number of whole limb shifts
	  usint shiftByLimb = shift>>m_log2LimbBitLength;

	  //compute the remaining number of bits to shift
	  limb_t remainingShift = (shift&(m_limbBitLength-1));


	  DEBUG("l2lbl "<< m_log2LimbBitLength);
	  DEBUG("totalshift "<< shift);
	  DEBUG("shiftByLimb "<<shiftByLimb);
	  DEBUG("remainingShift "<<remainingShift);
	  DEBUG("size "<<m_value.size());

	  //first shift by the number of whole limb shifts
	  if(shiftByLimb!=0){

	    if (shiftByLimb >ans.m_value.size())
	      DEBUG("LOGIC ERROR size is " <<ans.m_value.size());


	    for(auto i =  shiftByLimb; i < ans.m_value.size(); ++i){
	      DEBUG("limb shift ");
	      ans.m_value.at(i-shiftByLimb) = ans.m_value.at(i);
	    }
	    //zero out upper  "shifted in" limbs
	    for(usint i = 0; i< shiftByLimb; ++i){
	      DEBUG("limb zereo");
	      ans.m_value.pop_back();
	    }

	    //msb adjusted to show the shifts
	    ans.m_MSB -= shiftByLimb<<m_log2LimbBitLength;

	  }

	  //remainderShift bit shifts
	  if(remainingShift!=0){

		  limb_t overFlow = 0;
		  limb_t oldVal;
		  limb_t maskVal = (1<<(remainingShift))-1;
		  limb_t compShiftVal = m_limbBitLength- remainingShift;

		  usint startVal = ceilIntByUInt(ans.m_MSB);
		  //perform shifting by bits by calculating the overflow
		  //oveflow is added after the shifting operation

		  DEBUG("maskVal "<< maskVal);
		  DEBUG("startVal "<< startVal);
		  DEBUG("compShiftVal " << compShiftVal);

		  for(sint i = startVal -1 ; i>=0;i--){
	  	  DEBUG("bit shift "<<i);
			  oldVal = ans.m_value.at(i);
			  ans.m_value.at(i) = (ans.m_value.at(i)>>remainingShift) + overFlow;

			  overFlow = (oldVal &  maskVal);
			  overFlow <<= compShiftVal ;
		  }

		  ans.m_MSB -= remainingShift;

	  }

	  //go through the mslimbs and pop off any zero limbs we missed
	  for (usint i = ans.m_value.size()-1; i >= 0; i--){
	    if (!ans.m_value.at(i)) {
	      ans.m_value.pop_back();
	      //std::cout<<"popped "<<std::endl;
	    } else {
	      break;
	    }
	  }
	  DEBUG("final MSB "<<ans.m_MSB);
	  ans.SetMSB();
	  DEBUG("final MSB check "<<ans.m_MSB);
	  return ans;
  }


  /**Right Shift is done by splitting the number of shifts into
   *1. Multiple of the bit length of limb data type.
   *	Shifting is done by the shifting the limb type numbers in the array to the right.
   *2. Shifts between 1 to bit length of limb data type.
   *   Shifting is done by using bit shift operations and carry over propagation.
   */
  template<typename limb_t>
  ubint<limb_t>&  ubint<limb_t>::operator>>=(usint shift){
    //check for garbage
    if(m_state==State::GARBAGE)
      throw std::logic_error("Value not initialized");

    if(this->m_MSB==0 )
      return *this;
    else if(this->m_MSB<=shift){
      *this = ZERO;
      return *this;
    } else {
    	*this = *this >> shift;
    	return *this;
    }
  }


  template<typename limb_t>
  void ubint<limb_t>::PrintLimbsInDec() const{
    bool dbg_flag = false;		// if true then print dbg output
    if (m_state == GARBAGE) {
      std::cout <<"bint uninitialised"<<std::endl;
    } else {
      DEBUG("PrintLimbsInDec size "<< m_value.size());
      for (auto i = 0; i < m_value.size(); i++){
        std::cout<< i << ":"<< m_value.at(i);
        std::cout <<std::endl;
      }
      std::cout<<"MSB: "<<m_MSB << std::endl;
    }
  }

  template<typename limb_t>
  void ubint<limb_t>::PrintLimbsInHex() const{
    bool dbg_flag = false;   // if true then print dbg output
     if (m_state == GARBAGE) {
       std::cout <<"bint uninitialised"<<std::endl;
     } else {
       DEBUG("PrintLimbsInHex size "<< m_value.size());
       for (auto i = 0; i < m_value.size(); i++){
         std::cout<< i << ": 0x"<< std::hex << m_value.at(i) << std::dec <<std::endl;
       }
       std::cout<<"MSB: "<<m_MSB << std::endl;
     }
  }

  template<typename limb_t>
  usint ubint<limb_t>::GetMSB() {
    return m_MSB;
  }

  template<typename limb_t>
  usint ubint<limb_t>::GetNumberOfLimbs() const {
    return m_value.size();
  }

  template<typename limb_t>
  const std::string ubint<limb_t>::GetState()const{

    switch(m_state) {
    case INITIALIZED:
      return "INITIALIZED";
      break;
    case GARBAGE:
      return "GARBAGE";
      break;
    default:
      throw std::logic_error("GetState() on uninitialized bint"); //shouldn't happen
    }
  }

  /** Addition operation:
   *  Algorithm used is usual school book sum and carry-over, expect for that radix is 2^m_bitLength.
   */
  template<typename limb_t>
  ubint<limb_t> ubint<limb_t>::Add(const ubint& b) const{
	bool dbg_flag = false;		// if true then print dbg output
    //two operands A and B for addition, A is the greater one, B is the smaller one
	  DEBUG("Add");
    const ubint* A = NULL;
    const ubint* B = NULL;
    //check for garbage initializations
    if(this->m_state==GARBAGE){
    	throw std::logic_error("Add() to uninitialized bint");
    }
    if(b.m_state==GARBAGE){
    	throw std::logic_error("Add() from uninitialized bint");
    }

    //Assignment of pointers, A assigned the higher value and B assigned the lower value
    if(*this>b){
      A = this; B = &b;
    }
    else {A = &b; B = this;}

    if(B->m_MSB==0)
      return ubint(*A);

    ubint result;
    result.m_state = INITIALIZED;

    DEBUG("result initial size "<<result.m_value.size());
    //overflow variable
    Dlimb_t ofl=0;

    //position from A to end addition
    limb_t ceilIntA = ceilIntByUInt(A->m_MSB);
    //position from B to end addition
    limb_t ceilIntB = ceilIntByUInt(B->m_MSB);

    usint i;//

    DEBUG("ceilIntA "<<ceilIntA);
    DEBUG("ceilIntB "<<ceilIntB);

    DEBUG("size a "<< A->m_value.size());
    DEBUG("size b "<< A->m_value.size());



    for(i=0; i<ceilIntB; ++i){ //loop over limbs low to high till you reach the end of the smaller one
      DEBUG("i "<<i);
      DEBUG("ofl "<<ofl);
      DEBUG("Alimb "<<A->m_value.at(i));
      DEBUG("Blimb "<<B->m_value.at(i));

      ofl =(Dlimb_t)A->m_value.at(i)+ (Dlimb_t)B->m_value.at(i)+ofl;//sum of the two int and the carry over
      DEBUG("newofl "<<ofl);
      result.m_value.push_back((limb_t)ofl);
      ofl>>=m_limbBitLength;//current overflow
      DEBUG("shiftofl "<<ofl);
    }

    // we have an overflow at the end
    if(ofl){
    	for(; i<ceilIntA; ++i){ //keep looping over the remainder of the larger value
    	  DEBUG("oi "<<i);
    	  ofl = (Dlimb_t)A->m_value.at(i)+ofl;//sum of the two int and the carry over

    		result.m_value.push_back((limb_t)ofl);
    		ofl>>=m_limbBitLength;//current overflow
    	}

    	if(ofl){//in the end if overflow is set it indicates MSB is one greater than the one we started with
    	  DEBUG("push(1)");
    	  result.m_value.push_back(1);
    	}
    } else { //there is no overflow at the end
    	for(; i<ceilIntA; ++i){
    		DEBUG("push "<<i);
    	  result.m_value.push_back(A->m_value.at(i));
    	}
    }
    result.SetMSB();//Set the MSB.


	  DEBUG("final MSB "<<result.m_MSB);

    return result;
  }

  /** Sub operation:
   *  Algorithm used is usual school book borrow and subtract, except for that radix is 2^m_bitLength.
   */
  template<typename limb_t>
  ubint<limb_t> ubint<limb_t>::Sub(const ubint& b) const{
    bool dbg_flag = false;
    DEBUG("Sub");
    //check for garbage initialization
    if(this->m_state==GARBAGE){
      throw std::logic_error("Sub() to uninitialized bint");
    }
    if(b.m_state==GARBAGE){
      throw std::logic_error("Sub() to uninitialized bint");
    }
    //return 0 if b is higher than *this as there is no support for negative number
    if(!(*this>b)){
      DEBUG("in Sub, b > a return zero");
      return std::move(ubint(ZERO));
    }
    int cntr=0,current=0;

    ubint result(*this);

    DEBUG ("result starts out");
    if (dbg_flag){
      result.PrintLimbsInDec();
    }
    //array position in A to end substraction (a is always larger than b now)
    int endValA = ceilIntByUInt(this->m_MSB);
    //array position in B to end substraction
    int endValB = ceilIntByUInt(b.m_MSB);

    if (dbg_flag){
      std::cout<<"a "<<std::endl;
      this->PrintLimbsInHex();
      std::cout<<"b "<<std::endl;
      b.PrintLimbsInHex();
    }

    for(sint i=0; i<endValB; ++i){
      DEBUG ("limb  "<<i);
      DEBUG ("a limb "<<this->m_value.at(i));
      DEBUG ("res limb "<<result.m_value.at(i));
      DEBUG ("b limb "<<b.m_value.at(i));
      if(result.m_value.at(i)<b.m_value.at(i)){ //carryover condition need to borrow from higher limbs.
        DEBUG ("borrow at "<<i);
        current=i;
        cntr = current+1;
        //find the first nonzero limb
        if (cntr>result.m_value.size()){
          std::cout<<"error seek past end of result "<<std::endl;
        }
        while(result.m_value.at(cntr)==0){
          DEBUG("FF at cntr" <<cntr);
          result.m_value.at(cntr)=m_MaxLimb; //set all the zero limbs to all FFs (propagate the 1)
          cntr++;
        }
        DEBUG("decrement at " << cntr);
        result.m_value.at(cntr)--; // and eventually borrow 1 from the first nonzero limb we find
        DEBUG("sub with borrow at " <<i);
        result.m_value.at(i)=result.m_value.at(i)+(m_MaxLimb - b.m_value.at(i)) +1; // and add the it to the current limb
      } else {       //usual subtraction condition
        DEBUG("sub no borrow at " <<i);
        result.m_value.at(i)=result.m_value.at(i)- b.m_value.at(i);
      }
      DEBUG ("res limb "<<i<<" finally "<<result.m_value.at(i));

    }

//    while(result.m_value[endValA]==0){
//      endValA++;
//    }
    //reset the MSB after subtraction
    //result.m_MSB = (m_value.size()-endValA-1)*m_limbBitLength + GetMSBlimb_t(result.m_value[endValA]);

    //go through the mslimbs and pop off any zero limbs
    for (usint i = result.m_value.size()-1; i >= 0; i--){
      if (!result.m_value.at(i)) {
	result.m_value.pop_back();
	//std::cout<<"popped "<<std::endl;
      } else {
	break;
      }
    }
    
    result.SetMSB();
    DEBUG("result msb now "<<result.m_MSB);
    //return the result
    DEBUG ("Returning");
    return std::move(result);

  }

  /** Multiply operation:
   *  Algorithm used is usual school book shift and add after multiplication, except for that radix is 2^m_bitLength.
   */
  template<typename limb_t>
  ubint<limb_t> ubint<limb_t>::Mul(const ubint& b) const{
    bool dbg_flag = false;
    DEBUG("Mul");
	
    ubint ans(ZERO);
    //check for garbage initialized objects
    if(b.m_MSB==0 || b.m_state==GARBAGE ||this->m_state==GARBAGE || this->m_MSB==0){
      return ans;
    }
    //check for trivial condtions
    if(b.m_MSB==1)
      return ubint(*this);

    if(this->m_MSB==1)
      return std::move(ubint(b)); //todo check this? don't think standard move is what we want.
	
    //position of B in the array where the multiplication should start
    limb_t ceilLimb = b.m_value.size();
    //Multiplication is done by getting a limb_t from b and multiplying it with *this
    //after multiplication the result is shifted and added to the final answer

    usint nSize = this->m_value.size();
    for(sint i= 0;i< b.m_value.size();++i){
      DEBUG("i "<<i);
      ubint tmp2;

      //ans += (this->MulIntegerByLimb(b.m_value.at(i)))<<=(i)*m_limbBitLength;
      usint tmp1 = (i)*m_limbBitLength;
      DEBUG("tmp1 "<<tmp1);
      tmp2 = (this->MulIntegerByLimb(b.m_value.at(i))) <<= tmp1;
      DEBUG("tmp2 "<<tmp2.ToString());
      ans += tmp2;

      DEBUG("ans now "<<ans.ToString());
    }
    
    return ans;
  }



  template<typename limb_t>
  const ubint<limb_t>& ubint<limb_t>::operator+=(const ubint &b){
    *this = *this+b;
    return *this;
  }

  template<typename limb_t>
  const ubint<limb_t>& ubint<limb_t>::operator-=(const ubint &b){
    *this = *this-b;
    return *this;
  }

  template<typename limb_t>
  const ubint<limb_t>& ubint<limb_t>::operator*=(const ubint &b){
    *this = *this*b;
    return *this;
  }

  template<typename limb_t>
  const ubint<limb_t>& ubint<limb_t>::operator/=(const ubint &b){
    *this = *this/b;
    return *this;
  }

  template<typename limb_t>
  const ubint<limb_t>& ubint<limb_t>::operator%=(const ubint &b){
    *this = *this%b;
    return *this;
  }


  /** Multiply operation helper function:
   *  Algorithm used is usual school book multiplication.
   *  This function is used in the Multiplication of two ubint objects
   */
  template<typename limb_t>
  ubint<limb_t> ubint<limb_t>::MulIntegerByLimb(limb_t b) const{
    bool dbg_flag = false;
    DEBUG("MulIntegerByLimb");
    if(this->m_state==GARBAGE)
      throw std::logic_error("MulIntegerByLimb() of uninitialized bint");
    if(b==0 || this->m_MSB==0)
      return ubint(ZERO);

    ubint ans;
    //position in the array to start multiplication
    //
    usint endVal = this->m_value.size();
    DEBUG("endVal"<<endVal);
    //variable to capture the overflow
    Dlimb_t temp=0;
    //overflow value
    limb_t ofl=0;
    sint i= 0;

    DEBUG("mibl A:"<<this->ToString() );
    DEBUG("mibl B:"<<b );
    DEBUG("ans.size() now " <<ans.m_value.size());
    if (dbg_flag)
      ans.PrintLimbsInDec();
    for(;i<endVal ;++i){
      DEBUG("mullimb i"<<i);
      temp = ((Dlimb_t)m_value.at(i)*(Dlimb_t)b) + ofl;
      DEBUG("temp "<<temp);

      ans.m_value.push_back((limb_t)temp);
      ofl = temp>>m_limbBitLength;
      DEBUG("ans.size() now " <<ans.m_value.size());
      if (dbg_flag)
        ans.PrintLimbsInDec();
    }
    //check if there is any final overflow
    if(ofl){
      DEBUG("mullimb ofl "<<ofl);
      ans.m_value.push_back(ofl);
    }

    //usint nSize = m_value.size();
    ans.m_state = INITIALIZED;
    ans.SetMSB();
    DEBUG("ans.size() final " <<ans.m_value.size());
    if (dbg_flag)
      ans.PrintLimbsInDec();
    DEBUG("mibl ans "<<ans.ToString());

    return ans;
  }

/* q[0], r[0], u[0], and v[0] contain the LEAST significant words.
(The sequence is in little-endian order).

This is a fairly precise implementation of Knuth's Algorithm D, for a
binary computer with base b = 2**32. The caller supplies:
   1. Space q for the quotient, m - n + 1 words (at least one).
   2. Space r for the remainder (optional), n words.
   3. The dividend u, m words, m >= 1.
   4. The divisor v, n words, n >= 2.
The most significant digit of the divisor, v[n-1], must be nonzero.  The
dividend u may have leading zeros; this just makes the algorithm take
longer and makes the quotient contain more leading zeros.  A value of
NULL may be given for the address of the remainder to signify that the
caller does not want the remainder.
   The program does not alter the input parameters u and v.
   The quotient and remainder returned may have leading zeros.  The
function itself returns a value of 0 for success and 1 for invalid
parameters (e.g., division by 0).
   For now, we must have m >= n.  Knuth's Algorithm D also requires
that the dividend be at least as long as the divisor.  (In his terms,
m >= 0 (unstated).  Therefore m+n >= n.) */
inline const int nlz(usint x) {
   int n;

   if (x == 0) return(32);
   n = 0;
   if (x <= 0x0000FFFF) {n = n +16; x = x <<16;}
   if (x <= 0x00FFFFFF) {n = n + 8; x = x << 8;}
   if (x <= 0x0FFFFFFF) {n = n + 4; x = x << 4;}
   if (x <= 0x3FFFFFFF) {n = n + 2; x = x << 2;}
   if (x <= 0x7FFFFFFF) {n = n + 1;}
   return n;
}

//#define max(x, y) ((x) > (y) ? (x) : (y))

template<typename limb_t>
int ubint<limb_t>::divmnu_vect(ubint& qin, ubint& rin, const ubint& uin, const ubint& vin) const{

  vector<limb_t>&q = (qin.m_value);
  vector<limb_t>&r = (rin.m_value);
  const vector<limb_t>&u = (uin.m_value);
  const vector<limb_t>&v = (vin.m_value);

  int m = u.size();
  int n = v.size();

  q.resize(m-n+1);
  r.resize(n);

   const uint64_t b = 4294967296LL; // Number base (2**32).
   //const uint64_t b = ((uint64_t) m_MaxLimb) +1LL; // Number base (2**32).
//   limb_t *un, *vn;                  // Normalized form of u, v.
   uint64_t qhat;                   // Estimated quotient digit.
   uint64_t rhat;                   // A remainder.
   uint64_t p;                      // Product of two digits.
   int64_t t, k;
   int s, i, j;

   if (m < n || n <= 0 || v[n-1] == 0)
      return 1;                         // Return if invalid param.

   if (n == 1) {                        // Take care of
      k = 0;                            // the case of a
      for (j = m - 1; j >= 0; j--) {    // single-digit
         q[j] = (k*b + u[j])/v[0];      // divisor here.
         k = (k*b + u[j]) - q[j]*v[0];
      }
      if (r.size() != 0) r[0]=k;
      return 0;
   }

   /* Normalize by shifting v left just enough so that its high-order
   bit is on, and shift u left the same amount. We may have to append a
   high-order digit on the dividend; we do that unconditionally. */

   s = nlz(v[n-1]);             // 0 <= s <= 31.
  // vn = (limb_t *)alloca(4*n);
   vector<limb_t> vn(n);
   for (i = n - 1; i > 0; i--)
      vn[i] = (v[i] << s) | ((uint64_t)v[i-1] >> (32-s));
   vn[0] = v[0] << s;

   //un = (limb_t *)alloca(4*(m + 1));
   vector<limb_t> un(m+1);

   un[m] = (uint64_t)u[m-1] >> (32-s);
   for (i = m - 1; i > 0; i--)
      un[i] = (u[i] << s) | ((uint64_t)u[i-1] >> (32-s));
   un[0] = u[0] << s;

   for (j = m - n; j >= 0; j--) {       // Main loop.
      // Compute estimate qhat of q[j].
      qhat = (un[j+n]*b + un[j+n-1])/vn[n-1];
      rhat = (un[j+n]*b + un[j+n-1]) - qhat*vn[n-1];
again:
      if (qhat >= b || qhat*vn[n-2] > b*rhat + un[j+n-2])
      { qhat = qhat - 1;
        rhat = rhat + vn[n-1];
        if (rhat < b) goto again;
      }

      // Multiply and subtract.
      k = 0;
      for (i = 0; i < n; i++) {
         p = qhat*vn[i];
         t = un[i+j] - k - (p & 0xFFFFFFFFLL);
         un[i+j] = t;
         k = (p >> 32) - (t >> 32);
      }
      t = un[j+n] - k;
      un[j+n] = t;

      q[j] = qhat;              // Store quotient digit.
      if (t < 0) {              // If we subtracted too
         q[j] = q[j] - 1;       // much, add back.
         k = 0;
         for (i = 0; i < n; i++) {
            t = (uint64_t)un[i+j] + vn[i] + k;
            un[i+j] = t;
            k = t >> 32;
         }
         un[j+n] = un[j+n] + k;
      }
   } // End j.
   // If the caller wants the remainder, unnormalize
   // it and pass it back.
   if (r.size() != 0) {
     r.resize(n);
     for (i = 0; i < n-1; i++)
       r[i] = (un[i] >> s) | ((uint64_t)un[i+1] << (32-s));
     r[n-1] = un[n-1] >> s;
   }
   return 0;
}

  /* Division operation:
   *  Algorithm used is usual school book long division , except for that radix is 2^m_bitLength.
   *  Optimization done: Uses bit shift operation for logarithmic convergence.
   */
  template<typename limb_t>
  ubint<limb_t> ubint<limb_t>::Div(const ubint& b) const{
    //check for garbage initialization and 0 condition
    if(b.m_state==GARBAGE)
      throw std::logic_error("Div() Divisor uninitialised");

    if(b==ZERO)
        throw std::logic_error("Div() Divisor is zero");

    if(b.m_MSB>this->m_MSB)
      return std::move(ubint(ZERO)); // Kurt and Yuriy want this.

    if(this->m_state==GARBAGE)
      throw std::logic_error("Div() Dividend uninitialised");

    else if(b==*this)
      return std::move(ubint(ONE));

    ubint ans;
    ubint rv;

    int f;
    f = divmnu_vect((ans), (rv),  (*this),  (b));
    if (f!= 0)
      throw std::logic_error("Div() error");

    //go through the mslimbs and pop off any zero limbs
    for (usint i = ans.m_value.size()-1; i >= 0; i--){
     if (!ans.m_value.at(i)) {
	ans.m_value.pop_back();
	//std::cout<<"popped "<<std::endl;
      } else {
	break;
      }
    }

    ans.m_state = INITIALIZED;
    ans.SetMSB();


    return ans;

  }

  //Initializes the vector of limbs from the string equivalent of ubint
  // also sets MSB
  //Algorithm used is repeated division by 2
  //Reference:http://pctechtips.org/convert-from-decimal-to-binary-with-recursion-in-java/
  template<typename limb_t>
  void ubint<limb_t>::AssignVal(const std::string& vin){
    //Todo: eliminate m_limbBitLength, make dynamic instead

	  bool dbg_flag = false;	// if true then print dbg output
	  DEBUG("AssignVal ");
	  DEBUG("vin: "<< vin);


	  std::string v = vin;
	  DEBUG("v1: "<< v);
	  // strip off leading zeros from the input string
	  v.erase(0, v.find_first_not_of('0'));
	  // strip off leading spaces from the input string
	  v.erase(0, v.find_first_not_of(' '));
	  if (v.size() == 0) {
		  //caustic case of input string being all zeros
		  v = "0"; //set to one zero
	  }
	  DEBUG("v2: "<< v);


	  uschar *DecValue;//array of decimal values
	  int arrSize=v.length();

	  //memory allocated for decimal array
	  DecValue = new uschar[arrSize]; //todo smartpointer

	  for(sint i=0;i<arrSize;i++)//store the string to decimal array
		  DecValue[i] = (uschar) stoi(v.substr(i,1));

	  if (dbg_flag) {
		  std::cout << "decval1 ";
		  for(int i=0;i<arrSize;i++)
			  std::cout <<(usint)DecValue[i] << " ";//for debug purpose
		  std::cout << std::endl;
	  }

	  //clear the current value of m_value;
	  m_value.clear();

	  sshort zptr = 0;
	  //index of highest non-zero number in decimal number
	  //define  bit register array
	  uschar *bitArr = new uschar[m_limbBitLength](); //todo smartpointer

	  sint cnt=m_limbBitLength-1;
	  //cnt is a pointer to the bit position in bitArr, when bitArr is compelete it is ready to be transfered to Value
	  while(zptr!=arrSize){
		  bitArr[cnt]=DecValue[arrSize-1]%2;
		  //start divide by 2 in the DecValue array
		  for(sint i=zptr;i<arrSize-1;i++){
			  DecValue[i+1]= (DecValue[i]%2)*10 + DecValue[i+1];
			  DecValue[i]>>=1;
		  }
		  DecValue[arrSize-1]>>=1;
		  //division ends here
#ifdef DEBUG_DECVALUE
		  for(int i=zptr;i<arrSize;i++)
			  cout<<(short)DecValue[i];//for debug purpose
		  cout<<endl;
#endif
		  cnt--;
		  if(cnt==-1){//cnt = -1 indicates bitArr is ready for transfer
			  cnt=m_limbBitLength-1;
			  DEBUG("push back " <<  UintInBinaryToDecimal(bitArr));
			  m_value.push_back( UintInBinaryToDecimal(bitArr));
		  }
		  if(DecValue[zptr]==0)zptr++;//division makes Most significant digit zero, hence we increment zptr to next value
		  if(zptr==arrSize&&DecValue[arrSize-1]==0){
		    m_value.push_back(UintInBinaryToDecimal(bitArr));//Value assignment
		  }
	  }

	  m_state = INITIALIZED;
	  SetMSB(); //sets the MSB correctly
	  delete []bitArr;
	  delete[] DecValue;//deallocate memory

	  if (dbg_flag) {
		  std::cout << "in AssignVal m_value ";
		  for(int i=0;i<m_value.size();i++)
			  std::cout <<m_value.at(i) << " ";//for debug purpose
		  std::cout << std::endl;
		  std::cout << "in AssignVal m_value hex ";
		  for(int i=0;i<m_value.size();i++)
			  std::cout << std::hex <<m_value.at(i) <<  " ";//for debug purpose
		  std::cout <<std::dec << std::endl;

		  std::cout << "in AssignVal m_value hex ";
		  for(int i=0;i<m_value.size();i++)
			  std::cout << std::hex <<m_value.at(i) <<  " ";//for debug purpose
		  std::cout <<std::dec << std::endl;
	  }
	  DEBUG("in AssignVal msb now "<< m_MSB );
	  DEBUG("in AssignVal msb now "<< m_MSB );

  }

  template<typename limb_t>
  void ubint<limb_t>::SetMSB()
  {
    m_MSB = 0;
    if(this->m_state==GARBAGE){
    	throw std::logic_error("SetMSB() of uninitialized bint");
    }

	m_MSB = (m_value.size()-1) * m_limbBitLength; //figure out bit location of all but last limb
	m_MSB+= GetMSBlimb_t(m_value.back()); //add the value of that last limb.
  }

  //guessIdx is the index of largest limb_t number in array.
  template<typename limb_t>
  void ubint<limb_t>::SetMSB(usint guessIdxChar){

    m_MSB = (m_value.size() - guessIdxChar - 1)*m_limbBitLength;
    m_MSB += GetMSBlimb_t(m_value.at(guessIdxChar));
  }

  template<typename limb_t>
  void ubint<limb_t>::SetValue(const std::string& str){
    ubint::AssignVal(str);

  }

  //Algorithm used: optimized division algorithm
  template<typename limb_t>
  ubint<limb_t> ubint<limb_t>::Mod(const ubint& modulus) const{

	  //check for garbage initialisation
	  if(this->m_state==GARBAGE)
		  throw std::logic_error("Mod() of uninitialized bint");
	  if(modulus.m_state==GARBAGE)
		  throw std::logic_error("Mod() using uninitialized bint as modulus");

	  //return the same value if value is less than modulus
	  if(*this<modulus){
		  return std::move(ubint(*this));
	  }
	  //masking operation if modulus is 2
	  if(modulus.m_MSB==2 && modulus.m_value.at(0)==2){
		  if(this->m_value.at(0)%2==0)
			  return ubint(ZERO);
		  else
			  return ubint(ONE);
	  }

		  // return the remainder of the divided by operation
    ubint qv;
    ubint ans(0);

      int f;
    f = divmnu_vect(qv, ans,  *this,  modulus);
    if (f!= 0)
      throw std::logic_error("Mod() error");

    ans.SetMSB();
    ans.m_state = INITIALIZED;

    return(ans);

  }


  //Extended Euclid algorithm used to find the multiplicative inverse
  template<typename limb_t>
  ubint<limb_t> ubint<limb_t>::ModInverse(const ubint& modulus) const{

    if(m_state==GARBAGE || modulus.m_state==GARBAGE)
      throw std::logic_error("ModInverse of uninitialized bint");

    //std::ofstream f("grs_Modinverse");

    //f << *this <<" THIS VALUE "<< std::endl;
    //f << modulus << " Modulus value " << std::endl;

    std::vector<ubint> mods;
    std::vector<ubint> quotient;
    mods.push_back(ubint(modulus));
    if (*this>modulus)
      mods.push_back(this->Mod(modulus));
    else
      mods.push_back(ubint(*this));
    ubint first(mods[0]);
    ubint second(mods[1]);
    //Error if modulus is ZERO
    if(*this==ZERO){
      //std::cout<<"ZERO HAS NO INVERSE\n";
      //system("pause");
      throw std::logic_error("MOD INVERSE NOT FOUND");
    }

	
    //NORTH ALGORITHM
    while(true){
		
      //f << first << std::endl;
      //f << second << std::endl;

      mods.push_back(first.Mod(second));
      //f << "Mod step passed" << std::endl;
      quotient.push_back(first.Div(second));
      //f << "Division step passed" << std::endl;
      if(mods.back()==ONE)
	break;
      if(mods.back()==ZERO){
	std::cout<<"NO INVERSE FOUND, GOING TO THROW ERROR\n";
	throw std::logic_error("MOD INVERSE NOT FOUND");
      }
		
      first = second;
      second = mods.back();
    }

    mods.clear();
    mods.push_back(ubint(ZERO));
    mods.push_back(ubint(ONE));

    first = mods[0];
    second = mods[1];
    //SOUTH ALGORITHM
#if 0
    for(sint i=quotient.size()-1;i>=0;i--){
      mods.push_back(quotient.at(i)*second + first);
      first = second;
      second = mods.back();
    }
#else
    for(sint i=0; i<quotient.size();++i){
      mods.push_back(quotient.at(i)*second + first);
      first = second;
      second = mods.back();
    }

    #endif
    ubint result;
    if(quotient.size()%2==1){
      result = (modulus - mods.back());
    }
    else{
      result = ubint(mods.back());
    }

    mods.clear();
    quotient.clear();
    //f.close();

    return result;

  }

  template<typename limb_t>
  ubint<limb_t> ubint<limb_t>::ModAdd(const ubint& b, const ubint& modulus) const{
    return this->Add(b).Mod(modulus);
    //todo what is the order of this operation?
  }

  template<typename limb_t>
  ubint<limb_t> ubint<limb_t>::ModSub(const ubint& b, const ubint& modulus) const{
    ubint* a = const_cast<ubint*>(this);
    ubint* b_op = const_cast<ubint*>(&b);

    //reduce this to a value lower than modulus
    if(*this>modulus){

      *a = std::move(this->Mod(modulus));
    }
    //reduce b to a value lower than modulus
    if(b>modulus){
      *b_op = std::move(b.Mod(modulus));
    }

    if(*a>=*b_op){
      return ((*a-*b_op).Mod(modulus));		
    }
    else{
      return ((*a + modulus) - *b_op);
    }
  }


  template<typename limb_t>
  ubint<limb_t> ubint<limb_t>::ModMul(const ubint& b, const ubint& modulus) const{
    ubint a(*this);
    ubint bb(b);

    //if a is greater than q reduce a to its mod value
    if(a>modulus){
      a = a.Mod(modulus);
    }

    //if b is greater than q reduce b to its mod value
    if(b>modulus){ 
      bb = bb.Mod(modulus);
    }

    //return a*b%q

    return (a*bb).Mod(modulus);
  }


  //Modular Exponentiation using Square and Multiply Algorithm
  //reference:http://guan.cse.nsysu.edu.tw/note/expn.pdf
  template<typename limb_t>
  ubint<limb_t> ubint<limb_t>::ModExp(const ubint& b, const ubint& modulus) const{
    bool dbg_flag = false;
    DEBUG("ModExp");

    DEBUG("a: "<<this->ToString());
    DEBUG("b: "<<b.ToString());
    DEBUG("mod: "<<modulus.ToString());

    //mid is intermidiate value that calculates mid^2%q
    ubint mid = this->Mod(modulus);	
    DEBUG("mid: "<<mid.ToString());

    //product calculates the running product of mod values
    ubint product(ONE);

    //Exp is used for spliting b to bit values/ bit extraction
    ubint Exp(b);

    while(true){
      //product is multiplied only if lsb bitvalue is 1
      if(Exp.m_value.at(0)%2==1){
        product = product*mid;
      }

      //running product is calculated
      if(product>modulus){
        product = product.Mod(modulus);
      }

      DEBUG("product "<<product.ToString());
      //divide by 2 and check even to odd to find bit value
      Exp = Exp>>1;
      if(Exp==ZERO)break;

      DEBUG("Exp "<<Exp.ToString());

      //mid calculates mid^2%q
      mid = mid*mid;
      mid = (mid.Mod(modulus));
      DEBUG("mid: "<<mid.ToString());
    }
    return product;
  }

  template<typename limb_t>
  const std::string ubint<limb_t>::ToString() const{
      //todo get rid of m_numDigitInPrintval make dynamic
    if (m_value.size()==0)
     throw std::logic_error("ToString() on uninitialized bint");		

    //this string object will store this ubint's value
    std::string bbiString;

    //create reference for the object to be printed
    ubint<limb_t> *print_obj;

    usint counter;

    //initiate to object to be printed
    print_obj = new ubint<limb_t>(*this);  //todo smartpointer

    //print_obj->PrintValueInDec();

    //print_VALUE array stores the decimal value in the array
    uschar *print_VALUE = new uschar[m_numDigitInPrintval];  //todo smartpointer

    //reset to zero
    for(sint i=0;i<m_numDigitInPrintval;i++)
      *(print_VALUE+i)=0;

    //starts the conversion from base r to decimal value
    for(sint i=print_obj->m_MSB;i>0;i--){

      //print_VALUE = print_VALUE*2
      ubint<limb_t>::double_bitVal(print_VALUE);

      //adds the bit value to the print_VALUE
      ubint<limb_t>::add_bitVal(print_VALUE,print_obj->GetBitAtIndex(i));


    }

    //find the first occurence of non-zero value in print_VALUE
    for(counter=0;counter<m_numDigitInPrintval-1;counter++){
      if((sint)print_VALUE[counter]!=0)break;							
    }

    //append this ubint's digits to this method's returned string object
    for (; counter < m_numDigitInPrintval; counter++) {
      bbiString += std::to_string(print_VALUE[counter]);
    }

    delete [] print_VALUE;
    //deallocate the memory since values are inserted into the ostream object
    delete print_obj;

    return bbiString;

  }

  //Compares the current object with the ubint a.
    template<typename limb_t>
  sint ubint<limb_t>::Compare(const ubint& a) const
  {

    if(this->m_state==GARBAGE || a.m_state==GARBAGE)
      throw std::logic_error("ERROR Compare() against uninitialized bint\n");

    //check MSBs to get quick answer
    if(this->m_MSB<a.m_MSB)
      return -1;
    else if(this->m_MSB>a.m_MSB)
      return 1;
    if(this->m_MSB==a.m_MSB){
      //check each limb in descending order
      sint testChar;
      for(sint i=m_value.size()-1 ;i>=0; i--){
        testChar = this->m_value.at(i)-a.m_value.at(i) ;
        if(testChar<0)return -1;
        else if(testChar>0)return 1;
      }
    }
    return 0; //bottom out? then the same
  }
  // == operator
  template<typename limb_t>
  bool ubint<limb_t>::operator==(const ubint& a) const{
    if(this->m_state==GARBAGE || a.m_state==GARBAGE)
            throw std::logic_error("ERROR == against uninitialized bint\n");
    return(this->Compare(a)==0);
  }


  template<typename limb_t>
  bool ubint<limb_t>::operator!=(const ubint& a)const{
    return !(*this==a);
  }

  //greater than operator
  template<typename limb_t>
  bool ubint<limb_t>::operator>(const ubint& a)const{
    if(this->m_state==GARBAGE || a.m_state==GARBAGE)
      throw std::logic_error("ERROR > against uninitialized bint\n");
    return(this->Compare(a)>0);

  }

  //greater than or equals operator
  template<typename limb_t>
  bool ubint<limb_t>::operator>=(const ubint& a) const{
    return (*this>a || *this==a);
  }

   //less than operator
  template<typename limb_t>
  bool ubint<limb_t>::operator<(const ubint& a) const{
    if(this->m_state==GARBAGE || a.m_state==GARBAGE)
      throw std::logic_error("ERROR > against uninitialized bint\n");
    return(this->Compare(a)<0);

  }

  //less than or equal operation
  template<typename limb_t>
  bool ubint<limb_t>::operator<=(const ubint& a) const{
    return (*this<a || *this==a);
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
   * The scheme here is to take each of the uint_types in the
   * BigBinaryInteger and turn it into 6 ascii characters. It's
   * basically Base64 encoding: 6 bits per character times 5 is the
   * first 30 bits. For efficiency's sake, the last two bits are encoded
   * as A,B,C, or D and the code is implemented as unrolled loops
   */
  template<typename limb_t>
  const std::string ubint<limb_t>::Serialize() const {

    std::string ans = "";
    //const uint_type *fromP;

    //	sint siz = (m_MSB%m_uintBitLength==0&&m_MSB!=0) ? (m_MSB/m_uintBitLength) : ((sint)m_MSB/m_uintBitLength +1);
    int i;
    //note limbs are now stored little endian in ubint
    //for(i=m_nSize-1, fromP=m_value+i ; i>=m_nSize-siz ; i--,fromP--) {
    for (auto fromP = m_value.begin(); fromP!=m_value.end(); fromP++){
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
  template<typename limb_t>
  const char * ubint<limb_t>::Deserialize(const char *cp){

    m_value.clear();

    while( *cp != '\0' && *cp != '|' ) {
      limb_t converted =  base64_to_value(*cp++) << b64_shifts[0];
      converted |= base64_to_value(*cp++) << b64_shifts[1];
      converted |= base64_to_value(*cp++) << b64_shifts[2];
      converted |= base64_to_value(*cp++) << b64_shifts[3];
      converted |= base64_to_value(*cp++) << b64_shifts[4];
      converted |= ((*cp++ - 'A')&0x3) << b64_shifts[5];
      m_value.push_back(converted);
    }

    SetMSB();
    m_state = INITIALIZED;

    return cp;
  }

  //helper functions
  template<typename limb_t>
  bool ubint<limb_t>::isPowerOfTwo(const ubint& m_numToCheck){
    usint m_MSB = m_numToCheck.m_MSB;
    for(int i=m_MSB-1;i>0;i--){
      if((sint)m_numToCheck.GetBitAtIndex(i)==(sint)1){
	return false;
      }
    }
    return true;
  }

  template<typename limb_t>
  uint64_t ubint<limb_t>::GetMSB32(uint64_t x)
  {
    static const usint bval[] =
      {0,1,2,2,3,3,3,3,4,4,4,4,4,4,4,4};

    uint64_t r = 0;
    if (x & 0xFFFFFFFF00000000) { r += 32/1; x >>= 32/1; }
    if (x & 0x00000000FFFF0000) { r += 32/2; x >>= 32/2; }
    if (x & 0x000000000000FF00) { r += 32/4; x >>= 32/4; }
    if (x & 0x00000000000000F0) { r += 32/8; x >>= 32/8; }
    return r + bval[x];
  }

  template<typename limb_t>
  usint ubint<limb_t>::GetMSBlimb_t(limb_t x){
    return ubint<limb_t>::GetMSB32(x);
  }
  
  
  template<typename limb_t>
  uint64_t ubint<limb_t>::GetMSB64(uint64_t x) {
    uint64_t bitpos = 0;
    while (x != 0) {
      bitpos++; //increment the bit position
      x = x >> 1; // shift the whole thing to the right once
    }
    return bitpos;
  }

  template<typename limb_t>
  usint ubint<limb_t>::GetDigitAtIndexForBase(usint index, usint base) const{

    usint digit = 0;
    usint newIndex = index; 
    for (usint i = 1; i < base; i = i*2)
      {
	digit += GetBitAtIndex(newIndex)*i;
	newIndex++;
      }
    return digit;

  }

  //Splits the binary string to equi sized chunks and then populates the internal array values.
  template<typename limb_t>
  ubint<limb_t> ubint<limb_t>::BinaryStringToUbint(const std::string& vin){
    bool dbg_flag = false;		// if true then print dbg output
	  DEBUG("BinaryStringToUbint ");
	  std::string v = vin;
	  // strip off leading spaces from the input string
	  v.erase(0, v.find_first_not_of(' '));
	  // strip off leading zeros from the input string
	  v.erase(0, v.find_first_not_of('0'));

	  if (v.size() == 0) {
		  //caustic case of input string being all zeros
		  v = "0"; //set to one zero
	  }

    ubint value;
    usint len = v.length();
    usint cntr = ceilIntByUInt(len);
    std::string val;
    Dlimb_t partial_value = 0;

    for (usint i = 0; i < cntr; i++) 	  {//loop over limbs

      if (len>((i + 1)*m_limbBitLength))
        val = v.substr((len - (i + 1)*m_limbBitLength), m_limbBitLength);
      else
        val = v.substr(0, len%m_limbBitLength);
      for (usint j = 0; j < val.length(); j++){
        partial_value += std::stoi(val.substr(j, 1));
        partial_value <<= 1;
      }
      partial_value >>= 1;
      value.m_value.push_back((limb_t)partial_value);
      partial_value = 0;
    }
    value.m_MSB = (cntr - 1)*m_limbBitLength;
    value.m_MSB += GetMSBlimb_t(value.m_value.back());
    DEBUG("computed msb" << value.m_MSB);
    value.m_state = INITIALIZED;
    value.SetMSB();
    DEBUG("true msb" <<value.m_MSB);
    return value;
  }

  //Recursive Exponentiation function
  template<typename limb_t>
  ubint<limb_t> ubint<limb_t>::Exp(usint p) const{
    if (p == 0) return ubint(ubint::ONE);
    ubint x(*this);
    if (p == 1) return x;

    ubint tmp = x.Exp(p/2);
    if (p%2 == 0) return tmp * tmp;
    else return tmp * tmp * x;
  }


  template<typename limb_t>
  usint ubint<limb_t>::GetMSBDlimb_t(Dlimb_t x){
    return ubint<limb_t>::GetMSB64(x);
  }

  //Algoritm used is shift and add
  template<typename limb_t>
  limb_t ubint<limb_t>::UintInBinaryToDecimal(uschar *a){
    limb_t Val = 0;
    limb_t one =1;
    for(sint i=m_limbBitLength-1;i>=0;i--){
      Val+= one**(a+i);
      one<<=1;
      *(a+i)=0;
    }

    return Val;
  }

  //Algorithm used is double and add
  //http://www.wikihow.com/Convert-from-Binary-to-Decimal
  template<typename limb_t_c_c>
  std::ostream& operator<<(std::ostream& os, const ubint<limb_t_c_c>& ptr_obj){
    //todo: get rid of m_numDigitInPrintval and make dynamic
    //create reference for the object to be printed
    ubint<limb_t_c_c> *print_obj;

    usint counter;

    //initiate to object to be printed
    print_obj = new ubint<limb_t_c_c>(ptr_obj);  //todo smartpointer

    //print_obj->PrintValueInDec();

    //print_VALUE array stores the decimal value in the array
    uschar *print_VALUE = new uschar[ptr_obj.m_numDigitInPrintval];  //todo smartpointer

    //reset to zero
    for(sint i=0;i<ptr_obj.m_numDigitInPrintval;i++)
      *(print_VALUE+i)=0;

    //starts the conversion from base r to decimal value
    for(sint i=print_obj->m_MSB;i>0;i--){

      //print_VALUE = print_VALUE*2
      ubint<limb_t_c_c>::double_bitVal(print_VALUE);
#ifdef DEBUG_OSTREAM
      for(sint i=0;i<ptr_obj.m_numDigitInPrintval;i++)
	std::cout<<(sint)*(print_VALUE+i);
      std::cout<<endl;
#endif
      //adds the bit value to the print_VALUE
      ubint<limb_t_c_c>::add_bitVal(print_VALUE,print_obj->GetBitAtIndex(i));
#ifdef DEBUG_OSTREAM
      for(sint i=0;i<ptr_obj.m_numDigitInPrintval;i++)
	std::cout<<(sint)*(print_VALUE+i);
      std::cout<<endl;
#endif

    }

    //find the first occurence of non-zero value in print_VALUE
    for(counter=0;counter<ptr_obj.m_numDigitInPrintval-1;counter++){
      if((sint)print_VALUE[counter]!=0)break;							
    }

    //start inserting values into the ostream object 
    for(;counter<ptr_obj.m_numDigitInPrintval;counter++){
      os<<(int)print_VALUE[counter];
    }

    //os<<endl;
    delete [] print_VALUE;
    //deallocate the memory since values are inserted into the ostream object
    delete print_obj;
    return os;
  }

 
  template<typename limb_t>
  void ubint<limb_t>::double_bitVal(uschar* a){
	
    uschar ofl=0;
    for(sint i=m_numDigitInPrintval-1;i>-1;i--){
      *(a+i)<<=1;
      if(*(a+i)>9){
	*(a+i)=*(a+i)-10+ofl;
	ofl=1;
		  } else {
			  *(a+i)=*(a+i)+ofl;
	ofl = 0;
      }

    }
  }

  template<typename limb_t>
  void ubint<limb_t>::add_bitVal(uschar* a,uschar b){
    uschar ofl=0;
    *(a+m_numDigitInPrintval-1)+=b;
    for(sint i=m_numDigitInPrintval-1;i>-1;i--){
      *(a+i) += ofl;
      if(*(a+i)>9){
	*(a+i)=0;
	ofl=1;
      }
		
    }
  }


  template<typename limb_t>
  uschar ubint<limb_t>::GetBitAtIndex(usint index) const{
    if(index<=0){
      std::cout<<"Invalid index \n";
      return 0;
    }
    else if (index > m_MSB)
      return 0;
    limb_t result;
    sint idx =ceilIntByUInt(index)-1;//idx is the index of the character array
    limb_t temp = this->m_value.at(idx);
    limb_t bmask_counter = index%m_limbBitLength==0? m_limbBitLength:index%m_limbBitLength;//bmask is the bit number in the 8 bit array
    limb_t bmask = 1;
    for(sint i=1;i<bmask_counter;i++)
      bmask<<=1;//generate the bitmask number
    result = temp&bmask;//finds the bit in  bit format
    result>>=bmask_counter-1;//shifting operation gives bit either 1 or 0
    return (uschar)result;
  }

  template<typename limb_t>
  void ubint<limb_t>::SetIntAtIndex(usint idx, limb_t value){
    if (idx >= m_value.size())
      throw std::logic_error("Index Invalid");
    this->m_value.at(idx) = value;
  }

  /*
    This method can be used to convert int to ubint
  */
  template<typename limb_t>
  ubint<limb_t> ubint<limb_t>::UsintToUbint(usint m){

    return ubint(m);

  }


} // namespace exp_int32 ends
