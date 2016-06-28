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
 * big integers: bint. Big integers are represented as arrays of
 * native usigned integers. The native integer type is supplied as a
 * template parameter.  Currently implementations based on uint8_t,
 * uint16_t, and uint32_t are supported. The second template parameter
 * is the maximum bitwidth for the big integer.
 */


#include "bint.h"

#include <iostream>
#include <fstream>
#include "time.h"
#include <chrono>

#include "../../utils/debug.h"//todo: should be in debug.h

namespace exp_int32 {

  //constant static member variable initialization of 0
  template<typename limb_t,usint BITLENGTH>
  const bint<limb_t,BITLENGTH> bint<limb_t,BITLENGTH>::ZERO = bint(0);

  //constant static member variable initialization of 1
  template<typename limb_t,usint BITLENGTH>
  const bint<limb_t,BITLENGTH> bint<limb_t,BITLENGTH>::ONE = bint(1);

  //constant static member variable initialization of 2
  template<typename limb_t,usint BITLENGTH>
  const bint<limb_t,BITLENGTH> bint<limb_t,BITLENGTH>::TWO = bint(2);

  //constant static member variable initialization of 3
  template<typename limb_t,usint BITLENGTH>
  const bint<limb_t,BITLENGTH> bint<limb_t,BITLENGTH>::THREE = bint(3);

  //constant static member variable initialization of 4
  template<typename limb_t,usint BITLENGTH>
  const bint<limb_t,BITLENGTH> bint<limb_t,BITLENGTH>::FOUR = bint(4);

  //constant static member variable initialization of 5
  template<typename limb_t,usint BITLENGTH>
  const bint<limb_t,BITLENGTH> bint<limb_t,BITLENGTH>::FIVE = bint(5);

  //MOST REQUIRED STATIC CONSTANTS INITIALIZATION

  //constant static member variable initialization of m_uintBitLength which is equal to number of bits in the unit data type
  //permitted values: 8,16,32
  template<typename limb_t,usint BITLENGTH>
  //const uschar bint<limb_t,BITLENGTH>::m_uintBitLength = UIntBitWidth<limb_t>::value;
const usint bint<limb_t,BITLENGTH>::m_limbBitLength = sizeof(limb_t)*8;

  template<typename limb_t,usint BITLENGTH>
  const usint bint<limb_t,BITLENGTH>::m_numDigitInPrintval = BITLENGTH/exp_int32::LOG2_10;

  //constant static member variable initialization of m_logUintBitLength which is equal to log of number of bits in the unit data type
  //permitted values: 3,4,5
  template<typename limb_t,usint BITLENGTH>
  //const uschar bint<limb_t,BITLENGTH>::m_log2LimbBitLength = LogDtype<limb_t>::value;
const usint bint<limb_t,BITLENGTH>::m_log2LimbBitLength = Log2<m_limbBitLength>::value;

  //constant static member variable initialization of m_nSize which is size of the array of unit data type
  //template<typename limb_t,usint BITLENGTH>
  //const usint bint<limb_t,BITLENGTH>::m_nSize = BITLENGTH%m_limbBitLength==0 ? BITLENGTH/m_limbBitLength : BITLENGTH/m_limbBitLength + 1;

  //constant static member variable initialization of m_uintMax which is maximum value of unit data type
  template<typename limb_t,usint BITLENGTH>
const usint bint<limb_t,BITLENGTH>::m_MaxLimb = std::numeric_limits<limb_t>::max();

  //optimized ceiling function after division by number of bits in the limb data type.
  template<typename limb_t,usint BITLENGTH>
  usint bint<limb_t,BITLENGTH>::ceilIntByUInt(const limb_t Number){
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
  template<typename limb_t,usint BITLENGTH>
  bint<limb_t,BITLENGTH>::bint()
  {
	bool dbg_flag = 0;		// if true then print dbg output

    DEBUG("ctor()");
    DEBUG( "maxlimb "<<m_MaxLimb);

    DEBUG( "initial size "<< m_value.size());
    //last first limb set to 0
    this->m_value.reserve(1);
    this->m_value[0] = 0;
    //MSB set to zero since value set to ZERO
    this->m_MSB = 0;
    m_state = INITIALIZED;
    DEBUG("size now "<<m_value.size());
    DEBUG("final msb ="<<this->m_MSB);
  }
  
  template<typename limb_t,usint BITLENGTH>
  bint<limb_t,BITLENGTH>::bint(usint init){
	    bool dbg_flag = 0;		// if true then print dbg output

    //setting the MSB
    usint msb = 0;
    
    msb = GetMSB32(init);
    DEBUG("ctor("<<init<<")");
    DEBUG( "msb " <<msb);
    DEBUG( "maxlimb "<<m_MaxLimb);

    DEBUG( "initial size "<< m_value.size());
    
    if (init <= m_MaxLimb) {
      //init fits in first limb entry
      m_value.push_back((limb_t)init);
      DEBUG("single limb size now "<<m_value.size());
    } else {
      usint ceilInt = ceilIntByUInt(msb);
      //setting the values of the array
      this->m_value.reserve(ceilInt);
      for(usint i= 0;i<ceilInt;++i){
	this->m_value[i] = (limb_t)init;
	init>>=m_limbBitLength;
      }
      DEBUG("mulit limb ceilIntByUInt ="<<ceilInt);
    }
    this->m_MSB = msb;
    m_state = INITIALIZED;
    
    DEBUG("final msb ="<<msb);
  }
  
  template<typename limb_t,usint BITLENGTH>
  bint<limb_t,BITLENGTH>::bint(const std::string& str){
	    bool dbg_flag = 0;		// if true then print dbg output

    DEBUG("ctor(str "<<str<<")");
    //memory allocation step
    //m_value = new limb_t[m_nSize]; //todosmartpointer
    //setting the array values from the string

    AssignVal(str);
    //state set
    m_state = INITIALIZED;
  	DEBUG("final msb ="<<this->m_MSB);
  }
  
  template<typename limb_t,usint BITLENGTH>
  bint<limb_t,BITLENGTH>::bint(const bint& rhs){
	  bool dbg_flag = 0;		// if true then print dbg output

	  DEBUG("ctor(bint)");

    //memory allocation step
    //m_value = new limb_t[m_nSize];  //todo smartpointer
    this->m_MSB=rhs.m_MSB; //copy MSB
    limb_t  tempChar = ceilIntByUInt(rhs.m_MSB);
    //copy array values
    this->m_value = rhs.m_value;
    //for(int i=0;i<tempChar;i++){//copy array value
    //  m_value[i]=rhs.m_value[i];
    //}
    //set state
    m_state = INITIALIZED;
  	DEBUG("final msb ="<<this->m_MSB);
  }

  template<typename limb_t,usint BITLENGTH>
  bint<limb_t,BITLENGTH>::bint(bint &&bigInteger){
    //copy MSB
    m_MSB = bigInteger.m_MSB;
    //copy assignment
    m_value = bigInteger.m_value;
    //set state
    m_state = bigInteger.m_state;
    //remove ref from bigInteger
    vector<limb_t>().swap(bigInteger.m_value); //clears value with reallocation.
  }

  template<typename limb_t,usint BITLENGTH>
  std::function<unique_ptr<bint<limb_t,BITLENGTH>>()> bint<limb_t,BITLENGTH>::Allocator = [=](){
    return make_unique<exp_int32::bint<uint32_t,1500>>();
  };
  template<typename limb_t,usint BITLENGTH>
  bint<limb_t,BITLENGTH>::~bint()
  {	
    //memory deallocation
	  vector<limb_t>().swap(m_value); //clear with reallocation
  }

  /**
   *Converts the bint to a usint unsigned integer or returns the first
   *m_limbBitLength bits of the bint.  Splits the bint into bit length of uint data
   *type and then uses shift and add to form the  unsigned
   *integer.
   */
  template<typename limb_t, usint BITLENGTH>
  usint bint<limb_t, BITLENGTH>::ConvertToUsint() const{
	  usint result;
	  if (sizeof(limb_t)>=sizeof(usint)){
		  result = m_value[0];
		  return result;
	  } else {
		  //Case where limb_t is less bits than usint
		  //set num to number of equisized chunks
		  //usint num = (8*sizeof(usint)) / m_limbBitLength;

		  usint ceilInt = ceilIntByUInt(m_MSB);
		  //copy the values by shift and add
		  for (usint i = 0; i < ceilInt; i++){
			  result += (this->m_value[i] << (m_limbBitLength*i));
		  }
		  return result;
	  }
  }
  // the following conversions all throw 
  //Converts the bint to uint32_t using the std library functions.
  template<typename limb_t, usint BITLENGTH>
  uint32_t bint<limb_t,BITLENGTH>::ConvertToUint32() const{
    return std::stoul(this->ToString());
  }

  //Converts the bint to uint64_t using the std library functions.
  template<typename limb_t, usint BITLENGTH>
  uint64_t bint<limb_t,BITLENGTH>::ConvertToUint64() const{
    return std::stoull(this->ToString());
  }

  //Converts the bint to float using the std library functions.
  template<typename limb_t, usint BITLENGTH>
  float bint<limb_t,BITLENGTH>::ConvertToFloat() const{
    return std::stof(this->ToString());
  }

  //Converts the bint to double using the std library functions.
  template<typename limb_t, usint BITLENGTH>
  double bint<limb_t,BITLENGTH>::ConvertToDouble() const{
    return std::stod(this->ToString());
  }

  //Converts the bint to long double using the std library functions.
  template<typename limb_t, usint BITLENGTH>
  long double bint<limb_t,BITLENGTH>::ConvertToLongDouble() const{
    return std::stold(this->ToString());
  }

  template<typename limb_t,usint BITLENGTH>
  const bint<limb_t,BITLENGTH>&  bint<limb_t,BITLENGTH>::operator=(const bint &rhs){
	if(this!=&rhs){
      this->m_MSB=rhs.m_MSB;
      this->m_state = rhs.m_state;
      //copy vector
      this->m_value=rhs.m_value;
    }
    return *this;
  }

  template<typename limb_t,usint BITLENGTH>
  const bint<limb_t,BITLENGTH>&  bint<limb_t,BITLENGTH>::operator=(bint &&rhs){

    if(this!=&rhs){
      this->m_MSB = rhs.m_MSB;
      this->m_state = rhs.m_state;
      this->m_value = rhs.m_value;
	  vector<limb_t>().swap(rhs.m_value); //clear with reallocation
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
  template<typename limb_t,usint BITLENGTH>
  bint<limb_t,BITLENGTH>  bint<limb_t,BITLENGTH>::operator<<(usshort shift) const{
	  if(m_state==State::GARBAGE)
		  throw std::logic_error("Value not initialized");
	  if(this->m_MSB==0)
		  return bint(ZERO);

	  bint ans(*this);
	  //check for OVERFLOW
	  if((ans.m_MSB+shift) > BITLENGTH )
		  throw std::logic_error("OVERFLOW \n");

	  //compute the number of whole limb shifts
	  usint shiftByLimb = shift>>m_log2LimbBitLength;
	  //compute the remaining number of bits to shift
	  usshort remainingShift = (shift&(m_limbBitLength-1));

	  //first shift by the # remainingShift bits
	  if(remainingShift!=0){
		  limb_t oFlow = 0;
		  Dlimb_t temp = 0;
		  sint i;

		  for(i=0; i<ceilIntByUInt(m_MSB); ++i){
			  temp = ans.m_value[i];
			  temp <<=remainingShift;
			  ans.m_value[i] = (limb_t)temp + oFlow;
			  oFlow = temp >> m_limbBitLength;
		  }

		  if(i>-1)
			  ans.m_value[i] = oFlow;

		  ans.m_MSB += remainingShift;

	  }

	  if(shiftByLimb!=0){
		  //todo could be ceilIntbyUint
      for(auto  iter =  ans.m_value.rbegin(); iter!= ans.m_value.rend(); ++iter){
	//ans.m_value[iter+shiftByLimb] = ans.m_value[iter];
	*(iter+shiftByLimb) = *iter;
		  }

		  //zero out lower "shifted in" limbs
      //usint j;
      for(auto iter = ans.m_value.rbegin()+shiftByLimb; iter!= ans.m_value.rend(); ++iter){
	*iter = 0;
		  }
	  }

	  ans.m_MSB += shiftByLimb*m_limbBitLength;
	  return ans;

  }

  /**
   *	Left Shift is done by splitting the number of shifts into
   *1. Multiple of the bit length of limb data type.
   *	Shifting is done by the shifting the limb type numbers.
   *2. Shifts between 1 to bit length of limb data type.
   *   Shifting is done by using bit shift operations and carry over propagation.
   */
  template<typename limb_t,usint BITLENGTH>
  const bint<limb_t,BITLENGTH>&  bint<limb_t,BITLENGTH>::operator<<=(usshort shift){
    if(m_state==State::GARBAGE)
      throw std::logic_error("Value not initialized");

    if(this->m_MSB==0) {
      return *this;
    } else {
      bint ans(*this);
      *this = ans << shift;
      return *this;
    }
  }

  /**Right Shift is done by splitting the number of shifts into
   *1. Multiple of the bit length of limb data type.
   *	Shifting is done by the shifting the limb type numbers in the array to the right.
   *2. Shifts between 1 to bit length of limb data type.
   *   Shifting is done by using bit shift operations and carry over propagation.
   */
  template<typename limb_t,usint BITLENGTH>
  bint<limb_t,BITLENGTH>  bint<limb_t,BITLENGTH>::operator>>(usshort shift) const{
	  //garbage check
	  if(m_state==State::GARBAGE)
		  throw std::logic_error("Value not initialized");

	  //trivial cases
	  if(this->m_MSB==0 || this->m_MSB <= shift)
		  return bint(0);


	  bint ans(*this);
	  //no of array shifts
	  usint shiftByLimb = shift>>m_log2LimbBitLength;
	  //no of bit shifts
	  limb_t remainingShift = (shift&(m_limbBitLength-1));

	  //first shift by the number of whole limb shifts
	  if(shiftByLimb!=0){
		  //todo could be ceilIntbyUint
      for(auto i =  ans.m_value.begin()+shiftByLimb; i  != ans.m_value.end();++i){
	//ans.m_value[i-shiftByLimb] = ans.m_value[i];
	*(i-shiftByLimb) = *i;
		  }
		  //zero out upper  "shifted in" limbs
		  usint j;
      for(auto j = ans.m_value.end() - shiftByLimb; j!= ans.m_value.end(); ++j){
	//ans.m_value[j] = 0;	//todo should this instead just be deleted?
	*j = 0;
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
		  for( ;startVal>=0;startVal--){

			  oldVal = ans.m_value[startVal];

			  ans.m_value[startVal] = (ans.m_value[startVal]>>remainingShift) + overFlow;

			  overFlow = (oldVal &  maskVal);
			  overFlow <<= compShiftVal ;
		  }

		  ans.m_MSB -= remainingShift;

	  }
	  return ans;
  }


  /**Right Shift is done by splitting the number of shifts into
   *1. Multiple of the bit length of limb data type.
   *	Shifting is done by the shifting the limb type numbers in the array to the right.
   *2. Shifts between 1 to bit length of limb data type.
   *   Shifting is done by using bit shift operations and carry over propagation.
   */
  template<typename limb_t,usint BITLENGTH>
  bint<limb_t,BITLENGTH>&  bint<limb_t,BITLENGTH>::operator>>=(usshort shift){
    //check for garbage
    if(m_state==State::GARBAGE)
      throw std::logic_error("Value not initialized");

    if(this->m_MSB==0 )
      return *this;
    else if(this->m_MSB<=shift){
      *this = ZERO;
      return *this;
    } else {
    	bint ans(*this);
    	*this - ans >> shift;
    	return *this;

    }

  }


  template<typename limb_t,usint BITLENGTH>
  void bint<limb_t,BITLENGTH>::PrintLimbsInDec() const{
	bool dbg_flag = 0;		// if true then print dbg output
	DEBUG("PrintLimbsInDec m_MSB    "<< m_MSB);
	DEBUG("PrintLimbsInDec m_limbBitLength "<< m_limbBitLength);
    usint upperlim =  m_MSB/m_limbBitLength +1;
	DEBUG("PrintLimbsInDec upperlim "<< upperlim);
    if (upperlim == 0) {
      upperlim = 1;
    }
    DEBUG("PrintLimbsInDec size "<< m_value.size());
    for (usint i = 0; i < upperlim; i++){
      std::cout<< i << ":"<< m_value[i];
      std::cout <<std::endl;
    }
    std::cout<<std::endl;
  }

  template<typename limb_t,usint BITLENGTH>
  void bint<limb_t,BITLENGTH>::PrintLimbsInHex() const{
      std::cout<<std::hex<<m_value <<std::dec<<std::endl;
  }

  template<typename limb_t,usint BITLENGTH>
  usshort bint<limb_t,BITLENGTH>::GetMSB()const{
    return m_MSB;
  }

  /** Addition operation:
   *  Algorithm used is usual school book sum and carry-over, expect for that radix is 2^m_bitLength.
   */
  template<typename limb_t,usint BITLENGTH>
  bint<limb_t,BITLENGTH> bint<limb_t,BITLENGTH>::Add(const bint& b) const{
	
    //two operands A and B for addition, A is the greater one, B is the smaller one
    const bint* A = NULL;
    const bint* B = NULL;
    //check for garbage initializations
    if((this->m_state==GARBAGE)||(b.m_state==GARBAGE)){
    	throw std::logic_error("Add() of uninitialized bint");
    }

    //Assignment of pointers, A assigned the higher value and B assigned the lower value
    if(*this>b){
      A = this; B = &b;
    }
    else {A = &b; B = this;}

    if(B->m_MSB==0)
      return bint(*A);

    bint result;
    result.m_state = INITIALIZED;

    //overflow variable
    Dlimb_t ofl=0;

    //position from A to end addition
    limb_t ceilIntA = ceilIntByUInt(A->m_MSB);
    //position from B to end addition
    limb_t ceilIntB = ceilIntByUInt(B->m_MSB);

    usint i;//
    for(i=0; i<ceilIntB; ++i){ //loop over limbs low to high till you reach the end of the smaller one
      ofl =(Dlimb_t)A->m_value[i]+ (Dlimb_t)B->m_value[i]+ofl;//sum of the two int and the carry over
      result.m_value.push_back((limb_t)ofl);
      ofl>>=m_limbBitLength;//current overflow
    }

    // we have an overflow at the end
    if(ofl){
    	for(; i<=ceilIntA; ++i){ //keep looping over the remainder of the larger value
    		ofl = (Dlimb_t)A->m_value[i]+ofl;//sum of the two int and the carry over
    		result.m_value.push_back((limb_t)ofl);
    		ofl>>=m_limbBitLength;//current overflow
    	}

    	if(ofl){//in the end if overflow is set it indicates MSB is one greater than the one we started with
    		result.m_value.push_back(1);
    	}
    } else { //there is no overflow at the end
    	for(; i<=ceilIntA; ++i){
    		result.m_value.push_back(A->m_value[i]);
    	}
    }
    result.SetMSB();//Set the MSB.

    return result;
  }

  /** Sub operation:
   *  Algorithm used is usual school book borrow and subtract, except for that radix is 2^m_bitLength.
   */
  template<typename limb_t,usint BITLENGTH>
  bint<limb_t,BITLENGTH> bint<limb_t,BITLENGTH>::Sub(const bint& b) const{
    //check for garbage initialization
    if(this->m_state==GARBAGE){
      return std::move(bint(ZERO));		
    }
    if(b.m_state==GARBAGE){
      return std::move(bint(*this));
    }
    //return 0 if b is higher than *this as there is no support for negative number
    if(!(*this>b))
      return std::move(bint(ZERO)); //todo: should we throw an exception ?

    int cntr=0,current=0;
	
    bint result(*this);
    //array position in A to end substraction
    int endValA = m_value.size()-ceilIntByUInt(this->m_MSB);
    //array position in B to end substraction
    int endValB = m_value.size()-ceilIntByUInt(b.m_MSB);
    sint i;
    for(i=m_value.size()-1;i>=endValB;i--){
      //carryover condtion
      if(result.m_value[i]<b.m_value[i]){
	current=i;
	cntr = current-1;
	//assigning carryover value
	while(result.m_value[cntr]==0){
	  result.m_value[cntr]=m_MaxLimb;cntr--;
	}
	result.m_value[cntr]--;
	result.m_value[i]=result.m_value[i]+m_MaxLimb+1- b.m_value[i];
      }
      //usual substraction condition
      else{
	result.m_value[i]=result.m_value[i]- b.m_value[i];
      }
      cntr=0;
    }

    while(result.m_value[endValA]==0){
      endValA++;
    }
    //reset the MSB after substraction
    result.m_MSB = (m_value.size()-endValA-1)*m_limbBitLength + GetMSBlimb_t(result.m_value[endValA]);

    //return the result
    return std::move(result);

  }

  /** Multiply operation:
   *  Algorithm used is usual school book shift and add after multiplication, except for that radix is 2^m_bitLength.
   */
  template<typename limb_t,usint BITLENGTH>
  bint<limb_t,BITLENGTH> bint<limb_t,BITLENGTH>::Mul(const bint& b) const{
	
    bint ans;
    //check for garbage initialised objects
    if(b.m_MSB==0 || b.m_state==GARBAGE ||this->m_state==GARBAGE || this->m_MSB==0){
      ans = ZERO;
      return ans;
    }
    //check for trivial condtions
    if(b.m_MSB==1)
      return bint(*this);

    if(this->m_MSB==1)
      return std::move(bint(b));
	
    //position of B in the array where the multiplication should start
    limb_t ceilInt = ceilIntByUInt(b.m_MSB);
    //Multiplication is done by getting a limb_t from b and multiplying it with *this
    //after multiplication the result is shifted and added to the final answer

    usint nSize = this->m_value.size();
    for(sint i= nSize-1;i>= nSize-ceilInt;i--){
      ans += (this->MulIntegerByLimb(b.m_value[i]))<<=( nSize-1-i)*m_limbBitLength;
    }
    
    return ans;
  }


  template<typename limb_t,usint BITLENGTH>
  const bint<limb_t,BITLENGTH>& bint<limb_t,BITLENGTH>::operator+=(const bint &b){

#if 0
    const bint* A = NULL;//two operands A and B for addition, A is the greater one, B is the smaller one
    const bint* B = NULL;
    //check for garbage initialisation
    if(this->m_state==GARBAGE){
      if(b.m_state==GARBAGE){
	*this = ZERO;
	return *this;
      }
      else{
	*this = b;
	return *this;
      }
    }
    //check for trivial cases
    if(b.m_state==GARBAGE || b.m_MSB==0){
      return *this;
    }
    //assigning pointers, A is assigned higher value and B the lower one
    if(*this>b){
      A = this; B = &b;
    }
    else {A = &b; B = this;}
    //overflow variable
    Dlimb_t ofl=0;
    //position in the array of A to start addition 
    limb_t ceilIntA = ceilIntByUInt(A->m_MSB);
    //position in the array of B to start addition
    limb_t ceilIntB = ceilIntByUInt(B->m_MSB);

    //counter
    sint i;
    for(i=m_nSize-1;i>=m_nSize-ceilIntB;i--){
      ofl =(Dlimb_t)A->m_value[i]+ (Dlimb_t)B->m_value[i]+ofl;//sum of the two apint and the carry over
      this->m_value[i] = (limb_t)ofl;
      ofl>>=m_limbBitLength;//current overflow
    }

    if(ofl){
      for(;i>=m_nSize-ceilIntA;i--){
	ofl = (Dlimb_t)A->m_value[i]+ofl;//sum of the two int and the carry over
	this->m_value[i] = (limb_t)ofl;
	ofl>>=m_limbBitLength;//current overflow
      }

      if(ofl){//in the end if overflow is set it indicates MSB is one greater than the one we started with
	this->m_value[m_nSize-ceilIntA-1] = 1;
	this->m_MSB = A->m_MSB + 1;
      }
      else{
	this->m_MSB = (m_nSize - i - 2)*m_limbBitLength;
	this->m_MSB += GetMSBlimb_t(this->m_value[++i]);
      }
    }
    else{
      for(;i>=m_nSize-ceilIntA;i--){//NChar-ceil(MSB/8)
	this->m_value[i] = A->m_value[i];
      }
      this->m_MSB = (m_nSize-i-2)*m_limbBitLength;
      this->m_MSB += GetMSBlimb_t(this->m_value[++i]);
    }	
#else
    *this = *this+b;
#endif
    return *this;
  }

  template<typename limb_t,usint BITLENGTH>
  const bint<limb_t,BITLENGTH>& bint<limb_t,BITLENGTH>::operator-=(const bint &b){
	
#if 0
    if(this->m_state==GARBAGE){
      *this=ZERO;
      return *this;		
    }
    if(b.m_state==GARBAGE){
      return *this;
    }

    if(!(*this>b)){
      *this=ZERO;
      return *this;
    }

    int cntr=0,current=0;

    usint nSize = m_value.size();
    int endValA = nSize-ceilIntByUInt(this->m_MSB);
    int endValB = nSize-ceilIntByUInt(b.m_MSB);
    sint i;
    for(i=m_nSize-1;i>=endValB;i--){
      if(this->m_value[i]<b.m_value[i]){
	current=i;
	cntr = current-1;
	while(this->m_value[cntr]==0){
	  this->m_value[cntr]=m_MaxLimb;cntr--;
	}
	this->m_value[cntr]--;
	this->m_value[i]=this->m_value[i]+m_MaxLimb+1- b.m_value[i];
      }
      else{
	this->m_value[i]=this->m_value[i]- b.m_value[i];
      }
    }

    while(this->m_value[endValA]==0){
      endValA++;
    }

    this->m_MSB = (m_nSize-endValA-1)*m_limbBitLength + GetMSBlimb_t(this->m_value[endValA]);


    return *this;
#else
    *this = *this-b;
#endif
    return *this;
  }


  /** Multiply operation:
   *  Algorithm used is usual school book multiplication.
   *  This function is used in the Multiplication of two bint objects
   */
  template<typename limb_t,usint BITLENGTH>
  bint<limb_t,BITLENGTH> bint<limb_t,BITLENGTH>::MulIntegerByLimb(limb_t b) const{
	
    if(this->m_state==GARBAGE)
      throw std::logic_error("ERROR \n");
    if(b==0 || this->m_MSB==0)
      return bint(ZERO);
	
    bint ans;
    //position in the array to start multiplication
    usint endVal = this->m_value.size()-ceilIntByUInt(m_MSB);
    //variable to capture the overflow
    Dlimb_t temp=0;
    //overflow value
    limb_t ofl=0;
    sint i= m_value.size()-1;

    for(;i>=endVal ;i--){
      temp = ((Dlimb_t)m_value[i]*(Dlimb_t)b) + ofl;
      ans.m_value[i] = (limb_t)temp;
      ofl = temp>>m_limbBitLength;
    }
    //check if there is any final overflow
    if(ofl){
      ans.m_value[i]=ofl;
    }
    usint nSize = m_value.size();
    ans.m_MSB = (nSize-1-endVal)*m_limbBitLength;
    //set the MSB after the final computation
    ans.m_MSB += GetMSBDlimb_t(temp);
    ans.m_state = INITIALIZED;

    return ans;
  }

  /* Division operation:
   *  Algorithm used is usual school book long division , except for that radix is 2^m_bitLength.
   *  Optimization done: Uses bit shift operation for logarithmic convergence.
   */
  template<typename limb_t,usint BITLENGTH>
  bint<limb_t,BITLENGTH> bint<limb_t,BITLENGTH>::DividedBy(const bint& b) const{
    //check for garbage initialization and 0 condition
    if(b.m_state==GARBAGE || b==ZERO)
      throw std::logic_error("DIVISION BY ZERO");

    if(b.m_MSB>this->m_MSB || this->m_state==GARBAGE)
      return std::move(bint(ZERO));
    else if(b==*this)
      return std::move(bint(ONE));
	
		
    bint ans;
#if 0
	
    //normalised_dividend = result*quotient
    bint normalised_dividend( this->Sub( this->Mod(b) ) );
    //Number of array elements in Divisor
    limb_t ncharInDivisor = ceilIntByUInt(b.m_MSB);
    //Get the uint integer that is in the MSB position of the Divisor
    limb_t msbCharInDivisor = b.m_value[(usint)( m_nSize-ncharInDivisor)];
    //Number of array elements in Normalised_dividend
    limb_t ncharInNormalised_dividend = ceilIntByUInt(normalised_dividend.m_MSB);
    ////Get the uint integer that is in the MSB position of the normalised_dividend
    limb_t msbCharInRunning_Normalised_dividend = normalised_dividend.m_value[(usint)( m_nSize-ncharInNormalised_dividend)];
    //variable to store the running dividend
    bint running_dividend;
    //variable to store the running remainder
    bint runningRemainder;
    bint expectedProd;
    bint estimateFinder;

    //Initialize the running dividend
    for(usint i=0;i<ncharInDivisor;i++){
      running_dividend.m_value[ m_nSize-ncharInDivisor+i] = normalised_dividend.m_value[ m_nSize-ncharInNormalised_dividend+i]; 
    }
    running_dividend.m_MSB = GetMSBlimb_t(running_dividend.m_value[m_nSize-ncharInDivisor]) + (ncharInDivisor-1)*m_limbBitLength;
    running_dividend.m_state = INITIALIZED;
	
    limb_t estimate=0;
    limb_t maskBit = 0;
    limb_t shifts =0;
    usint ansCtr = m_nSize - ncharInNormalised_dividend+ncharInDivisor-1;
    //Long Division Computation to determine quotient
    for(usint i=ncharInNormalised_dividend-ncharInDivisor;i>=0;){
      //Get the remainder from the Modulus operation
      runningRemainder = running_dividend.Mod(b);
      //Compute the expected product from the running dividend and remainder
      expectedProd = running_dividend-runningRemainder;
      estimateFinder = expectedProd;
		
      estimate =0;
		
      //compute the quotient
      if(expectedProd>b){	
	while(estimateFinder.m_MSB > 0){
	  /*
	    if(expectedProd.m_MSB-b.m_MSB==m_uintBitLength){
	    maskBit= 1<<(m_uintBitLength-1);
	    }
	    else
	    maskBit= 1<<(expectedProd.m_MSB-b.m_MSB);
	  */
	  shifts = estimateFinder.m_MSB-b.m_MSB;
	  if(shifts==m_limbBitLength){
	    maskBit= 1<<(m_limbBitLength-1);
	  }
	  else
	    maskBit= 1<<(shifts);
				
	  if((b.MulIntegerByLimb(maskBit))>estimateFinder){
	    maskBit>>=1;
	    estimateFinder-= b<<(shifts-1);
	  }
	  else if(shifts==m_limbBitLength)
	    estimateFinder-= b<<(shifts-1);
	  else
	    estimateFinder-= b<<shifts;
				
	  estimate |= maskBit;
	}
			
      }
      else if(expectedProd.m_MSB==0)
	estimate = 0;
      else
	estimate = 1; 
      //assgning the quotient in the result array
      ans.m_value[ansCtr] = estimate;
      ansCtr++;		
      if(i==0)
	break;
      //Get the next uint element from the divisor and proceed with long division
      if(running_dividend.m_MSB==0){
	running_dividend.m_MSB=GetMSBlimb_t(normalised_dividend.m_value[m_nSize-i]);
      }
      else
	running_dividend = runningRemainder<<m_limbBitLength;

      running_dividend.m_value[ m_nSize-1] = normalised_dividend.m_value[m_nSize-i];	
      if (running_dividend.m_MSB == 0)
	running_dividend.m_MSB = GetMSBlimb_t(normalised_dividend.m_value[m_nSize - i]);
      i--;
    }
    ansCtr = m_nSize - ncharInNormalised_dividend+ncharInDivisor-1;
    //Loop to the MSB position
    while(ans.m_value[ansCtr]==0){
      ansCtr++;
    }
    //Computation of MSB value 
    ans.m_MSB = GetMSBlimb_t(ans.m_value[ansCtr]) + (m_nSize-1-ansCtr)*m_limbBitLength;
    ans.m_state = INITIALIZED;
#else
    ans = 0;
    std::cout <<"DividedBy function not built yet"<<std::endl;
#endif
    return ans;

  }

  //Initializes the array of uint_array from the string equivalent of bint
  //Algorithm used is repeated division by 2
  //Reference:http://pctechtips.org/convert-from-decimal-to-binary-with-recursion-in-java/
  template<typename limb_t,usint BITLENGTH>
  void bint<limb_t,BITLENGTH>::AssignVal(const std::string& vin){
	  bool dbg_flag = 0;		// if true then print dbg output
	  DEBUG("vin: "<< vin);


	  std::string v = vin;
	  DEBUG("v1: "<< v);
	  // strip off leading zeros from the input string
	  v.erase(0, v.find_first_not_of('0'));
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

	  sshort zptr = 0;
	  //index of highest non-zero number in decimal number
	  //define  bit register array
	  uschar *bitArr = new uschar[m_limbBitLength](); //todo smartpointer

	  //sint bitValPtr=m_nSize-1;
	  //bitValPtr is a pointer to the Value char array, initially pointed to the last char
	  //we increment the pointer to the next char when we get the complete value of the char array

	  sint cnt=m_limbBitLength-1;
	  //cnt8 is a pointer to the bit position in bitArr, when bitArr is compelete it is ready to be transfered to Value
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
			  //m_value[bitValPtr--]= UintInBinaryToDecimal(bitArr);//UintInBinaryToDecimal converts bitArr to decimal and resets the content of bitArr.
			  m_value.push_back( UintInBinaryToDecimal(bitArr));
		  }
		  if(DecValue[zptr]==0)zptr++;//division makes Most significant digit zero, hence we increment zptr to next value
		  if(zptr==arrSize&&DecValue[arrSize-1]==0){
			  	  //m_value[bitValPtr]=UintInBinaryToDecimal(bitArr);//Value assignment
			  m_value.push_back(UintInBinaryToDecimal(bitArr));//Value assignment
		  }
	  }
	  //std::reverse (m_value.begin(), m_value.end()); //kludge, above is old code that writes the vector bigendian
	  SetMSB(); //sets the MSB correctly
	  delete []bitArr;
	  delete[] DecValue;//deallocate memory

	  if (dbg_flag) {
		  std::cout << "in AssignVal m_value ";
		  for(int i=0;i<m_value.size();i++)
			  std::cout <<m_value[i] << " ";//for debug purpose
		  std::cout << std::endl;
		  std::cout << "in AssignVal m_value hex ";
		  for(int i=0;i<m_value.size();i++)
			  std::cout << std::hex <<m_value[i] <<  " ";//for debug purpose
		  std::cout <<std::dec << std::endl;

		  std::cout << "in AssignVal m_value hex ";
		  for(int i=0;i<m_value.size();i++)
			  std::cout << std::hex <<m_value[i] <<  " ";//for debug purpose
		  std::cout <<std::dec << std::endl;
	  }
	  DEBUG("in AssignVal msb now "<< m_MSB );
	  DEBUG("in AssignVal msb now "<< m_MSB );

  }

  template<typename limb_t,usint BITLENGTH>
  void bint<limb_t,BITLENGTH>::SetMSB()
  {
    m_MSB = 0;
    if(this->m_state==GARBAGE){//todo: should fail.
    	throw std::logic_error("SetMSB() of uninitialized bint");
    }

	m_MSB = (m_value.size()-1) * m_limbBitLength; //figure out bit location of all but last limb
	m_MSB+= GetMSBlimb_t(m_value.back()); //add the value of that last limb.
  }

  //guessIdx is the index of largest limb_t number in array.
  template<typename limb_t, usint BITLENGTH>
  void bint<limb_t, BITLENGTH>::SetMSB(usint guessIdxChar){

    m_MSB = (m_value.size() - guessIdxChar - 1)*m_limbBitLength;
    m_MSB += GetMSBlimb_t(m_value[guessIdxChar]);
  }

  template<typename limb_t, usint BITLENGTH>
  void bint<limb_t, BITLENGTH>::SetValue(const std::string& str){
    bint::AssignVal(str);

  }

  //Algorithm used: Repeated substraction by a multiple of modulus, which will be referred to as "Classical Modulo Reduction Algorithm"
  //Complexity: O(log(*this)-log(modulus))
  template<typename limb_t,usint BITLENGTH>
  bint<limb_t,BITLENGTH> bint<limb_t,BITLENGTH>::Mod(const bint& modulus) const{

    //check for garbage initialisation
    if(this->m_state==GARBAGE || modulus.m_state==GARBAGE)
      throw std::logic_error("Error \n");

    //return the same value if value is less than modulus
    if(*this<modulus){
      return std::move(bint(*this));
    }
    //masking operation if modulus is 2
    if(modulus.m_MSB==2 && modulus.m_value[m_value.size()-1]==2){
      if(this->m_value[m_value.size()-1]%2==0)
	return bint(ZERO);
      else
	return bint(ONE);
    }
	
    Dlimb_t initial_shift = 0;
    //No of initial left shift that can be performed which will make it comparable to the current value.
    if(this->m_MSB > modulus.m_MSB)
      initial_shift=this->m_MSB - modulus.m_MSB -1;

	
    bint j = modulus<<initial_shift;

	
    bint result(*this);

    bint temp;
    while(true){
      //exit criteria
      if(result<modulus) break;
      if (result.m_MSB > j.m_MSB) {
	temp = j<<1;
	if (result.m_MSB == j.m_MSB + 1) {
	  if(result>temp){
	    j=temp;
	  }
	}
      }
      //subtracting the running remainder by a multiple of modulus
      result -= j;
		
      initial_shift = j.m_MSB - result.m_MSB +1;
      if(result.m_MSB-1>=modulus.m_MSB){
	j>>=initial_shift;
      }
      else{ 
	j = modulus;
      }

    }

    return std::move(result);
  }

  /**
     Source: http://homes.esat.kuleuven.be/~fvercaut/papers/bar_mont.pdf
     @article{knezevicspeeding,
     title={Speeding Up Barrett and Montgomery Modular Multiplications},
     author={Knezevic, Miroslav and Vercauteren, Frederik and Verbauwhede, Ingrid}
     }
     We use the Generalized Barrett modular reduction algorithm described in Algorithm 2 of the Source. The algorithm was originally 
     proposed in J.-F. Dhem. Modified version of the Barrett algorithm. Technical report, 1994 and described in more detail 
     in the PhD thesis of the author published at
     http://users.belgacom.net/dhem/these/these_public.pdf (Section 2.2.4).
     We take \alpha equal to n + 3. So in our case, \mu = 2^(n + \alpha) = 2^(2*n + 3).
     Generally speaking, the value of \alpha should be \ge \gamma + 1, where \gamma + n is the number of digits in the dividend.
     We use the upper bound of dividend assuming that none of the dividends will be larger than 2^(2*n + 3). The value of \mu
     is computed by BigBinaryVector::ModMult.

  */
  template<typename limb_t,usint BITLENGTH>
  bint<limb_t,BITLENGTH> bint<limb_t,BITLENGTH>::ModBarrett(const bint& modulus, const bint& mu) const{
	
    if(*this<modulus){
      return std::move(bint(*this));
    }
    bint z(*this);
    bint q(*this);

    usint n = modulus.m_MSB;
    usint alpha = n + 3;
    sint beta = -2;

    q>>=n + beta;
    q=q*mu;
    q>>=alpha-beta;
    z-=q*modulus;
	
    if(z>=modulus)
      z-=modulus;
	
    return z;

  }
#if 0
  /**
     Source: http://homes.esat.kuleuven.be/~fvercaut/papers/bar_mont.pdf
     @article{knezevicspeeding,
     title={Speeding Up Barrett and Montgomery Modular Multiplications},
     author={Knezevic, Miroslav and Vercauteren, Frederik and Verbauwhede, Ingrid}
     }
     We use the Generalized Barrett modular reduction algorithm described in Algorithm 2 of the Source. The algorithm was originally 
     proposed in J.-F. Dhem. Modified version of the Barrett algorithm. Technical report, 1994 and described in more detail 
     in the PhD thesis of the author published at
     http://users.belgacom.net/dhem/these/these_public.pdf (Section 2.2.4).
     We take \alpha equal to n + 3. In this case, we work with an array of precomputed \mu values.
  **/
  template<typename limb_t,usint BITLENGTH>
  bint<limb_t,BITLENGTH> bint<limb_t,BITLENGTH>::ModBarrett(const bint& modulus, const bint mu_arr[BARRETT_LEVELS+1]) const{

    if(*this<modulus){
      bint z(*this);
      return z;
    }
    bint z(*this);
    bint q(*this);

    uschar n = modulus.m_MSB;
    //level is set to the index between 0 and BARRET_LEVELS - 1
    uschar level = (this->m_MSB-1-n)*BARRETT_LEVELS/(n+1)+1;
    uschar gamma = (n*level)/BARRETT_LEVELS;

    uschar alpha = gamma + 3;
    schar beta = -2;

    const bint& mu = mu_arr[level];

    q>>=n + beta;
    q=q*mu;
    q>>=alpha-beta;
    z-=q*modulus;
	
    if(z>=modulus)
      z-=modulus;
	
    return z;

  }
#endif
  //Extended Euclid algorithm used to find the multiplicative inverse
  template<typename limb_t,usint BITLENGTH>
  bint<limb_t,BITLENGTH> bint<limb_t,BITLENGTH>::ModInverse(const bint& modulus) const{

    if(m_state==GARBAGE || modulus.m_state==GARBAGE)
      throw std::logic_error("ModInverse of uninitialized bint");

    //std::ofstream f("grs_Modinverse");

    //f << *this <<" THIS VALUE "<< std::endl;
    //f << modulus << " Modulus value " << std::endl;

    std::vector<bint> mods;
    std::vector<bint> quotient;
    mods.push_back(bint(modulus));
    if (*this>modulus)
      mods.push_back(this->Mod(modulus));
    else
      mods.push_back(bint(*this));
    bint first(mods[0]);
    bint second(mods[1]);
    //Error if modulus is ZERO
    if(*this==ZERO){
      std::cout<<"ZERO HAS NO INVERSE\n";
      system("pause");
      throw std::logic_error("MOD INVERSE NOT FOUND");
    }

	
    //NORTH ALGORITHM
    while(true){
		
      //f << first << std::endl;
      //f << second << std::endl;

      mods.push_back(first.Mod(second));
      //f << "Mod step passed" << std::endl;
      quotient.push_back(first.DividedBy(second));
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
    mods.push_back(bint(ZERO));
    mods.push_back(bint(ONE));

    first = mods[0];
    second = mods[1];
    //SOUTH ALGORITHM
    for(sint i=quotient.size()-1;i>=0;i--){
      mods.push_back(quotient[i]*second + first);
      first = second;
      second = mods.back();
    }

    bint result;
    if(quotient.size()%2==1){
      result = (modulus - mods.back());
    }
    else{
      result = bint(mods.back());
    }

    mods.clear();
    quotient.clear();
    //f.close();

    return result;

  }

  template<typename limb_t,usint BITLENGTH>
  bint<limb_t,BITLENGTH> bint<limb_t,BITLENGTH>::ModAdd(const bint& b, const bint& modulus) const{
    return this->Add(b).Mod(modulus);
    //todo what is the order of this operation?
  }

  //Optimized Mod Addition using ModBarrett
//  template<typename limb_t,usint BITLENGTH>
//  bint<limb_t,BITLENGTH> bint<limb_t,BITLENGTH>::ModBarrettAdd(const bint& b, const bint& modulus,const bint mu_arr[BARRETT_LEVELS]) const{
//    return this->Plus(b).ModBarrett(modulus,mu_arr);
//  }
//


  template<typename limb_t,usint BITLENGTH>
  bint<limb_t,BITLENGTH> bint<limb_t,BITLENGTH>::ModBarrettAdd(const bint& b, const bint& modulus,const bint& mu) const{
    return this->Add(b).ModBarrett(modulus,mu);
  }

  template<typename limb_t,usint BITLENGTH>
  bint<limb_t,BITLENGTH> bint<limb_t,BITLENGTH>::ModSub(const bint& b, const bint& modulus) const{
    bint* a = const_cast<bint*>(this);
    bint* b_op = const_cast<bint*>(&b);

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

  //Optimized Mod Substraction using ModBarrett
  template<typename limb_t,usint BITLENGTH>
  bint<limb_t,BITLENGTH> bint<limb_t,BITLENGTH>::ModBarrettSub(const bint& b, const bint& modulus,const bint& mu) const{

    bint* a = NULL;
    bint* b_op = NULL;

    if(*this>modulus){
      *a = std::move(this->ModBarrett(modulus,mu));
    }
    else{
      a = const_cast<bint*>(this);
    }

    if(b>modulus){
      *b_op = std::move(b.ModBarrett(modulus,mu));
    }
    else{
      b_op = const_cast<bint*>(&b);
    }

    if(!(*a<*b_op)){
      return ((*a-*b_op).ModBarrett(modulus,mu));
		
    }
    else{
      return ((*a + modulus) - *b_op);
    }
  }


//  template<typename limb_t,usint BITLENGTH>
//  bint<limb_t,BITLENGTH> bint<limb_t,BITLENGTH>::ModBarrettSub(const bint& b, const bint& modulus,const bint mu_arr[BARRETT_LEVELS]) const{
//
//    bint* a = NULL;
//    bint* b_op = NULL;
//
//    if(*this>modulus){
//      *a = std::move(this->ModBarrett(modulus,mu_arr));
//    }
//    else{
//      a = const_cast<bint*>(this);
//    }
//
//    if(b>modulus){
//      *b_op = std::move(b.ModBarrett(modulus,mu_arr));
//    }
//    else{
//      b_op = const_cast<bint*>(&b);
//    }
//
//    if(!(*a<*b_op)){
//      return ((*a-*b_op).ModBarrett(modulus,mu_arr));
//
//    }
//    else{
//      return ((*a + modulus) - *b_op);
//    }
//
//  }

  template<typename limb_t,usint BITLENGTH>
  bint<limb_t,BITLENGTH> bint<limb_t,BITLENGTH>::ModMul(const bint& b, const bint& modulus) const{
    bint a(*this);
    bint bb(b);

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

  /*
    Source: http://homes.esat.kuleuven.be/~fvercaut/papers/bar_mont.pdf
    @article{knezevicspeeding,
    title={Speeding Up Barrett and Montgomery Modular Multiplications},
    author={Knezevic, Miroslav and Vercauteren, Frederik and Verbauwhede, Ingrid}
    }
    We use the Generalized Barrett modular reduction algorithm described in Algorithm 2 of the Source. The algorithm was originally 
    proposed in J.-F. Dhem. Modified version of the Barrett algorithm. Technical report, 1994 and described in more detail 
    in the PhD thesis of the author published at
    http://users.belgacom.net/dhem/these/these_public.pdf (Section 2.2.4).
    We take \alpha equal to n + 3. So in our case, \mu = 2^(n + \alpha) = 2^(2*n + 3).
    Generally speaking, the value of \alpha should be \ge \gamma + 1, where \gamma + n is the number of digits in the dividend.
    We use the upper bound of dividend assuming that none of the dividends will be larger than 2^(2*n + 3).

    Multiplication and modulo reduction are NOT INTERLEAVED.

    Potential improvements:
    1. When working with MATHBACKEND = 1, we tried to compute an evenly distributed array of \mu (the number is approximately equal
    to the number BARRET_LEVELS) but that did not give any performance improvement. So using one pre-computed value of 
    \mu was the most efficient option at the time.
    2. We also tried "Interleaved digit-serial modular multiplication with generalized Barrett reduction" Algorithm 3 in the Source but it 
    was slower with MATHBACKEND = 1.
    3. Our implementation makes the modulo operation essentially equivalent to two multiplications. If sparse moduli are selected, it can be replaced
    with a single multiplication. The interleaved version of modular multiplication for this case is listed in Algorithm 6 of the source. 
    This algorithm would most like give the biggest improvement but it sets constraints on moduli.

  */

  template<typename limb_t,usint BITLENGTH>
  bint<limb_t,BITLENGTH> bint<limb_t,BITLENGTH>::ModBarrettMul(const bint& b, const bint& modulus,const bint& mu) const{

    bint* a  = const_cast<bint*>(this);
    bint* bb = const_cast<bint*>(&b);

    //if a is greater than q reduce a to its mod value
    if(*this>modulus)
      *a = std::move(this->ModBarrett(modulus,mu));


    //if b is greater than q reduce b to its mod value
    if(b>modulus)
      *bb = std::move(b.ModBarrett(modulus,mu));

    return (*a**bb).ModBarrett(modulus,mu);

  }

//  template<typename limb_t,usint BITLENGTH>
//  bint<limb_t,BITLENGTH> bint<limb_t,BITLENGTH>::ModBarrettMul(const bint& b, const bint& modulus,const bint mu_arr[BARRETT_LEVELS]) const{
//    bint* a  = NULL;
//    bint* bb = NULL;
//
//    //if a is greater than q reduce a to its mod value
//    if(*this>modulus)
//      *a = std::move(this->ModBarrett(modulus,mu_arr));
//    else
//      a = const_cast<bint*>(this);
//
//    //if b is greater than q reduce b to its mod value
//    if(b>modulus)
//      *bb = std::move(b.ModBarrett(modulus,mu_arr));
//    else
//      bb = const_cast<bint*>(&b);
//
//    //return a*b%q
//
//    return (*a**bb).ModBarrett(modulus,mu_arr);
//  }

  //Modular Multiplication using Square and Multiply Algorithm
  //reference:http://guan.cse.nsysu.edu.tw/note/expn.pdf
  template<typename limb_t,usint BITLENGTH>
  bint<limb_t,BITLENGTH> bint<limb_t,BITLENGTH>::ModExp(const bint& b, const bint& modulus) const{

#ifdef DEBUG_MODEXP
    std::cout<<*this<<std::endl<<b<<std::endl<<modulus<<std::endl;
#endif

    //mid is intermidiate value that calculates mid^2%q
    bint mid = this->Mod(modulus);	

#ifdef DEBUG_MODEXP
    std::cout<<mid<<"  mid"<<std::endl;
#endif

    //product calculates the running product of mod values
    bint product(ONE);

#ifdef DEBUG_MODEXP
    std::cout<<*product<<"  product"<<std::endl;
#endif
    //Exp is used for spliting b to bit values/ bit extraction
    bint Exp(b);

#ifdef DEBUG_MODEXP
    std::cout<<Exp<<"  Exp"<<std::endl;
#endif

    while(true){

		
      //product is multiplied only if bitvalue is 1
      if(Exp.m_value[m_value.size()-1]%2==1){
	product = product*mid;
      }

      //running product is calculated
      if(product>modulus){
	product = product.Mod(modulus);
      }

#ifdef DEBUG_MODEXP
      std::cout<<*product<<std::endl;
#endif
      //divide by 2 and check even to odd to find bit value
      Exp = Exp>>1;
      if(Exp==ZERO)break;

#ifdef DEBUG_MODEXP
      std::cout<<"Exp: "<<Exp<<std::endl;
#endif

      //mid calculates mid^2%q
      mid = mid*mid;
		
      mid = (mid.Mod(modulus));

#ifdef DEBUG_MODEXP
      std::cout<<mid<<std::endl;
#endif

    }

    return product;

  }

  template<typename limb_t,usint BITLENGTH>
  const std::string bint<limb_t,BITLENGTH>::ToString() const{

    //this string object will store this bint's value
    std::string bbiString;

    //create reference for the object to be printed
    bint<limb_t,BITLENGTH> *print_obj;

    usint counter;

    //initiate to object to be printed
    print_obj = new bint<limb_t,BITLENGTH>(*this);  //todo smartpointer

    //print_obj->PrintValueInDec();

    //print_VALUE array stores the decimal value in the array
    uschar *print_VALUE = new uschar[m_numDigitInPrintval];  //todo smartpointer

    //reset to zero
    for(sint i=0;i<m_numDigitInPrintval;i++)
      *(print_VALUE+i)=0;

    //starts the conversion from base r to decimal value
    for(sint i=print_obj->m_MSB;i>0;i--){

      //print_VALUE = print_VALUE*2
      bint<limb_t,BITLENGTH>::double_bitVal(print_VALUE);	

      //adds the bit value to the print_VALUE
      bint<limb_t,BITLENGTH>::add_bitVal(print_VALUE,print_obj->GetBitAtIndex(i));


    }

    //find the first occurence of non-zero value in print_VALUE
    for(counter=0;counter<m_numDigitInPrintval-1;counter++){
      if((sint)print_VALUE[counter]!=0)break;							
    }

    //append this bint's digits to this method's returned string object
    for (; counter < m_numDigitInPrintval; counter++) {
      bbiString += std::to_string(print_VALUE[counter]);
    }

    delete [] print_VALUE;
    //deallocate the memory since values are inserted into the ostream object
    delete print_obj;

    return bbiString;

  }

  //Compares the current object with the bint a.
  //Uses MSB comparision to output requisite value.
  template<typename limb_t,usint BITLENGTH>
  sint bint<limb_t,BITLENGTH>::Compare(const bint& a) const
  {

    if(this->m_state==GARBAGE || a.m_state==GARBAGE)
      throw std::logic_error("Error \n");

    if(this->m_MSB<a.m_MSB)
      return -1;
    else if(this->m_MSB>a.m_MSB)
      return 1;
    if(this->m_MSB==a.m_MSB){
      uschar ceilInt = ceilIntByUInt(this->m_MSB); 
      sshort testChar;
      for(usint i=m_value.size()-ceilInt;i< m_value.size();i++){
	testChar = this->m_value[i]-a.m_value[i] ;
	if(testChar<0)return -1;
	else if(testChar>0)return 1;
      }
    }

    return 0;

  }

  template<typename limb_t,usint BITLENGTH>
  bool bint<limb_t,BITLENGTH>::operator==(const bint& a) const{

    if(this->m_state==GARBAGE || a.m_state==GARBAGE)
      throw std::logic_error("ERROR \n");
    if(this->m_MSB!=a.m_MSB)
      return false;
    else{
      uschar ceilInt = ceilIntByUInt(a.m_MSB); 
      for(usint i= m_value.size()-ceilInt;i< m_value.size();i++)
	if(this->m_value[i]!=a.m_value[i])
	  return false;	
    }
    return true;

  }

  template<typename limb_t,usint BITLENGTH>
  bool bint<limb_t,BITLENGTH>::CheckIfPowerOfTwo(const bint& m_numToCheck){
    usint m_MSB = m_numToCheck.m_MSB;
    for(int i=m_MSB-1;i>0;i--){
      if((sint)m_numToCheck.GetBitAtIndex(i)==(sint)1){
	return false;
      }
    }
    return true;
  }

  template<typename limb_t,usint BITLENGTH>
  bool bint<limb_t,BITLENGTH>::operator!=(const bint& a)const{
    return !(*this==a);
  }

  template<typename limb_t,usint BITLENGTH>
  bool bint<limb_t,BITLENGTH>::operator>(const bint& a)const{
	
    if(this->m_state==GARBAGE || a.m_state==GARBAGE)
      throw std::logic_error("ERROR \n");

    if(this->m_MSB<a.m_MSB)
      return false;
    else if(this->m_MSB>a.m_MSB)
      return true;
    else{
      uschar ceilInt = ceilIntByUInt(this->m_MSB); 
      for(usint i=m_value.size()-ceilInt;i< m_value.size();i++){
	if(this->m_value[i]<a.m_value[i])
	  return false;
	else if(this->m_value[i]>a.m_value[i])
	  return true;
      }

    }
    return false;
  }

  template<typename limb_t,usint BITLENGTH>
  bool bint<limb_t,BITLENGTH>::operator>=(const bint& a) const{
    return (*this>a || *this==a);
  }

  template<typename limb_t,usint BITLENGTH>
  bool bint<limb_t,BITLENGTH>::operator<(const bint& a) const{

    if(this->m_state==GARBAGE || a.m_state==GARBAGE)
      throw std::logic_error("ERROR \n");

    if(this->m_MSB<a.m_MSB)
      return true;
    else if(this->m_MSB>a.m_MSB)
      return false;
    else{
      uschar ceilInt = ceilIntByUInt(this->m_MSB); 
      usint vsize = this->m_value.size();
      for(usint i= vsize-ceilInt;i< vsize;i++){
	if(this->m_value[i]>a.m_value[i])
	  return false;
	else if(this->m_value[i]<a.m_value[i])
	  return true;
      }

    }
    return false;

  }

  template<typename limb_t,usint BITLENGTH>
  bool bint<limb_t,BITLENGTH>::operator<=(const bint& a) const{
    return (*this<a || *this==a);
  }

  template<typename limb_t,usint BITLENGTH>
  uint64_t bint<limb_t,BITLENGTH>::GetMSB32(uint64_t x)
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

  template<typename limb_t,usint BITLENGTH>
  usint bint<limb_t,BITLENGTH>::GetMSBlimb_t(limb_t x){
    return bint<limb_t,BITLENGTH>::GetMSB32(x);
  }
  
  
  template<typename limb_t,usint BITLENGTH>
  uint64_t bint<limb_t,BITLENGTH>::GetMSB64(uint64_t x) {
    uint64_t bitpos = 0;
    while (x != 0) {
      bitpos++; //increment the bit position
      x = x >> 1; // shift the whole thing to the right once
    }
    return bitpos;
  }

  template<typename limb_t,usint BITLENGTH>
  usint bint<limb_t,BITLENGTH>::GetDigitAtIndexForBase(usint index, usint base) const{

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
  template<typename limb_t,usint BITLENGTH>
  bint<limb_t,BITLENGTH> bint<limb_t,BITLENGTH>::BinaryStringToBint(const std::string& bitString){
	
    bint value;
    usint len = bitString.length();
    usint cntr = ceilIntByUInt(len);
    std::string val;
    Dlimb_t partial_value = 0;
    for (usint i = 0; i < cntr; i++) 	  {

	if (len>((i + 1)*m_limbBitLength))
	  val = bitString.substr((len - (i + 1)*m_limbBitLength), m_limbBitLength);
	else
	  val = bitString.substr(0, len%m_limbBitLength);
	for (usint j = 0; j < val.length(); j++){
	  partial_value += std::stoi(val.substr(j, 1));
	  partial_value <<= 1;
	}
	partial_value >>= 1;
      value.m_value[i] = (limb_t)partial_value;
      partial_value = 0;
    }
    value.m_MSB = (cntr - 1)*m_limbBitLength;
    value.m_MSB += GetMSBlimb_t(value.m_value.back());
    value.m_state = INITIALIZED;
    return value;

  }

  //Recursive Exponentiation function
  template<typename limb_t,usint BITLENGTH>
  bint<limb_t,BITLENGTH> bint<limb_t,BITLENGTH>::Exp(usint p) const{
    if (p == 0) return bint(bint::ONE);
    bint x(*this);
    if (p == 1) return x;

    bint tmp = x.Exp(p/2);
    if (p%2 == 0) return tmp * tmp;
    else return tmp * tmp * x;
  }


  template<typename limb_t,usint BITLENGTH>
  usint bint<limb_t,BITLENGTH>::GetMSBDlimb_t(Dlimb_t x){
    return bint<limb_t,BITLENGTH>::GetMSB64(x);
  }

  //Algoritm used is shift and add
  template<typename limb_t,usint BITLENGTH>
  limb_t bint<limb_t,BITLENGTH>::UintInBinaryToDecimal(uschar *a){
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
  template<typename limb_t_c,usint BITLENGTH_c>
  std::ostream& operator<<(std::ostream& os, const bint<limb_t_c,BITLENGTH_c>& ptr_obj){

    //create reference for the object to be printed
    bint<limb_t_c,BITLENGTH_c> *print_obj;

    usint counter;

    //initiate to object to be printed
    print_obj = new bint<limb_t_c,BITLENGTH_c>(ptr_obj);  //todo smartpointer

    //print_obj->PrintValueInDec();

    //print_VALUE array stores the decimal value in the array
    uschar *print_VALUE = new uschar[ptr_obj.m_numDigitInPrintval];  //todo smartpointer

    //reset to zero
    for(sint i=0;i<ptr_obj.m_numDigitInPrintval;i++)
      *(print_VALUE+i)=0;

    //starts the conversion from base r to decimal value
    for(sint i=print_obj->m_MSB;i>0;i--){

      //print_VALUE = print_VALUE*2
      bint<limb_t_c,BITLENGTH_c>::double_bitVal(print_VALUE);	
#ifdef DEBUG_OSTREAM
      for(sint i=0;i<ptr_obj.m_numDigitInPrintval;i++)
	std::cout<<(sint)*(print_VALUE+i);
      std::cout<<endl;
#endif
      //adds the bit value to the print_VALUE
      bint<limb_t_c,BITLENGTH_c>::add_bitVal(print_VALUE,print_obj->GetBitAtIndex(i));
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

 
  template<typename limb_t,usint BITLENGTH>
  void bint<limb_t,BITLENGTH>::double_bitVal(uschar* a){
	
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

  template<typename limb_t,usint BITLENGTH>
  void bint<limb_t,BITLENGTH>::add_bitVal(uschar* a,uschar b){
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


  template<typename limb_t,usint BITLENGTH>
  uschar bint<limb_t,BITLENGTH>::GetBitAtIndex(usint index) const{
    if(index<=0){
      std::cout<<"Invalid index \n";
      return 0;
    }
    else if (index > m_MSB)
      return 0;
    limb_t result;
    sint idx =ceilIntByUInt(index)-1;//idx is the index of the character array
    limb_t temp = this->m_value[idx];
    limb_t bmask_counter = index%m_limbBitLength==0? m_limbBitLength:index%m_limbBitLength;//bmask is the bit number in the 8 bit array
    limb_t bmask = 1;
    for(sint i=1;i<bmask_counter;i++)
      bmask<<=1;//generate the bitmask number
    result = temp&bmask;//finds the bit in  bit format
    result>>=bmask_counter-1;//shifting operation gives bit either 1 or 0
    return (uschar)result;
  }

  template<typename limb_t, usint BITLENGTH>
  void bint<limb_t, BITLENGTH>::SetIntAtIndex(usint idx, limb_t value){
    if (idx >= m_value.size())
      throw std::logic_error("Index Invalid");
    this->m_value[idx] = value;
  }

  /*
    This method can be used to convert int to bint
  */
  template<typename limb_t,usint BITLENGTH>
  bint<limb_t,BITLENGTH> bint<limb_t,BITLENGTH>::intTobint(usint m){

    return bint(m);

  }


} // namespace exp_int32 ends
