//LAYER 1 : PRIMITIVE DATA STRUCTURES AND OPERATIONS
/*
PRE SCHEME PROJECT, Crypto Lab, NJIT
Version:
	v00.01
Last Edited:
	3/1/2015 4:37AM
List of Authors:
	TPOC:
		Dr. Kurt Rohloff, rohloff@njit.edu
	Programmers:
		Dr. Yuriy Polyakov, polyakov@njit.edu
		Gyana Sahu, grs22@njit.edu
Description:
	This class provides a class for big integers.

License Information:

Copyright (c) 2015, New Jersey Institute of Technology (NJIT)
All rights reserved.
Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:
1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

*/
#include "binint.h"

#if defined(_MSC_VER)
	#pragma intrinsic(_BitScanReverse64) 
#endif

namespace cpu_int {

//static uschar* dec2bin(uschar a); //TODO DBC UNUSED REMOVE
static void printArray(uschar *a,int size);

void printArray(uschar *a,int size){
		for(int i=0;i<size;i++)
			std::cout<<(int)*(a+i)<<" ";
		std::cout<<std::endl;
	}

//constant static member variable initialization of 0
template<typename uint_type,usint BITLENGTH>
const BigBinaryInteger<uint_type,BITLENGTH> BigBinaryInteger<uint_type,BITLENGTH>::ZERO = BigBinaryInteger(0);

//constant static member variable initialization of 1
template<typename uint_type,usint BITLENGTH>
const BigBinaryInteger<uint_type,BITLENGTH> BigBinaryInteger<uint_type,BITLENGTH>::ONE = BigBinaryInteger(1);

//constant static member variable initialization of 2
template<typename uint_type,usint BITLENGTH>
const BigBinaryInteger<uint_type,BITLENGTH> BigBinaryInteger<uint_type,BITLENGTH>::TWO = BigBinaryInteger(2);

//constant static member variable initialization of 3
template<typename uint_type,usint BITLENGTH>
const BigBinaryInteger<uint_type,BITLENGTH> BigBinaryInteger<uint_type,BITLENGTH>::THREE = BigBinaryInteger(3);

//constant static member variable initialization of 4
template<typename uint_type,usint BITLENGTH>
const BigBinaryInteger<uint_type,BITLENGTH> BigBinaryInteger<uint_type,BITLENGTH>::FOUR = BigBinaryInteger(4);

//constant static member variable initialization of 5
template<typename uint_type,usint BITLENGTH>
const BigBinaryInteger<uint_type,BITLENGTH> BigBinaryInteger<uint_type,BITLENGTH>::FIVE = BigBinaryInteger(5);

//MOST REQUIRED STATIC CONSTANTS INITIALIZATION

//constant static member variable initialization of m_uintBitLength which is equal to number of bits in the unit data type
//permitted values: 8,16,32
template<typename uint_type,usint BITLENGTH>
const uschar BigBinaryInteger<uint_type,BITLENGTH>::m_uintBitLength = UIntBitWidth<uint_type>::value;

template<typename uint_type,usint BITLENGTH>
const usint BigBinaryInteger<uint_type,BITLENGTH>::m_numDigitInPrintval = BITLENGTH/cpu_int::LOG2_10;

//constant static member variable initialization of m_logUintBitLength which is equal to log of number of bits in the unit data type
//permitted values: 3,4,5
template<typename uint_type,usint BITLENGTH>
const uschar BigBinaryInteger<uint_type,BITLENGTH>::m_logUintBitLength = LogDtype<uint_type>::value;

//constant static member variable initialization of m_nSize which is size of the array of unit data type
template<typename uint_type,usint BITLENGTH>
const usint BigBinaryInteger<uint_type,BITLENGTH>::m_nSize = BITLENGTH%m_uintBitLength==0 ? BITLENGTH/m_uintBitLength : BITLENGTH/m_uintBitLength + 1;

//constant static member variable initialization of m_uintMax which is maximum value of unit data type
template<typename uint_type,usint BITLENGTH>
const uint_type BigBinaryInteger<uint_type,BITLENGTH>::m_uintMax = std::numeric_limits<uint_type>::max();

// DTS:
// this seems to be the traditional "round up to the next power of two" function, except that ceilIntByUInt(0) == 1
//
// ((number+(1<<m_uintBitLength)-1)>>m_uintBitLength);
// where m_uintBitLength = 8*sizeof(uint_type)
//
//optimized ceiling function after division by number of bits in the interal data type.
template<typename uint_type,usint BITLENGTH>
uint_type BigBinaryInteger<uint_type,BITLENGTH>::ceilIntByUInt(const uint_type Number){
	//mask to perform bitwise AND
	//static uint_type mask = m_uintBitLength-1;
	uint_type mask = m_uintBitLength - 1;

	if ((Number&mask) != 0)
		return (Number >> m_logUintBitLength) + 1;
	else if (!Number)
		return 1;
	else
		return Number>>m_logUintBitLength;
}

//CONSTRUCTORS
template<typename uint_type,usint BITLENGTH>
BigBinaryInteger<uint_type,BITLENGTH>::BigBinaryInteger()
{
	//last base-r digit set to 0
	this->m_value[m_nSize-1] = 0;
	//MSB set to zero since value set to ZERO
	this->m_MSB = 0;

}

template<typename uint_type,usint BITLENGTH>
BigBinaryInteger<uint_type,BITLENGTH>::BigBinaryInteger(uint64_t init){
	//setting the MSB
	usint msb = GetMSB32(init);

	uint_type ceilInt = ceilIntByUInt(msb);
	//setting the values of the array
	for(sint i= m_nSize-1;i>= m_nSize-ceilInt;i--){
		this->m_value[i] = (uint_type)init;
		init>>=m_uintBitLength;
	}

	this->m_MSB = msb;

}

template<typename uint_type,usint BITLENGTH>
BigBinaryInteger<uint_type,BITLENGTH>::BigBinaryInteger(const std::string& str){
	//setting the array values from the string
	AssignVal(str);
}

template<typename uint_type,usint BITLENGTH>
BigBinaryInteger<uint_type,BITLENGTH>::BigBinaryInteger(const BigBinaryInteger& bigInteger){
	m_MSB = bigInteger.m_MSB;
	//copy array values
	for (size_t i=0; i < m_nSize; ++i) {
		m_value[i] = bigInteger.m_value[i];
	}
}

//template<typename uint_type,usint BITLENGTH>
//BigBinaryInteger<uint_type,BITLENGTH>::BigBinaryInteger(BigBinaryInteger &&bigInteger){
//	//copy MSB
//	m_MSB = bigInteger.m_MSB;
//	//copy array values
//	for (size_t i=0; i < m_nSize; ++i) {
//		m_value[i] = bigInteger.m_value[i];
//	}
//}

template<typename uint_type,usint BITLENGTH>
std::function<unique_ptr<BigBinaryInteger<uint_type,BITLENGTH>>()> BigBinaryInteger<uint_type,BITLENGTH>::Allocator = [](){
	return lbcrypto::make_unique<cpu_int::BigBinaryInteger<uint_type,BITLENGTH>>();
};

template<typename uint_type,usint BITLENGTH>
BigBinaryInteger<uint_type,BITLENGTH>::~BigBinaryInteger()
{	
}

/**
*Converts the BigBinaryInteger to unsigned integer or returns the first 32 bits of the BigBinaryInteger.
*Splits the BigBinaryInteger into bit length of uint data type and then uses shift and add to form the 32 bit unsigned integer.
*/
template<typename uint_type, usint BITLENGTH>
uint64_t BigBinaryInteger<uint_type, BITLENGTH>::ConvertToInt() const{

	uint64_t result = 0;
	//set num to number of equisized chunks
	usint num = 64 / m_uintBitLength;

	usint ceilInt = m_nSize - ceilIntByUInt(m_MSB);
	//copy the values by shift and add
	for (usint i = 0; i < num && (m_nSize - i - 1) >= ceilInt; i++){
		result += (this->m_value[m_nSize - i - 1] << (m_uintBitLength*i));
	}
	return result;
}

//Converts the BigBinaryInteger to double using the std library functions.
template<typename uint_type, usint BITLENGTH>
double BigBinaryInteger<uint_type,BITLENGTH>::ConvertToDouble() const{
	return std::stod(this->ToString());
}

template<typename uint_type,usint BITLENGTH>
const BigBinaryInteger<uint_type,BITLENGTH>&  BigBinaryInteger<uint_type,BITLENGTH>::operator=(const BigBinaryInteger &rhs){

	if(this!=&rhs){
	    this->m_MSB = rhs.m_MSB;
		for (size_t i=0; i < m_nSize; ++i) {
			m_value[i] = rhs.m_value[i];
		}
	}
	
	return *this;
}

//template<typename uint_type,usint BITLENGTH>
//const BigBinaryInteger<uint_type,BITLENGTH>&  BigBinaryInteger<uint_type,BITLENGTH>::operator=(BigBinaryInteger &&rhs){
//
//	if(this!=&rhs){
//        this->m_MSB = rhs.m_MSB;
//		for (size_t i=0; i < m_nSize; ++i) {
//			m_value[i] = rhs.m_value[i];
//		}
//    }
//
//    return *this;
//}

/**
*	Left Shift is done by splitting the number of shifts into
*1. Multiple of the bit length of uint data type.
*	Shifting is done by the shifting the uint type numbers.
*2. Shifts between 1 to bit length of uint data type.
*   Shifting is done by using bit shift operations and carry over propagation.
*/
template<typename uint_type,usint BITLENGTH>
BigBinaryInteger<uint_type,BITLENGTH>  BigBinaryInteger<uint_type,BITLENGTH>::operator<<(usshort shift) const{

	if(this->m_MSB==0)
		return BigBinaryInteger(ZERO);

	BigBinaryInteger ans(*this);
	//check for OVERFLOW
	if((ans.m_MSB+shift) > BITLENGTH )
		throw std::logic_error("OVERFLOW");

	usint shiftByUint = shift>>m_logUintBitLength;

	usshort remShift = (shift&(m_uintBitLength-1));

	if(remShift!=0){
		uint_type endVal = m_nSize - ceilIntByUInt(m_MSB);
		uint_type oFlow = 0;
		Duint_type temp = 0;
		sint i;
		// DTS- BUG FIX!!!!! (signed < unsigned(0) is always true)
		for(i=m_nSize-1;i>=static_cast<sint>(endVal);i--){
			temp = ans.m_value[i];
			temp <<=remShift;
			ans.m_value[i] = (uint_type)temp + oFlow;
			oFlow = temp >> m_uintBitLength;
		}
		if(i>-1)
			ans.m_value[i] = oFlow;

		ans.m_MSB += remShift;

	}

	if(shiftByUint!=0){
		usint i= m_nSize - ceilIntByUInt(ans.m_MSB);
		for(;i<m_nSize;i++){
			ans.m_value[i-shiftByUint] = ans.m_value[i]; 
		}

		for(usint j=0;j<shiftByUint;j++)
			ans.m_value[m_nSize-1-j] = 0;

	}


	ans.m_MSB += shiftByUint*m_uintBitLength;	

	return ans;

}

/**
*	Left Shift is done by splitting the number of shifts into
*1. Multiple of the bit length of uint data type.
*	Shifting is done by the shifting the uint type numbers.
*2. Shifts between 1 to bit length of uint data type.
*   Shifting is done by using bit shift operations and carry over propagation.
*/
template<typename uint_type,usint BITLENGTH>
const BigBinaryInteger<uint_type,BITLENGTH>&  BigBinaryInteger<uint_type,BITLENGTH>::operator<<=(usshort shift){

	if(this->m_MSB==0)
		return *this;

	//first check whether shifts are possible without overflow
	if(this->m_MSB+shift > BITLENGTH)
		throw std::logic_error ("OVERFLOW");

	//calculate the no.of shifts
	usint shiftByUint = shift>>m_logUintBitLength;

	uint_type remShift = (shift&(m_uintBitLength-1));

	if(remShift!=0){

		uint_type endVal = m_nSize-ceilIntByUInt(this->m_MSB);
		uint_type oFlow = 0;
		Duint_type temp = 0;
		sint i ;
		// DTS- BUG FIX!!!!! (endVal may be computed <0)
		for(i=m_nSize-1; i>= static_cast<sint>(endVal); i--){
			temp = this->m_value[i];
			temp <<= remShift;
			this->m_value[i] = (uint_type)temp + oFlow;
			oFlow = temp>>m_uintBitLength;		
		}

		if(i>-1)
			this->m_value[i] = oFlow;

		this->m_MSB += remShift;

	}

	if(shiftByUint!=0){
		usint i= m_nSize-ceilIntByUInt(this->m_MSB);
		for(;i<m_nSize;i++){
			this->m_value[i-shiftByUint] = this->m_value[i]; 
		}

		for(usint i=0;i<shiftByUint;i++)
			this->m_value[m_nSize-1-i] = 0;

	}


	this->m_MSB += shiftByUint*m_uintBitLength;	

	return *this;

}

/**Right Shift is done by splitting the number of shifts into
*1. Multiple of the bit length of uint data type.
*	Shifting is done by the shifting the uint type numbers in the array to the right.
*2. Shifts between 1 to bit length of uint data type.
*   Shifting is done by using bit shift operations and carry over propagation.
*/
template<typename uint_type,usint BITLENGTH>
BigBinaryInteger<uint_type,BITLENGTH>  BigBinaryInteger<uint_type,BITLENGTH>::operator>>(usshort shift) const{

	//trivial cases
	if(this->m_MSB==0 || this->m_MSB <= shift)
		return BigBinaryInteger(0);
	 
	
	BigBinaryInteger ans(*this);
	//no of array shifts
	usint shiftByUint = shift>>m_logUintBitLength;
	//no of bit shifts
	uint_type remShift = (shift&(m_uintBitLength-1));

	if(shiftByUint!=0){
		//termination index counter
		usint endVal= m_nSize-ceilIntByUInt(ans.m_MSB);
		usint j= endVal;
		//array shifting operation
		for(sint i= m_nSize-1-shiftByUint;i>=static_cast<sint>(endVal);i--){
			ans.m_value[i+shiftByUint] = ans.m_value[i];
		}
		//msb adjusted to show the shifts
		ans.m_MSB -= shiftByUint<<m_logUintBitLength;
		//nulling the removed uints from the array
		while(shiftByUint>0){
			ans.m_value[j] = 0;
			shiftByUint--;
			j++;
		}

	}
	//bit shifts
	if(remShift!=0){

		uint_type overFlow = 0;
		uint_type oldVal;
		uint_type maskVal = ((uint_type)1<<(remShift))-1;
		uint_type compShiftVal = m_uintBitLength- remShift;

		usint startVal = m_nSize - ceilIntByUInt(ans.m_MSB);
		//perform shifting by bits by calculating the overflow
		//oveflow is added after the shifting operation
		for( ;startVal<m_nSize;startVal++){

			oldVal = ans.m_value[startVal];

			ans.m_value[startVal] = (ans.m_value[startVal]>>remShift) + overFlow;

			overFlow = (oldVal &  maskVal);
			overFlow <<= compShiftVal ;
		}

		ans.m_MSB -= remShift;

	}

	return ans;



}


/**Right Shift is done by splitting the number of shifts into
*1. Multiple of the bit length of uint data type.
*	Shifting is done by the shifting the uint type numbers in the array to the right.
*2. Shifts between 1 to bit length of uint data type.
*   Shifting is done by using bit shift operations and carry over propagation.
*/
template<typename uint_type,usint BITLENGTH>
BigBinaryInteger<uint_type,BITLENGTH>&  BigBinaryInteger<uint_type,BITLENGTH>::operator>>=(usshort shift){

	if(this->m_MSB==0 )
		return *this;
	else if(this->m_MSB<=shift){
		*this = ZERO;
		return *this;
	}

	//no of array shifts
	usint shiftByUint = shift>>m_logUintBitLength;
	//no of bit shifts
	uschar remShift = (shift&(m_uintBitLength-1));
	//perform shifting in arrays
	if(shiftByUint!=0){

		usint endVal= m_nSize-ceilIntByUInt(this->m_MSB);
		usint j= endVal;
		
                // DTS: watch sign/unsign compare!!!!
		for(sint i= m_nSize-1-shiftByUint;i>=static_cast<sint>(endVal);i--){
			this->m_value[i+shiftByUint] = this->m_value[i];
		}
		//adjust shift to reflect left shifting 
		this->m_MSB -= shiftByUint<<m_logUintBitLength;

		while(shiftByUint>0){
			this->m_value[j] = 0;
			shiftByUint--;
			j++;
		}

		
	}

	
	//perform shift by bits if any
	if(remShift!=0){

		uint_type overFlow = 0;
		uint_type oldVal;
		uint_type maskVal = ((uint_type)1<<(remShift))-1;
		uint_type compShiftVal = m_uintBitLength- remShift;

		usint startVal = m_nSize - ceilIntByUInt(this->m_MSB);
		//shift and add the overflow from the previous position
		for( ;startVal<m_nSize;startVal++){

			oldVal = this->m_value[startVal];

			this->m_value[startVal] = (this->m_value[startVal]>>remShift) + overFlow;

			overFlow = (oldVal &  maskVal);
			overFlow <<= compShiftVal ;
		}

		this->m_MSB -= remShift;

	}

	return *this;	

}


template<typename uint_type,usint BITLENGTH>
void BigBinaryInteger<uint_type,BITLENGTH>::PrintValueInDec() const{

	sint i= m_MSB%m_uintBitLength==0&&m_MSB!=0? m_MSB/m_uintBitLength:(sint)m_MSB/m_uintBitLength +1;
	for(i=m_nSize-i;i<m_nSize;i++)//actual
    //(i=0;i<Nchar;i++)//for debug
	    std::cout<<std::dec<<(uint_type)m_value[i]<<".";

    std::cout<<std::endl;
}

// the array and the next two functions convert a BigBinaryInteger in and out of a string of characters
// the encoding is Base64-like: the first 5 6-bit groupings are Base64 encoded, and the last 2 bits are A-D

// Note this is, sadly, hardcoded for 32 bit integers and needs Some Work to handle arbitrary sizes

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
 * The scheme here is to take each of the uint_types in the BigBinaryInteger
 * and turn it into 6 ascii characters. It's basically Base64 encoding: 6 bits per character
 * times 5 is the first 30 bits. For efficiency's sake, the last two bits are encoded as A,B,C, or D
 * and the code is implemented as unrolled loops
 */
template<typename uint_type,usint BITLENGTH>
const std::string BigBinaryInteger<uint_type,BITLENGTH>::Serialize() const {

	std::string ans = "";
	const uint_type *fromP;

	sint siz = (m_MSB%m_uintBitLength==0&&m_MSB!=0) ? (m_MSB/m_uintBitLength) : ((sint)m_MSB/m_uintBitLength +1);
	int i;
	for(i=m_nSize-1, fromP=m_value+i ; i>=m_nSize-siz ; i--,fromP--) {
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
template<typename uint_type, usint BITLENGTH>
const char *BigBinaryInteger<uint_type, BITLENGTH>::Deserialize(const char *cp){

	sint i = m_nSize-1;
	uint_type *msbInt = &m_value[i];

	usint counter = 0;

	while( *cp != '\0' && *cp != '|' ) {
		uint_type converted =  base64_to_value(*cp++) << b64_shifts[0];
		converted |= base64_to_value(*cp++) << b64_shifts[1];
		converted |= base64_to_value(*cp++) << b64_shifts[2];
		converted |= base64_to_value(*cp++) << b64_shifts[3];
		converted |= base64_to_value(*cp++) << b64_shifts[4];
		converted |= ((*cp++ - 'A')&0x3) << b64_shifts[5];
		m_value[i] = converted;
		counter++;
		i--;
	}

	m_MSB = GetMSB32(m_value[i+1])+(counter-1)*32; // 32 should be something better: (sizeof(uint_type)*8 ??

	return cp;
}


template<typename uint_type,usint BITLENGTH>
usshort BigBinaryInteger<uint_type,BITLENGTH>::GetMSB()const{
	return m_MSB;
}

/** Addition operation:
*  Algorithm used is usual school book sum and carry-over, expect for that radix is 2^m_bitLength.
*/
template<typename uint_type,usint BITLENGTH>
BigBinaryInteger<uint_type,BITLENGTH> BigBinaryInteger<uint_type,BITLENGTH>::Plus(const BigBinaryInteger& b) const{
	
	//two operands A and B for addition, A is the greater one, B is the smaller one
    const BigBinaryInteger* A = NULL;
	const BigBinaryInteger* B = NULL;

	//Assignment of pointers, A assigned the higher value and B assigned the lower value
	if(*this>b){
		A = this; B = &b;
	}
	else {A = &b; B = this;}

	if(B->m_MSB==0)
		return BigBinaryInteger(*A);

	BigBinaryInteger result;

	//overflow variable
	Duint_type ofl=0;
	//position from A to start addition
	uint_type ceilIntA = ceilIntByUInt(A->m_MSB);
	//position from B to start addition
	uint_type ceilIntB = ceilIntByUInt(B->m_MSB);
	sint i;//counter
        // DTS: TODO: verify that the sign/unsigned compare is valid here. it seems to have the same form as the bugs fixed above, but i did not observe any crashes in this function (perhaps it was never exercised)
        // a safer alternative would be something like what follows (the loops i fixed above could use the same structure; note all variables become unsigned and all loop indices start from zero):
        // for (usint j = 0; j < m_nSize - CeilIntB /*&& j < m_nSize*/; ++j) {
        //    usint i = m_nSize - 1 -j ;
        //    ...
        // }
	for(i=m_nSize-1;i>=m_nSize-ceilIntB;i--){
		ofl =(Duint_type)A->m_value[i]+ (Duint_type)B->m_value[i]+ofl;//sum of the two int and the carry over
		result.m_value[i] = (uint_type)ofl;
		ofl>>=m_uintBitLength;//current overflow
	}

	if(ofl){
		for(;i>=m_nSize-ceilIntA;i--){
			ofl = (Duint_type)A->m_value[i]+ofl;//sum of the two int and the carry over
			result.m_value[i] = (uint_type)ofl;
			ofl>>=m_uintBitLength;//current overflow
		}

		if(ofl){//in the end if overflow is set it indicates MSB is one greater than the one we started with
			result.m_value[m_nSize-ceilIntA-1] = 1;
			result.m_MSB = A->m_MSB + 1;
		}
		else{
			result.m_MSB = (m_nSize - i - 2)*m_uintBitLength;
			result.m_MSB += GetMSBUint_type(result.m_value[++i]);
		}
	}
	else{
		for(;i>=m_nSize-ceilIntA;i--){
			result.m_value[i] = A->m_value[i];
		}
		result.m_MSB =  (m_nSize - i - 2)*m_uintBitLength;
		result.m_MSB += GetMSBUint_type(result.m_value[++i]);
	}

	return result;
}

/** Minus operation:
*  Algorithm used is usual school book borrow and subtract, except for that radix is 2^m_bitLength.
*/
template<typename uint_type,usint BITLENGTH>
BigBinaryInteger<uint_type,BITLENGTH> BigBinaryInteger<uint_type,BITLENGTH>::Minus(const BigBinaryInteger& b) const{

	//return 0 if b is higher than *this as there is no support for negative number
	if(!(*this>b))
		return BigBinaryInteger(ZERO);

        // DTS: note: these variables are confusing. if you look close you will find (a) they are only inside the inner if block (cntr=0 is superfluous); (b) current simply equals i (neither changes after the current=i assignment); and (c) the while loop needs to check cntr >= 0 (when m_value[] == 0...)
	int cntr=0,current=0;
	
        // DTS: (see Plus(), above) this function uses [signed] int for endValA and endValB, unlike all the similar loops in the previous functions. (why does this combine int and sint? sure, all the values should be small, )
	BigBinaryInteger result(*this);
	//array position in A to end substraction
	int endValA = m_nSize-ceilIntByUInt(this->m_MSB);
	//array position in B to end substraction
	int endValB = m_nSize-ceilIntByUInt(b.m_MSB);
	sint i;
	for(i=m_nSize-1;i>=endValB;i--){
		//carryover condtion
		if(result.m_value[i]<b.m_value[i]){
			current=i;
			cntr = current-1;
			//assigning carryover value
			// DTS: added check against cntr being < 0 (I think)
			while(cntr>=0 && result.m_value[cntr]==0){
				result.m_value[cntr]=m_uintMax;cntr--;
			}
			// DTS: probably need to check cntr >= 0 here, too
			result.m_value[cntr]--;
			result.m_value[i]=result.m_value[i]+m_uintMax+1- b.m_value[i];		
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
	result.m_MSB = (m_nSize-endValA-1)*m_uintBitLength + GetMSBUint_type(result.m_value[endValA]);

	//return the result
	return result;

}

/** Times operation:
*  Algorithm used is usual school book shift and add after multiplication, except for that radix is 2^m_bitLength.
*/
template<typename uint_type,usint BITLENGTH>
void BigBinaryInteger<uint_type, BITLENGTH>::Times(const BigBinaryInteger& b, BigBinaryInteger *ans) const {

	//BigBinaryInteger ans;

	//if one of them is zero
	if (b.m_MSB == 0 || this->m_MSB == 0) {
		*ans = ZERO;
		return;
		//return ans;
	}

	//check for trivial conditions
	if (b.m_MSB == 1) {
		*ans = *this;
		return;
	}
	if (this->m_MSB == 1) {
		*ans = b;
		return;
	}
	
	//position of B in the array where the multiplication should start
	uint_type ceilInt = ceilIntByUInt(b.m_MSB);
	//Multiplication is done by getting a uint_type from b and multiplying it with *this
	//after multiplication the result is shifted and added to the final answer
	BigBinaryInteger temp;
	for(sint i= m_nSize-1;i>= m_nSize-ceilInt;i--){
		this->MulIntegerByCharInPlace(b.m_value[i], &temp);
		*ans += temp<<=( m_nSize-1-i)*m_uintBitLength;
	}

	return;

	//return ans;
}


template<typename uint_type,usint BITLENGTH>
const BigBinaryInteger<uint_type,BITLENGTH>& BigBinaryInteger<uint_type,BITLENGTH>::operator+=(const BigBinaryInteger &b){
	const BigBinaryInteger* A = NULL;//two operands A and B for addition, A is the greater one, B is the smaller one
	const BigBinaryInteger* B = NULL;

	//check for trivial cases
	if(b.m_MSB==0){
		return *this;
	}

	//assigning pointers, A is assigned higher value and B the lower one
	if(this->m_MSB > b.m_MSB){
	//if(*this>b){
		A = this; B = &b;
	}
	else {A = &b; B = this;}
	//overflow variable
	Duint_type ofl=0;
	//position in the array of A to start addition 
	uint_type ceilIntA = ceilIntByUInt(A->m_MSB);
	//position in the array of B to start addition
	uint_type ceilIntB = ceilIntByUInt(B->m_MSB);

	//counter
	sint i;
        // DTS: watch sign/unsign compare!!!!
	for(i=m_nSize-1;i>=m_nSize-ceilIntB;i--){
		ofl =(Duint_type)A->m_value[i]+ (Duint_type)B->m_value[i]+ofl;//sum of the two apint and the carry over
		this->m_value[i] = (uint_type)ofl;
		ofl>>=m_uintBitLength;//current overflow
	}

	if(ofl){
		// DTS: watch sign/unsign compare!!!!
		for(;i>=static_cast<sint>(m_nSize-ceilIntA);i--){
			ofl = (Duint_type)A->m_value[i]+ofl;//sum of the two int and the carry over
			this->m_value[i] = (uint_type)ofl;
			ofl>>=m_uintBitLength;//current overflow
		}

		if(ofl){//in the end if overflow is set it indicates MSB is one greater than the one we started with
			this->m_value[m_nSize-ceilIntA-1] = 1;
			this->m_MSB = A->m_MSB + 1;
		}
		else{
			this->m_MSB = (m_nSize - i - 2)*m_uintBitLength;
			this->m_MSB += GetMSBUint_type(this->m_value[++i]);
		}
	}
	else{
		// DTS: watch sign/unsign compare!!!!
		for(;i>=static_cast<sint>(m_nSize-ceilIntA);i--){//NChar-ceil(MSB/8)
			this->m_value[i] = A->m_value[i];
		}
		this->m_MSB = (m_nSize-i-2)*m_uintBitLength;
		this->m_MSB += GetMSBUint_type(this->m_value[++i]);
	}	

	return *this;
}

template<typename uint_type,usint BITLENGTH>
const BigBinaryInteger<uint_type,BITLENGTH>& BigBinaryInteger<uint_type,BITLENGTH>::operator-=(const BigBinaryInteger &b){
	
	if(!(*this>b)){
		*this=ZERO;
		return *this;
	}

	int cntr=0,current=0;

	int endValA = m_nSize-ceilIntByUInt(this->m_MSB);
	int endValB = m_nSize-ceilIntByUInt(b.m_MSB);
	sint i;
	for(i=m_nSize-1;i>=endValB;i--){
		if(this->m_value[i]<b.m_value[i]){
			current=i;
			cntr = current-1;
			// DTS: added cntr >= 0 (see above; probably also need check cntr>=0 before "this->m_value[cntr]--")
			while(cntr>=0 && this->m_value[cntr]==0){
				this->m_value[cntr]=m_uintMax;cntr--;
			}
			this->m_value[cntr]--;
			this->m_value[i]=this->m_value[i]+m_uintMax+1- b.m_value[i];		
		}
		else{
			this->m_value[i]=this->m_value[i]- b.m_value[i];
		}
	}

	while(this->m_value[endValA]==0){
		endValA++;
	}

	this->m_MSB = (m_nSize-endValA-1)*m_uintBitLength + GetMSBUint_type(this->m_value[endValA]);


	return *this;

}

template<typename uint_type, usint BITLENGTH>
BigBinaryInteger<uint_type, BITLENGTH> BigBinaryInteger<uint_type, BITLENGTH>::operator*(const BigBinaryInteger &a) const{
	BigBinaryInteger result;
	this->Times(a, &result);
	return result;
}

/** Times operation:
*  Algorithm used is usual school book multiplication.
*  This function is used in the Multiplication of two BigBinaryInteger objects
*/
template<typename uint_type,usint BITLENGTH>
BigBinaryInteger<uint_type,BITLENGTH> BigBinaryInteger<uint_type,BITLENGTH>::MulIntegerByChar(uint_type b) const{
	
	if(b==0 || this->m_MSB==0)
		return BigBinaryInteger(ZERO);
	
	BigBinaryInteger ans;
	//position in the array to start multiplication
	usint endVal = m_nSize-ceilIntByUInt(m_MSB);
	//variable to capture the overflow
	Duint_type temp=0;
	//overflow value
	uint_type ofl=0;
	sint i= m_nSize-1;

	for(;i>=endVal ;i--){
		temp = ((Duint_type)m_value[i]*(Duint_type)b) + ofl;
		ans.m_value[i] = (uint_type)temp;
		ofl = temp>>m_uintBitLength;
	}
	//check if there is any final overflow
	if(ofl){
		ans.m_value[i]=ofl;
	}
	ans.m_MSB = (m_nSize-1-endVal)*m_uintBitLength;
	//set the MSB after the final computation
	ans.m_MSB += GetMSBDUint_type(temp);

	return ans;
}

/** Times operation:
*  Algorithm used is usual school book multiplication.
*  This function is used in the Multiplication of two BigBinaryInteger objects
*/
template<typename uint_type, usint BITLENGTH>
void BigBinaryInteger<uint_type, BITLENGTH>::MulIntegerByCharInPlace(uint_type b, BigBinaryInteger *ans) const {

	if (b == 0 || this->m_MSB == 0) {
		*ans = ZERO;
		return;
	}

	//BigBinaryInteger ans;
	//position in the array to start multiplication
	usint endVal = m_nSize - ceilIntByUInt(m_MSB);
	//variable to capture the overflow
	Duint_type temp = 0;
	//overflow value
	uint_type ofl = 0;
	sint i = m_nSize - 1;

	for (; i >= endVal; i--) {
		temp = ((Duint_type)m_value[i] * (Duint_type)b) + ofl;
		ans->m_value[i] = (uint_type)temp;
		ofl = temp >> m_uintBitLength;
	}
	//check if there is any final overflow
	if (ofl) {
		ans->m_value[i] = ofl;
	}
	ans->m_MSB = (m_nSize - 1 - endVal)*m_uintBitLength;
	//set the MSB after the final computation
	ans->m_MSB += GetMSBDUint_type(temp);

	return;
}

/* Division operation:
*  Algorithm used is usual school book long division , except for that radix is 2^m_bitLength.
*  Optimization done: Uses bit shift operation for logarithmic convergence.
*/
template<typename uint_type,usint BITLENGTH>
BigBinaryInteger<uint_type,BITLENGTH> BigBinaryInteger<uint_type,BITLENGTH>::DividedBy(const BigBinaryInteger& b) const{
	
	//check for the 0 condition
	if(b==ZERO)
		throw std::logic_error("DIVISION BY ZERO");

	if(b.m_MSB>this->m_MSB)
		return BigBinaryInteger(ZERO);
	else if(b==*this)
		return BigBinaryInteger(ONE);
	
	BigBinaryInteger ans;
	
	//normalised_dividend = result*quotient
	BigBinaryInteger normalised_dividend( this->Minus( this->Mod(b) ) );
	//Number of array elements in Divisor
	uint_type ncharInDivisor = ceilIntByUInt(b.m_MSB);
	//Get the uint integer that is in the MSB position of the Divisor
	uint_type msbCharInDivisor = b.m_value[(usint)( m_nSize-ncharInDivisor)];
	//Number of array elements in Normalised_dividend
	uint_type ncharInNormalised_dividend = ceilIntByUInt(normalised_dividend.m_MSB);
	////Get the uint integer that is in the MSB position of the normalised_dividend
	uint_type msbCharInRunning_Normalised_dividend = normalised_dividend.m_value[(usint)( m_nSize-ncharInNormalised_dividend)];
	//variable to store the running dividend
	BigBinaryInteger running_dividend;
	//variable to store the running remainder
	BigBinaryInteger runningRemainder;
	BigBinaryInteger expectedProd;
	BigBinaryInteger estimateFinder;

	//Initialize the running dividend
	for(usint i=0;i<ncharInDivisor;i++){
		running_dividend.m_value[ m_nSize-ncharInDivisor+i] = normalised_dividend.m_value[ m_nSize-ncharInNormalised_dividend+i]; 
	}
	running_dividend.m_MSB = GetMSBUint_type(running_dividend.m_value[m_nSize-ncharInDivisor]) + (ncharInDivisor-1)*m_uintBitLength;
	
	uint_type estimate=0;
	uint_type maskBit = 0;
	uint_type shifts =0;
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
					maskBit= (uint_type)1<<(m_uintBitLength-1);
				}
				else
					maskBit= (uint_type)1<<(expectedProd.m_MSB-b.m_MSB);
					*/
				shifts = estimateFinder.m_MSB-b.m_MSB;
				if(shifts==m_uintBitLength){
					maskBit= (uint_type)1<<(m_uintBitLength-1);
				}
				else
					maskBit= (uint_type)1<<(shifts);
				
				if((b.MulIntegerByChar(maskBit))>estimateFinder){
					maskBit>>=1;
					estimateFinder-= b<<(shifts-1);
				}
				else if(shifts==m_uintBitLength)
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
			running_dividend.m_MSB=GetMSBUint_type(normalised_dividend.m_value[m_nSize-i]);
		}
		else
			running_dividend = runningRemainder<<m_uintBitLength;

		running_dividend.m_value[ m_nSize-1] = normalised_dividend.m_value[m_nSize-i];	
		if (running_dividend.m_MSB == 0)
			running_dividend.m_MSB = GetMSBUint_type(normalised_dividend.m_value[m_nSize - i]);
		i--;
	}
	ansCtr = m_nSize - ncharInNormalised_dividend+ncharInDivisor-1;
	//Loop to the MSB position
	while(ans.m_value[ansCtr]==0){
		ansCtr++;
	}
	//Computation of MSB value 
	ans.m_MSB = GetMSBUint_type(ans.m_value[ansCtr]) + (m_nSize-1-ansCtr)*m_uintBitLength;

	return ans;

}

//Initializes the array of uint_array from the string equivalent of BigBinaryInteger
//Algorithm used is repeated division by 2
//Reference:http://pctechtips.org/convert-from-decimal-to-binary-with-recursion-in-java/
template<typename uint_type,usint BITLENGTH>
void BigBinaryInteger<uint_type,BITLENGTH>::AssignVal(const std::string& v){

	uschar *DecValue;//array of decimal values
	int arrSize=v.length();
	
	//memory allocated for decimal array
	DecValue = new uschar[arrSize];
	
	for(sint i=0;i<arrSize;i++)//store the string to decimal array
		DecValue[i] = (uschar) atoi(v.substr(i,1).c_str());
		//DecValue[i] = (uschar) stoi(v.substr(i,1));
	sshort zptr = 0;
	//index of highest non-zero number in decimal number
	//define  bit register array
	uschar *bitArr = new uschar[m_uintBitLength]();
	
	sint bitValPtr=m_nSize-1;
	//bitValPtr is a pointer to the Value char array, initially pointed to the last char
	//we increment the pointer to the next char when we get the complete value of the char array
	
	sint cnt=m_uintBitLength-1;
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
#ifdef DEBUG
		for(int i=zptr;i<arrSize;i++)
			cout<<(short)DecValue[i];//for debug purpose
		cout<<endl;
#endif
		cnt--;
		if(cnt==-1){//cnt = -1 indicates bitArr is ready for transfer
			cnt=m_uintBitLength-1;
			m_value[bitValPtr--]= UintInBinaryToDecimal(bitArr);//UintInBinaryToDecimal converts bitArr to decimal and resets the content of bitArr.
		}
		if(DecValue[zptr]==0)zptr++;//division makes Most significant digit zero, hence we increment zptr to next value
		if(zptr==arrSize&&DecValue[arrSize-1]==0)m_value[bitValPtr]=UintInBinaryToDecimal(bitArr);//Value assignment
	}
	SetMSB(bitValPtr);
	delete []bitArr;
	delete[] DecValue;//deallocate memory

}

template<typename uint_type,usint BITLENGTH>
void BigBinaryInteger<uint_type,BITLENGTH>::SetMSB()
{

	m_MSB = 0;
	
	for(usint i=0;i<m_nSize;i++)//loops to find first nonzero number in char array
		if((Duint_type)m_value[i]!=0){
			
			m_MSB = (m_nSize-i-1)*m_uintBitLength; 
			m_MSB+= GetMSBUint_type(m_value[i]);
			break;
		}
}

//guessIdx is the index of largest uint_type number in array.
template<typename uint_type, usint BITLENGTH>
void BigBinaryInteger<uint_type, BITLENGTH>::SetMSB(usint guessIdxChar){

	m_MSB = (m_nSize - guessIdxChar - 1)*m_uintBitLength;
	m_MSB += GetMSBUint_type(m_value[guessIdxChar]);
}

template<typename uint_type, usint BITLENGTH>
void BigBinaryInteger<uint_type, BITLENGTH>::SetValue(const std::string& str){
	AssignVal(str);
}

//Algorithm used: Repeated substraction by a multiple of modulus, which will be referred to as "Classical Modulo Reduction Algorithm"
//Complexity: O(log(*this)-log(modulus))
template<typename uint_type,usint BITLENGTH>
BigBinaryInteger<uint_type,BITLENGTH> BigBinaryInteger<uint_type,BITLENGTH>::Mod(const BigBinaryInteger& modulus) const{

	//return the same value if value is less than modulus
	if(*this<modulus){
		return BigBinaryInteger(*this);
	}
	//masking operation if modulus is 2
	if(modulus.m_MSB==2 && modulus.m_value[m_nSize-1]==2){
		if(this->m_value[m_nSize-1]%2==0)
			return BigBinaryInteger(ZERO);
		else
			return BigBinaryInteger(ONE);
	}
	
	Duint_type initial_shift = 0;
	//No of initial left shift that can be performed which will make it comparable to the current value.
	if(this->m_MSB > modulus.m_MSB)
		initial_shift=this->m_MSB - modulus.m_MSB -1;

	
	BigBinaryInteger j = modulus<<initial_shift;

	
	BigBinaryInteger result(*this);

	BigBinaryInteger temp;
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

	return result;
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
template<typename uint_type,usint BITLENGTH>
BigBinaryInteger<uint_type,BITLENGTH> BigBinaryInteger<uint_type,BITLENGTH>::ModBarrett(const BigBinaryInteger& modulus, const BigBinaryInteger& mu) const{
	
	if(*this<modulus){
		return BigBinaryInteger(*this);
	}
	BigBinaryInteger z(*this);
	BigBinaryInteger q(*this);

	usint n = modulus.m_MSB;
	usint alpha = n + 3;
	sint beta = -2;

	q>>=n + beta;
	q = q*mu;
	q>>=alpha-beta;
	z-=q*modulus;
	
	if(!(z<modulus))
		z-=modulus;
	
	return z;

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
template<typename uint_type, usint BITLENGTH>
void BigBinaryInteger<uint_type, BITLENGTH>::ModBarrettInPlace(const BigBinaryInteger& modulus, const BigBinaryInteger& mu) {

	if (*this<modulus) {
		return;
	}

	BigBinaryInteger q(*this);

	usint n = modulus.m_MSB;
	usint alpha = n + 3;
	sint beta = -2;

	q >>= n + beta;
	q = q*mu;
	q >>= alpha - beta;
	*this -= q*modulus;

	if (!(*this<modulus))
		*this -= modulus;

	return;

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
We take \alpha equal to n + 3. In this case, we work with an array of precomputed \mu values.
**/
template<typename uint_type,usint BITLENGTH>
BigBinaryInteger<uint_type,BITLENGTH> BigBinaryInteger<uint_type,BITLENGTH>::ModBarrett(const BigBinaryInteger& modulus, const BigBinaryInteger mu_arr[BARRETT_LEVELS+1]) const{

	if(*this<modulus){
		BigBinaryInteger z(*this);
		return z;
	}
	BigBinaryInteger z(*this);
	BigBinaryInteger q(*this);

	uschar n = modulus.m_MSB;
	//level is set to the index between 0 and BARRET_LEVELS - 1
	uschar level = (this->m_MSB-1-n)*BARRETT_LEVELS/(n+1)+1;
	uschar gamma = (n*level)/BARRETT_LEVELS;

	uschar alpha = gamma + 3;
	schar beta = -2;

	const BigBinaryInteger& mu = mu_arr[level];

	q>>=n + beta;
	q=q*mu;
	q>>=alpha-beta;
	z-=q*modulus;
	
	if(z>=modulus)
		z-=modulus;
	
	return z;

}

//Extended Euclid algorithm used to find the multiplicative inverse
template<typename uint_type,usint BITLENGTH>
BigBinaryInteger<uint_type,BITLENGTH> BigBinaryInteger<uint_type,BITLENGTH>::ModInverse(const BigBinaryInteger& modulus) const{
	
	BigBinaryInteger result;

	std::vector<BigBinaryInteger> mods;
	std::vector<BigBinaryInteger> quotient;
	mods.push_back(BigBinaryInteger(modulus));
	if (*this>modulus)
		mods.push_back(this->Mod(modulus));
	else
		mods.push_back(BigBinaryInteger(*this));

	BigBinaryInteger first(mods[0]);
	BigBinaryInteger second(mods[1]);
	if(mods[1]==ONE){
		result = ONE;
		return result;
	}

	//Error if modulus is ZERO
	if(*this==ZERO){
		throw std::logic_error("Zero does not have a ModInverse");
	}

	
	//NORTH ALGORITHM
	while(true){
		mods.push_back(first.Mod(second));
		quotient.push_back(first.DividedBy(second));
		if(mods.back()==ONE)
			break;
		if(mods.back()==ZERO){
			std::string msg = this->ToString() + " does not have a ModInverse using " + modulus.ToString();
			throw std::logic_error(msg);
		}
		
		first = second;
		second = mods.back();
	}

	mods.clear();
	mods.push_back(BigBinaryInteger(ZERO));
	mods.push_back(BigBinaryInteger(ONE));

	first = mods[0];
	second = mods[1];
	//SOUTH ALGORITHM
	for(sint i=quotient.size()-1;i>=0;i--){
		mods.push_back(quotient[i]*second + first);
		first = second;
		second = mods.back();
	}

	
	if(quotient.size()%2==1){
		result = (modulus - mods.back());
	}
	else{
		result = BigBinaryInteger(mods.back());
	}

	mods.clear();
	quotient.clear();

	return result;

}

template<typename uint_type,usint BITLENGTH>
BigBinaryInteger<uint_type,BITLENGTH> BigBinaryInteger<uint_type,BITLENGTH>::ModAdd(const BigBinaryInteger& b, const BigBinaryInteger& modulus) const{
	return this->Plus(b).Mod(modulus);
}

//Optimized Mod Addition using ModBarrett
template<typename uint_type,usint BITLENGTH>
BigBinaryInteger<uint_type,BITLENGTH> BigBinaryInteger<uint_type,BITLENGTH>::ModBarrettAdd(const BigBinaryInteger& b, const BigBinaryInteger& modulus,const BigBinaryInteger mu_arr[BARRETT_LEVELS]) const{
	return this->Plus(b).ModBarrett(modulus,mu_arr);
}

template<typename uint_type,usint BITLENGTH>
BigBinaryInteger<uint_type,BITLENGTH> BigBinaryInteger<uint_type,BITLENGTH>::ModBarrettAdd(const BigBinaryInteger& b, const BigBinaryInteger& modulus,const BigBinaryInteger& mu) const{
	return this->Plus(b).ModBarrett(modulus,mu);
}

template<typename uint_type,usint BITLENGTH>
BigBinaryInteger<uint_type,BITLENGTH> BigBinaryInteger<uint_type,BITLENGTH>::ModSub(const BigBinaryInteger& b, const BigBinaryInteger& modulus) const{
	BigBinaryInteger* a = const_cast<BigBinaryInteger*>(this);
	BigBinaryInteger* b_op = const_cast<BigBinaryInteger*>(&b);

	//reduce this to a value lower than modulus
	if(*this>modulus){

		*a = this->Mod(modulus);
	}
	//reduce b to a value lower than modulus
	if(b>modulus){
		*b_op = b.Mod(modulus);
	}

	if(*a>=*b_op){
		return ((*a-*b_op).Mod(modulus));		
	}
	else{
		return ((*a + modulus) - *b_op);
	}
}

//Optimized Mod Substraction using ModBarrett
template<typename uint_type,usint BITLENGTH>
BigBinaryInteger<uint_type,BITLENGTH> BigBinaryInteger<uint_type,BITLENGTH>::ModBarrettSub(const BigBinaryInteger& b, const BigBinaryInteger& modulus,const BigBinaryInteger& mu) const{

	BigBinaryInteger* a = NULL;
	BigBinaryInteger* b_op = NULL;

	if(*this>modulus){
		*a = this->ModBarrett(modulus,mu);
	}
	else{
		a = const_cast<BigBinaryInteger*>(this);
	}

	if(b>modulus){
		*b_op = b.ModBarrett(modulus,mu);
	}
	else{
		b_op = const_cast<BigBinaryInteger*>(&b);
	}

	if(!(*a<*b_op)){
		return ((*a-*b_op).ModBarrett(modulus,mu));
		
	}
	else{
		return ((*a + modulus) - *b_op);
	}
}


template<typename uint_type,usint BITLENGTH>
BigBinaryInteger<uint_type,BITLENGTH> BigBinaryInteger<uint_type,BITLENGTH>::ModBarrettSub(const BigBinaryInteger& b, const BigBinaryInteger& modulus,const BigBinaryInteger mu_arr[BARRETT_LEVELS]) const{

	BigBinaryInteger* a = NULL;
	BigBinaryInteger* b_op = NULL;

	if(*this>modulus){
		*a = this->ModBarrett(modulus,mu_arr);
	}
	else{
		a = const_cast<BigBinaryInteger*>(this);
	}

	if(b>modulus){
		*b_op = b.ModBarrett(modulus,mu_arr);
	}
	else{
		b_op = const_cast<BigBinaryInteger*>(&b);
	}

	if(!(*a<*b_op)){
		return ((*a-*b_op).ModBarrett(modulus,mu_arr));
		
	}
	else{
		return ((*a + modulus) - *b_op);
	}

}

template<typename uint_type,usint BITLENGTH>
BigBinaryInteger<uint_type,BITLENGTH> BigBinaryInteger<uint_type,BITLENGTH>::ModMul(const BigBinaryInteger& b, const BigBinaryInteger& modulus) const{
	BigBinaryInteger a(*this);
	BigBinaryInteger bb(b);

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

template<typename uint_type,usint BITLENGTH>
BigBinaryInteger<uint_type,BITLENGTH> BigBinaryInteger<uint_type,BITLENGTH>::ModBarrettMul(const BigBinaryInteger& b, const BigBinaryInteger& modulus,const BigBinaryInteger& mu) const{

	BigBinaryInteger* a  = const_cast<BigBinaryInteger*>(this);
	BigBinaryInteger* bb = const_cast<BigBinaryInteger*>(&b);

	//if a is greater than q reduce a to its mod value
	if(*this>modulus)
		*a = this->ModBarrett(modulus,mu);


	//if b is greater than q reduce b to its mod value
	if(b>modulus)
		*bb = b.ModBarrett(modulus,mu);

	return (*a**bb).ModBarrett(modulus,mu);

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

template<typename uint_type, usint BITLENGTH>
void BigBinaryInteger<uint_type, BITLENGTH>::ModBarrettMulInPlace(const BigBinaryInteger& b, const BigBinaryInteger& modulus, const BigBinaryInteger& mu) {

	//BigBinaryInteger* a = const_cast<BigBinaryInteger*>(this);
	BigBinaryInteger* bb = const_cast<BigBinaryInteger*>(&b);

	//if a is greater than q reduce a to its mod value
	if (*this>modulus)
		this->ModBarrettInPlace(modulus, mu);


	//if b is greater than q reduce b to its mod value
	if (b>modulus)
		*bb = b.ModBarrett(modulus, mu);

	*this = *this**bb;

	this->ModBarrettInPlace(modulus, mu);

	return;

}


template<typename uint_type,usint BITLENGTH>
BigBinaryInteger<uint_type,BITLENGTH> BigBinaryInteger<uint_type,BITLENGTH>::ModBarrettMul(const BigBinaryInteger& b, const BigBinaryInteger& modulus,const BigBinaryInteger mu_arr[BARRETT_LEVELS]) const{
	BigBinaryInteger* a  = NULL;
	BigBinaryInteger* bb = NULL;

	//if a is greater than q reduce a to its mod value
	if(*this>modulus)
		*a = this->ModBarrett(modulus,mu_arr);
	else
		a = const_cast<BigBinaryInteger*>(this);

	//if b is greater than q reduce b to its mod value
	if(b>modulus)
		*bb = b.ModBarrett(modulus,mu_arr);
	else
		bb = const_cast<BigBinaryInteger*>(&b);

	//return a*b%q

	return (*a**bb).ModBarrett(modulus,mu_arr);
}

//Modular Multiplication using Square and Multiply Algorithm
//reference:http://guan.cse.nsysu.edu.tw/note/expn.pdf
template<typename uint_type,usint BITLENGTH>
BigBinaryInteger<uint_type,BITLENGTH> BigBinaryInteger<uint_type,BITLENGTH>::ModExp(const BigBinaryInteger& b, const BigBinaryInteger& modulus) const{

	#ifdef DEBUG_MODEXP
		std::cout<<*this<<std::endl<<b<<std::endl<<modulus<<std::endl;
	#endif

	//mid is intermidiate value that calculates mid^2%q
	BigBinaryInteger mid = this->Mod(modulus);	

	#ifdef DEBUG_MODEXP
		std::cout<<mid<<"  mid"<<std::endl;
	#endif

	//product calculates the running product of mod values
	BigBinaryInteger product(ONE);

	#ifdef DEBUG_MODEXP
		std::cout<<*product<<"  product"<<std::endl;
	#endif
	//Exp is used for spliting b to bit values/ bit extraction
	BigBinaryInteger Exp(b);

	#ifdef DEBUG_MODEXP
		std::cout<<Exp<<"  Exp"<<std::endl;
	#endif

	while(true){

		
		//product is multiplied only if bitvalue is 1
		if(Exp.m_value[m_nSize-1]%2==1){
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

template<typename uint_type,usint BITLENGTH>
const std::string BigBinaryInteger<uint_type,BITLENGTH>::ToString() const{

	//this string object will store this BigBinaryInteger's value
	std::string bbiString;

	//create reference for the object to be printed
	//BigBinaryInteger<uint_type,BITLENGTH> *print_obj;

	usint counter;

	//initiate to object to be printed
	//print_obj = new BigBinaryInteger<uint_type,BITLENGTH>(*this);

	//print_obj->PrintValueInDec();

	//print_VALUE array stores the decimal value in the array
	uschar *print_VALUE = new uschar[m_numDigitInPrintval];

	//reset to zero
	for(sint i=0;i<m_numDigitInPrintval;i++)
		*(print_VALUE+i)=0;

	//starts the conversion from base r to decimal value
	for(sint i=this->m_MSB;i>0;i--){

		//print_VALUE = print_VALUE*2
		BigBinaryInteger<uint_type,BITLENGTH>::double_bitVal(print_VALUE);	

		//adds the bit value to the print_VALUE
		BigBinaryInteger<uint_type,BITLENGTH>::add_bitVal(print_VALUE,this->GetBitAtIndex(i));


	}

	//find the first occurence of non-zero value in print_VALUE
	for(counter=0;counter<m_numDigitInPrintval-1;counter++){
		if((sint)print_VALUE[counter]!=0)break;							
	}

	//append this BigBinaryInteger's digits to this method's returned string object
	for (; counter < m_numDigitInPrintval; counter++) {
		bbiString += std::to_string(print_VALUE[counter]);
	}

	delete [] print_VALUE;
	//deallocate the memory since values are inserted into the ostream object
	//delete print_obj;

	return bbiString;

}

//Compares the current object with the BigBinaryInteger a.
//Uses MSB comparision to output requisite value.
template<typename uint_type,usint BITLENGTH>
sint BigBinaryInteger<uint_type,BITLENGTH>::Compare(const BigBinaryInteger& a) const
{

	if(this->m_MSB<a.m_MSB)
		return -1;
	else if(this->m_MSB>a.m_MSB)
		return 1;
	if(this->m_MSB==a.m_MSB){
		uschar ceilInt = ceilIntByUInt(this->m_MSB); 
		sshort testChar;
		for(usint i=m_nSize-ceilInt;i< m_nSize;i++){
			testChar = this->m_value[i]-a.m_value[i] ;
			if(testChar<0)return -1;
			else if(testChar>0)return 1;
		}
	}

	return 0;

}

template<typename uint_type,usint BITLENGTH>
bool BigBinaryInteger<uint_type,BITLENGTH>::operator==(const BigBinaryInteger& a) const{

	if(this->m_MSB!=a.m_MSB)
		return false;
	else{
		uschar ceilInt = ceilIntByUInt(a.m_MSB); 
		for(usint i= m_nSize-ceilInt;i< m_nSize;i++)
			if(this->m_value[i]!=a.m_value[i])
				return false;	
	}
	return true;

}

template<typename uint_type,usint BITLENGTH>
bool BigBinaryInteger<uint_type,BITLENGTH>::CheckIfPowerOfTwo(const BigBinaryInteger& m_numToCheck){
	usint m_MSB = m_numToCheck.m_MSB;
	for(int i=m_MSB-1;i>0;i--){
		if((sint)m_numToCheck.GetBitAtIndex(i)==(sint)1){
			return false;
		}
	}
	return true;
}

template<typename uint_type,usint BITLENGTH>
bool BigBinaryInteger<uint_type,BITLENGTH>::operator!=(const BigBinaryInteger& a)const{
	return !(*this==a);
}

template<typename uint_type,usint BITLENGTH>
bool BigBinaryInteger<uint_type,BITLENGTH>::operator>(const BigBinaryInteger& a)const{

	if(this->m_MSB<a.m_MSB)
		return false;
	else if(this->m_MSB>a.m_MSB)
		return true;
	else{
		uschar ceilInt = ceilIntByUInt(this->m_MSB); 
		for(usint i=m_nSize-ceilInt;i< m_nSize;i++){
			if(this->m_value[i]<a.m_value[i])
				return false;
			else if(this->m_value[i]>a.m_value[i])
				return true;
		}

	}
	return false;
}

template<typename uint_type,usint BITLENGTH>
bool BigBinaryInteger<uint_type,BITLENGTH>::operator>=(const BigBinaryInteger& a) const{
	return (*this>a || *this==a);
}

template<typename uint_type,usint BITLENGTH>
bool BigBinaryInteger<uint_type,BITLENGTH>::operator<(const BigBinaryInteger& a) const{

	if(this->m_MSB<a.m_MSB)
		return true;
	else if(this->m_MSB>a.m_MSB)
		return false;
	else{
		uschar ceilInt = ceilIntByUInt(this->m_MSB); 
		for(usint i= m_nSize-ceilInt;i< m_nSize;i++){
			if(this->m_value[i]>a.m_value[i])
				return false;
			else if(this->m_value[i]<a.m_value[i])
				return true;
		}

	}
	return false;

}

template<typename uint_type,usint BITLENGTH>
bool BigBinaryInteger<uint_type,BITLENGTH>::operator<=(const BigBinaryInteger& a) const{
	return (*this<a || *this==a);
}

template<typename uint_type,usint BITLENGTH>
usint BigBinaryInteger<uint_type,BITLENGTH>::GetMSB32(uint64_t x)
{

	if (x != 0) {
#if defined(_MSC_VER)
		unsigned long msb;
		_BitScanReverse64(&msb, x);
		return msb + 1;
#else
		return  64 - __builtin_clzl(x);
#endif
	}
	else
		return 0;

	//static const usint bval[] =
	//{ 0,1,2,2,3,3,3,3,4,4,4,4,4,4,4,4 };

	//uint64_t r = 0;
	//if (x & 0xFFFFFFFF00000000) { r += 32 / 1; x >>= 32 / 1; }
	//if (x & 0x00000000FFFF0000) { r += 32 / 2; x >>= 32 / 2; }
	//if (x & 0x000000000000FF00) { r += 32 / 4; x >>= 32 / 4; }
	//if (x & 0x00000000000000F0) { r += 32 / 8; x >>= 32 / 8; }
	//return r + bval[x];

}

template<typename uint_type,usint BITLENGTH>
usint BigBinaryInteger<uint_type,BITLENGTH>::GetMSBUint_type(uint_type x){
	return BigBinaryInteger<uint_type,BITLENGTH>::GetMSB32(x);
}

template<typename uint_type,usint BITLENGTH>
usint BigBinaryInteger<uint_type,BITLENGTH>::GetDigitAtIndexForBase(usint index, usint base) const{

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
template<typename uint_type,usint BITLENGTH>
BigBinaryInteger<uint_type,BITLENGTH> BigBinaryInteger<uint_type,BITLENGTH>::BinaryStringToBigBinaryInt(const std::string& bitString){
	
	BigBinaryInteger value;
	usint len = bitString.length();
	usint cntr = ceilIntByUInt(len);
	std::string val;
	Duint_type partial_value = 0;
	for (usint i = 0; i < cntr; i++)
	{

		if (len>((i + 1)*m_uintBitLength))
			val = bitString.substr((len - (i + 1)*m_uintBitLength), m_uintBitLength);
		else
			val = bitString.substr(0, len%m_uintBitLength);
		for (usint j = 0; j < val.length(); j++){
			partial_value += std::stoi(val.substr(j, 1));
			partial_value <<= 1;
		}
		partial_value >>= 1;
		value.m_value[m_nSize - 1 - i] = (uint_type)partial_value;
		partial_value = 0;
	}
	value.m_MSB = (cntr - 1)*m_uintBitLength;
	value.m_MSB += GetMSBUint_type(value.m_value[m_nSize - cntr]);
	return value;

}

//Recursive Exponentiation function
template<typename uint_type,usint BITLENGTH>
BigBinaryInteger<uint_type,BITLENGTH> BigBinaryInteger<uint_type,BITLENGTH>::Exp(usint p) const{
	if (p == 0) return BigBinaryInteger(BigBinaryInteger::ONE);
	BigBinaryInteger x(*this);
  	if (p == 1) return x;

	BigBinaryInteger tmp = x.Exp(p/2);
	if (p%2 == 0) return tmp * tmp;
	else return tmp * tmp * x;
}

template<typename uint_type, usint BITLENGTH>
BigBinaryInteger<uint_type, BITLENGTH> BigBinaryInteger<uint_type, BITLENGTH>::MultiplyAndRound(const BigBinaryInteger &p, const BigBinaryInteger &q) const {
	BigBinaryInteger ans(*this);
	ans = ans*p;
	ans = ans.DivideAndRound(q);

	return ans;
}

template<typename uint_type, usint BITLENGTH>
BigBinaryInteger<uint_type, BITLENGTH> BigBinaryInteger<uint_type, BITLENGTH>::DivideAndRound(const BigBinaryInteger &q) const {

	//check for garbage initialization and 0 condition
	if (q == ZERO)
		throw std::logic_error("DIVISION BY ZERO");

	BigBinaryInteger halfQ(q>>1);
	//std::cout<< "halfq "<<halfQ.ToString()<<std::endl;

	if (*this < q) {
		if (*this <= halfQ)
			return BigBinaryInteger(ZERO);
		else
			return BigBinaryInteger(ONE);
	}

	//std::cout<< "*this "<<this->ToString()<<std::endl;
	//std::cout<< "q "<<q.ToString()<<std::endl;

	BigBinaryInteger ans;

	//normalised_dividend = result*quotient
	BigBinaryInteger normalised_dividend(*this);
	//Number of array elements in Divisor
	uint_type ncharInDivisor = ceilIntByUInt(q.m_MSB);
	//Get the uint integer that is in the MSB position of the Divisor
	uint_type msbCharInDivisor = q.m_value[(usint)(m_nSize - ncharInDivisor)];
	//Number of array elements in Normalised_dividend
	uint_type ncharInNormalised_dividend = ceilIntByUInt(normalised_dividend.m_MSB);
	////Get the uint integer that is in the MSB position of the normalised_dividend
	uint_type msbCharInRunning_Normalised_dividend = normalised_dividend.m_value[(usint)(m_nSize - ncharInNormalised_dividend)];
	//variable to store the running dividend
	BigBinaryInteger running_dividend;
	//variable to store the running remainder
	BigBinaryInteger runningRemainder;
	BigBinaryInteger expectedProd;
	BigBinaryInteger estimateFinder;

	//Initialize the running dividend
	for (usint i = 0; i<ncharInDivisor; i++) {
		running_dividend.m_value[m_nSize - ncharInDivisor + i] = normalised_dividend.m_value[m_nSize - ncharInNormalised_dividend + i];
	}
	running_dividend.m_MSB = GetMSBUint_type(running_dividend.m_value[m_nSize - ncharInDivisor]) + (ncharInDivisor - 1)*m_uintBitLength;

	uint_type estimate = 0;
	uint_type maskBit = 0;
	uint_type shifts = 0;
	usint ansCtr = m_nSize - ncharInNormalised_dividend + ncharInDivisor - 1;
	//Long Division Computation to determine quotient
	for (usint i = ncharInNormalised_dividend - ncharInDivisor; i >= 0;) {
		//Get the remainder from the Modulus operation
		runningRemainder = running_dividend.Mod(q);
		//Compute the expected product from the running dividend and remainder
		expectedProd = running_dividend - runningRemainder;
		estimateFinder = expectedProd;
		
		estimate = 0;

		//compute the quotient
		if (expectedProd>q) {
			while (estimateFinder.m_MSB > 0) {
				/*
				if(expectedProd.m_MSB-b.m_MSB==m_uintBitLength){
				maskBit= (uint_type)1<<(m_uintBitLength-1);
				}
				else
				maskBit= (uint_type)1<<(expectedProd.m_MSB-b.m_MSB);
				*/
				shifts = estimateFinder.m_MSB - q.m_MSB;
				if (shifts == m_uintBitLength) {
					maskBit = 1 << (m_uintBitLength - 1);
				}
				else
					maskBit = 1 << (shifts);

				if ((q.MulIntegerByChar(maskBit))>estimateFinder) {
					maskBit >>= 1;
					estimateFinder -= q << (shifts - 1);
				}
				else if (shifts == m_uintBitLength)
					estimateFinder -= q << (shifts - 1);
				else
					estimateFinder -= q << shifts;

				estimate |= maskBit;
			}

		}
		else if (expectedProd.m_MSB == 0)
			estimate = 0;
		else
			estimate = 1;
		//assgning the quotient in the result array
		ans.m_value[ansCtr] = estimate;
		ansCtr++;
		if (i == 0)
			break;
		//Get the next uint element from the divisor and proceed with long division
		if (running_dividend.m_MSB == 0) {
			running_dividend.m_MSB = GetMSBUint_type(normalised_dividend.m_value[m_nSize - i]);
		}
		else
			running_dividend = runningRemainder << m_uintBitLength;

		running_dividend.m_value[m_nSize - 1] = normalised_dividend.m_value[m_nSize - i];
		if (running_dividend.m_MSB == 0)
			running_dividend.m_MSB = GetMSBUint_type(normalised_dividend.m_value[m_nSize - i]);
		i--;
	}
	ansCtr = m_nSize - ncharInNormalised_dividend + ncharInDivisor - 1;
	//Loop to the MSB position
	while (ans.m_value[ansCtr] == 0) {
		ansCtr++;
	}
	//Computation of MSB value 
	ans.m_MSB = GetMSBUint_type(ans.m_value[ansCtr]) + (m_nSize - 1 - ansCtr)*m_uintBitLength;


	//std::cout<< "ans "<<ans.ToString()<<std::endl;
	//std::cout<< "rv "<<runningRemainder.ToString()<<std::endl;



	//Rounding operation from running remainder
	if (!(runningRemainder <= halfQ)){
		ans += ONE;
		//std::cout<< "added1 ans "<<ans.ToString()<<std::endl;
	}

	return ans;

}

template<typename uint_type,usint BITLENGTH>
usint BigBinaryInteger<uint_type,BITLENGTH>::GetMSBDUint_type(Duint_type x){
	return BigBinaryInteger<uint_type,BITLENGTH>::GetMSB32(x); //todo possible loss of data
}

//Algoritm used is shift and add
template<typename uint_type,usint BITLENGTH>
 uint_type BigBinaryInteger<uint_type,BITLENGTH>::UintInBinaryToDecimal(uschar *a){
	 uint_type Val = 0;
	 uint_type one =1;
	 for(sint i=m_uintBitLength-1;i>=0;i--){
		 Val+= one**(a+i);
		 one<<=1;
		 *(a+i)=0;
	 }

	 return Val;
 }

//Algorithm used is double and add
//http://www.wikihow.com/Convert-from-Binary-to-Decimal
template<typename uint_type_c,usint BITLENGTH_c>
std::ostream& operator<<(std::ostream& os, const BigBinaryInteger<uint_type_c,BITLENGTH_c>& ptr_obj){

	//create reference for the object to be printed
	BigBinaryInteger<uint_type_c,BITLENGTH_c> *print_obj;

	usint counter;

	//initiate to object to be printed
	print_obj = new BigBinaryInteger<uint_type_c,BITLENGTH_c>(ptr_obj);

	//print_obj->PrintValueInDec();

	//print_VALUE array stores the decimal value in the array
	uschar *print_VALUE = new uschar[ptr_obj.m_numDigitInPrintval];

	//reset to zero
	for(sint i=0;i<ptr_obj.m_numDigitInPrintval;i++)
		*(print_VALUE+i)=0;

	//starts the conversion from base r to decimal value
	for(sint i=print_obj->m_MSB;i>0;i--){

		//print_VALUE = print_VALUE*2
		BigBinaryInteger<uint_type_c,BITLENGTH_c>::double_bitVal(print_VALUE);	
#ifdef DEBUG_OSTREAM
		for(sint i=0;i<ptr_obj.m_numDigitInPrintval;i++)
		 std::cout<<(sint)*(print_VALUE+i);
		std::cout<<endl;
#endif
		//adds the bit value to the print_VALUE
		BigBinaryInteger<uint_type_c,BITLENGTH_c>::add_bitVal(print_VALUE,print_obj->GetBitAtIndex(i));
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

 
 template<typename uint_type,usint BITLENGTH>
 void BigBinaryInteger<uint_type,BITLENGTH>::double_bitVal(uschar* a){
	
	uschar ofl=0;
	for(sint i=m_numDigitInPrintval-1;i>-1;i--){
		*(a+i)<<=1;
		if(*(a+i)>9){
			*(a+i)=*(a+i)-10+ofl;
			ofl=1;
		}
		else{
			*(a+i)=*(a+i)+ofl;
			ofl = 0;
		}

	}
 }

 template<typename uint_type,usint BITLENGTH>
 void BigBinaryInteger<uint_type,BITLENGTH>::add_bitVal(uschar* a,uschar b){
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


template<typename uint_type,usint BITLENGTH>
uschar BigBinaryInteger<uint_type,BITLENGTH>::GetBitAtIndex(usint index) const{
	if(index<=0){
		std::cout<<"Invalid index \n";
		return 0;
	}
	else if (index > m_MSB)
		return 0;
	uint_type result;
	sint idx = m_nSize - ceilIntByUInt(index);//idx is the index of the character array
	uint_type temp = this->m_value[idx];
	uint_type bmask_counter = index%m_uintBitLength==0? m_uintBitLength:index%m_uintBitLength;//bmask is the bit number in the 8 bit array
	uint_type bmask = 1;
	for(sint i=1;i<bmask_counter;i++)
		bmask<<=1;//generate the bitmask number
	result = temp&bmask;//finds the bit in  bit format
	result>>=bmask_counter-1;//shifting operation gives bit either 1 or 0
	return (uschar)result;
}

template<typename uint_type, usint BITLENGTH>
void BigBinaryInteger<uint_type, BITLENGTH>::SetIntAtIndex(usint idx, uint_type value){
	if (idx >= m_nSize)
		throw std::logic_error("Index Invalid");
	this->m_value[idx] = value;
}

/*
	This method can be used to convert int to BigBinaryInteger
*/
template<typename uint_type,usint BITLENGTH>
BigBinaryInteger<uint_type,BITLENGTH> BigBinaryInteger<uint_type,BITLENGTH>::intToBigBinaryInteger(usint m){

	return BigBinaryInteger(m);

}


} // namespace cpu_int ends
