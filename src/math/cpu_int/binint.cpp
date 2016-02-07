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
	This code provides basic arithmetic functionality.

License Information:

Copyright (c) 2015, New Jersey Institute of Technology (NJIT)
All rights reserved.
Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:
1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

*/
#include "binint.h"


namespace cpu_int {

static uschar* dec2bin(uschar a);
static void printArray(uschar *a,int size);

void printArray(uschar *a,int size){
		for(int i=0;i<size;i++)
			std::cout<<(int)*(a+i)<<" ";
		std::cout<<std::endl;
	}


//programming starts

template<typename uint_type,usint BITLENGTH>
const BigBinaryInteger<uint_type,BITLENGTH> BigBinaryInteger<uint_type,BITLENGTH>::ZERO = BigBinaryInteger(0);

template<typename uint_type,usint BITLENGTH>
const BigBinaryInteger<uint_type,BITLENGTH> BigBinaryInteger<uint_type,BITLENGTH>::ONE = BigBinaryInteger(1);

template<typename uint_type,usint BITLENGTH>
const BigBinaryInteger<uint_type,BITLENGTH> BigBinaryInteger<uint_type,BITLENGTH>::TWO = BigBinaryInteger(2);

template<typename uint_type,usint BITLENGTH>
const BigBinaryInteger<uint_type,BITLENGTH> BigBinaryInteger<uint_type,BITLENGTH>::THREE = BigBinaryInteger(3);

template<typename uint_type,usint BITLENGTH>
const BigBinaryInteger<uint_type,BITLENGTH> BigBinaryInteger<uint_type,BITLENGTH>::FOUR = BigBinaryInteger(4);

template<typename uint_type,usint BITLENGTH>
const BigBinaryInteger<uint_type,BITLENGTH> BigBinaryInteger<uint_type,BITLENGTH>::FIVE = BigBinaryInteger(5);

//MOST REQUIRED STATIC CONSTANTS INITIALIZATION
template<typename uint_type,usint BITLENGTH>
const uschar BigBinaryInteger<uint_type,BITLENGTH>::m_uintBitLength = uintBitWidth<uint_type>::value;

template<typename uint_type,usint BITLENGTH>
const uschar BigBinaryInteger<uint_type,BITLENGTH>::m_logUintBitLength = logdtype<uint_type>::value;

template<typename uint_type,usint BITLENGTH>
const usint BigBinaryInteger<uint_type,BITLENGTH>::m_nSize = BITLENGTH%m_uintBitLength==0 ? BITLENGTH/m_uintBitLength : BITLENGTH/m_uintBitLength + 1;

template<typename uint_type,usint BITLENGTH>
const uint_type BigBinaryInteger<uint_type,BITLENGTH>::m_uintMax = std::numeric_limits<uint_type>::max();

template<typename uint_type,usint BITLENGTH>
uint_type BigBinaryInteger<uint_type,BITLENGTH>::ceilIntByUInt(const uint_type Number){

	static uint_type mask = m_uintBitLength-1;

	if(!Number)
		return 1;

	if((Number&mask)!=0)
		return (Number>>m_logUintBitLength)+1;
	else
		return Number>>m_logUintBitLength;
}


//usshort BigBinaryInteger::m_nchar = ceilIntBy8(BIT_LENGTH)+1;

//CONSTRUCTORS
template<typename uint_type,usint BITLENGTH>
BigBinaryInteger<uint_type,BITLENGTH>::BigBinaryInteger()
{
	/*
	std::cout<<(int)m_uintBitLength<<" m_uintBitLength "<<std::endl;
	std::cout<<(int)m_logUintBitLength<<" m_uintBitLength "<<std::endl;
	std::cout<<(int)m_nSize<<" m_nSize "<<std::endl;
	std::cout<<m_uintMax<<" m_uintMax "<<std::endl;
	std::cout<<typeid(Duint_type).name()<<std::endl;
	*/
	//main code

	//m_value = new uint_type[m_nSize];
	//m_state = GARBAGE;

	m_value = new uint_type[m_nSize];
	this->m_value[m_nSize-1] = 0;
	this->m_MSB = 0;
	m_state = INITIALIZED;
}

template<typename uint_type,usint BITLENGTH>
BigBinaryInteger<uint_type,BITLENGTH>::BigBinaryInteger(usint init){

	m_value = new uint_type[m_nSize];

	usint msb = GetMSB32(init);

	uint_type ceilInt = ceilIntByUInt(msb);

	for(sint i= m_nSize-1;i>= m_nSize-ceilInt;i--){
		this->m_value[i] = (uint_type)init;
		init>>=m_uintBitLength;
	}
	this->m_MSB = msb;
	m_state = INITIALIZED;
	//this->PrintValueInDec();
}

template<typename uint_type,usint BITLENGTH>
BigBinaryInteger<uint_type,BITLENGTH>::BigBinaryInteger(const std::string& str){
	
	m_value = new uint_type[m_nSize];
	AssignVal(str);
	m_state = INITIALIZED;

}

template<typename uint_type,usint BITLENGTH>
BigBinaryInteger<uint_type,BITLENGTH>::BigBinaryInteger(const BigBinaryInteger& bigInteger){
	
	m_value = new uint_type[m_nSize];
	m_MSB=bigInteger.m_MSB; //copy MSB
	uint_type  tempChar = ceilIntByUInt(bigInteger.m_MSB);
	/*
	for(usint i=0;i<m_nSize - tempChar;i++)
		m_value[i] = 0;
	*/
	for(int i=m_nSize - tempChar;i<m_nSize;i++){//copy array value
		m_value[i]=bigInteger.m_value[i];
	}
	m_state = INITIALIZED;
}

template<typename uint_type,usint BITLENGTH>
BigBinaryInteger<uint_type,BITLENGTH>::BigBinaryInteger(BigBinaryInteger &&bigInteger){
	
	m_MSB = bigInteger.m_MSB;
	m_value = bigInteger.m_value;
	m_state = bigInteger.m_state;
	bigInteger.m_value = NULL;
}

template<typename uint_type,usint BITLENGTH>
std::function<unique_ptr<BigBinaryInteger<uint_type,BITLENGTH>>()> BigBinaryInteger<uint_type,BITLENGTH>::Allocator = [=](){
    return make_unique<BigBinaryInteger>();
};

template<typename uint_type,usint BITLENGTH>
BigBinaryInteger<uint_type,BITLENGTH>::~BigBinaryInteger()
{	
	delete []m_value;
}

template<typename uint_type, usint BITLENGTH>
usint BigBinaryInteger<uint_type, BITLENGTH>::ConvertToInt() const{

	usint result = 0;
	usint num = 32 / m_uintBitLength;

	usint ceilInt = m_nSize - ceilIntByUInt(m_MSB);
	for (usint i = 0; i < num && (m_nSize - i - 1) >= ceilInt; i++){
		result += (this->m_value[m_nSize - i - 1] << (m_uintBitLength*i));
	}
	return result;
}

template<typename uint_type, usint BITLENGTH>
double BigBinaryInteger<uint_type,BITLENGTH>::ConvertToDouble() const{
	return std::stod(this->ToString());
}

template<typename uint_type,usint BITLENGTH>
BigBinaryInteger<uint_type,BITLENGTH>&  BigBinaryInteger<uint_type,BITLENGTH>::operator=(const BigBinaryInteger &rhs){

	usint copyStart = ceilIntByUInt(rhs.m_MSB);
	if(this!=&rhs){
        this->m_MSB=rhs.m_MSB;
		this->m_state = rhs.m_state;
        for(int i= m_nSize-copyStart;i<m_nSize;i++){//copy array value
            this->m_value[i]=rhs.m_value[i];
        }
	}
    return *this;
}

template<typename uint_type,usint BITLENGTH>
BigBinaryInteger<uint_type,BITLENGTH>&  BigBinaryInteger<uint_type,BITLENGTH>::operator=(BigBinaryInteger &&rhs){

	if(this!=&rhs){
        this->m_MSB = rhs.m_MSB;
		this->m_state = rhs.m_state;
        delete []m_value;
        this->m_value = rhs.m_value;
        rhs.m_value = NULL;
    }

    return *this;
}

template<typename uint_type,usint BITLENGTH>
BigBinaryInteger<uint_type,BITLENGTH>  BigBinaryInteger<uint_type,BITLENGTH>::operator<<(usshort shift) const{
	if(m_state==State::GARBAGE)
		throw std::logic_error("Value not initialized");
	if(this->m_MSB==0)
		return BigBinaryInteger(ZERO);

	BigBinaryInteger ans(*this);
	//check for OVERFLOW
	if((ans.m_MSB+shift) > BITLENGTH )
		throw std::logic_error("OVERFLOW \n");

	usint shiftByUint = shift>>m_logUintBitLength;

	usshort remShift = (shift&(m_uintBitLength-1));

	if(remShift!=0){
		uint_type endVal = m_nSize - ceilIntByUInt(m_MSB);
		uint_type oFlow = 0;
		Duint_type temp = 0;
		sint i;
		for(i=m_nSize-1;i>=endVal;i--){
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

template<typename uint_type,usint BITLENGTH>
BigBinaryInteger<uint_type,BITLENGTH>&  BigBinaryInteger<uint_type,BITLENGTH>::operator<<=(usshort shift){
	if(m_state==State::GARBAGE)
		throw std::logic_error("Value not initialized");

	if(this->m_MSB==0)
		return *this;

	//first check whether shifts are possible without overflow
	if(this->m_MSB+shift > BITLENGTH)
		throw std::logic_error ("OVERFLOW \n");

	//calculate the no.of 8shifts
	usint shiftByUint = shift>>m_logUintBitLength;

	uint_type remShift = (shift&(m_uintBitLength-1));

	if(remShift!=0){

		uint_type endVal = m_nSize-ceilIntByUInt(this->m_MSB);
		uint_type oFlow = 0;
		Duint_type temp = 0;
		sint i ;
		for(i= m_nSize-1; i>= endVal ; i-- ){
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

template<typename uint_type,usint BITLENGTH>
BigBinaryInteger<uint_type,BITLENGTH>  BigBinaryInteger<uint_type,BITLENGTH>::operator>>(usshort shift) const{

	if(m_state==State::GARBAGE)
		throw std::logic_error("Value not initialized");

	if(this->m_MSB==0 || this->m_MSB <= shift)
		return BigBinaryInteger(0);
	 
	
	BigBinaryInteger ans(*this);

	usint shiftByUint = shift>>m_logUintBitLength;

	uint_type remShift = (shift&(m_uintBitLength-1));

	if(shiftByUint!=0){

		usint endVal= m_nSize-ceilIntByUInt(ans.m_MSB);
		usint j= endVal;
		
		for(sint i= m_nSize-1-shiftByUint;i>=endVal;i--){
			ans.m_value[i+shiftByUint] = ans.m_value[i];
		}

		ans.m_MSB -= shiftByUint<<m_logUintBitLength;

		while(shiftByUint>0){
			ans.m_value[j] = 0;
			shiftByUint--;
			j++;
		}

		//ans.PrintValueInDec();
	}

	if(remShift!=0){

		uint_type overFlow = 0;
		uint_type oldVal;
		uint_type maskVal = (1<<(remShift))-1;
		uint_type compShiftVal = m_uintBitLength- remShift;

		usint startVal = m_nSize - ceilIntByUInt(ans.m_MSB);

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

template<typename uint_type,usint BITLENGTH>
BigBinaryInteger<uint_type,BITLENGTH>&  BigBinaryInteger<uint_type,BITLENGTH>::operator>>=(usshort shift){

	if(m_state==State::GARBAGE)
		throw std::logic_error("Value not initialized");

	if(this->m_MSB==0 )
		return *this;
	else if(this->m_MSB<=shift){
		*this = ZERO;
		return *this;
	}

	usint shiftByUint = shift>>m_logUintBitLength;

	uschar remShift = (shift&(m_uintBitLength-1));

	if(shiftByUint!=0){

		usint endVal= m_nSize-ceilIntByUInt(this->m_MSB);
		usint j= endVal;
		
		for(sint i= m_nSize-1-shiftByUint;i>=endVal;i--){
			this->m_value[i+shiftByUint] = this->m_value[i];
		}

		this->m_MSB -= shiftByUint<<m_logUintBitLength;

		while(shiftByUint>0){
			this->m_value[j] = 0;
			shiftByUint--;
			j++;
		}

		
	}

	

	if(remShift!=0){

		uint_type overFlow = 0;
		uint_type oldVal;
		uint_type maskVal = (1<<(remShift))-1;
		uint_type compShiftVal = m_uintBitLength- remShift;

		usint startVal = m_nSize - ceilIntByUInt(this->m_MSB);

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

template<typename uint_type,usint BITLENGTH>
usshort BigBinaryInteger<uint_type,BITLENGTH>::GetMSB()const{
	return m_MSB;
}

template<typename uint_type,usint BITLENGTH>
BigBinaryInteger<uint_type,BITLENGTH> BigBinaryInteger<uint_type,BITLENGTH>::Plus(const BigBinaryInteger& b) const{
	
const BigBinaryInteger* A = NULL;//two operands A and B for addition, A is the greater one, B is the smaller one
	const BigBinaryInteger* B = NULL;
	
	if(this->m_state==GARBAGE){
		if(b.m_state==GARBAGE){
			return std::move(BigBinaryInteger(ZERO));
		}
		else
			return std::move(BigBinaryInteger(b));
	}
	if(b.m_state==GARBAGE){
		return std::move(BigBinaryInteger(*this));
	}
	
	if(*this>b){
		A = this; B = &b;
	}
	else {A = &b; B = this;}

	if(B->m_MSB==0)
		return BigBinaryInteger(*A);

	BigBinaryInteger result;//result initiated to the greater APint
	result.m_state = INITIALIZED;
	Duint_type ofl=0;//overflow variable
	
	uint_type ceilIntA = ceilIntByUInt(A->m_MSB);
	uint_type ceilIntB = ceilIntByUInt(B->m_MSB);
	sint i;//counter
	for(i=m_nSize-1;i>=m_nSize-ceilIntB;i--){//NChar-ceil(MSB/8)
		ofl =(Duint_type)A->m_value[i]+ (Duint_type)B->m_value[i]+ofl;//sum of the two apint and the carry over
		result.m_value[i] = (uint_type)ofl;
		ofl>>=m_uintBitLength;//current overflow
	}

	if(ofl){
		for(;i>=m_nSize-ceilIntA;i--){
			ofl = (Duint_type)A->m_value[i]+ofl;//sum of the two apint and the carry over
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
		for(;i>=m_nSize-ceilIntA;i--){//NChar-ceil(MSB/8)
			result.m_value[i] = A->m_value[i];
		}
		result.m_MSB =  (m_nSize - i - 2)*m_uintBitLength;
		result.m_MSB += GetMSBUint_type(result.m_value[++i]);
	}

	return result;
}

template<typename uint_type,usint BITLENGTH>
BigBinaryInteger<uint_type,BITLENGTH> BigBinaryInteger<uint_type,BITLENGTH>::Minus(const BigBinaryInteger& b) const{

	if(this->m_state==GARBAGE){
		return std::move(BigBinaryInteger(ZERO));		
	}
	if(b.m_state==GARBAGE){
		return std::move(BigBinaryInteger(*this));
	}

	if(!(*this>b))
		return std::move(BigBinaryInteger(ZERO));

	int cntr=0,current=0;
	
	BigBinaryInteger result(*this);

	int endValA = m_nSize-ceilIntByUInt(this->m_MSB);
	int endValB = m_nSize-ceilIntByUInt(b.m_MSB);
	sint i;
	for(i=m_nSize-1;i>=endValB;i--){
		if(result.m_value[i]<b.m_value[i]){
			current=i;
			cntr = current-1;
			while(result.m_value[cntr]==0){
				result.m_value[cntr]=m_uintMax;cntr--;
			}
			result.m_value[cntr]--;
			result.m_value[i]=result.m_value[i]+m_uintMax+1- b.m_value[i];		
		}
		else{
			result.m_value[i]=result.m_value[i]- b.m_value[i];
		}
		cntr=0;
	}

	while(result.m_value[endValA]==0){
		endValA++;
	}

	result.m_MSB = (m_nSize-endValA-1)*m_uintBitLength + GetMSBUint_type(result.m_value[endValA]);


	return std::move(result);

}

template<typename uint_type,usint BITLENGTH>
BigBinaryInteger<uint_type,BITLENGTH> BigBinaryInteger<uint_type,BITLENGTH>::Times(const BigBinaryInteger& b) const{
	
	BigBinaryInteger ans;
	
	if(b.m_MSB==0 || b.m_state==GARBAGE ||this->m_state==GARBAGE || this->m_MSB==0){
		ans = ZERO;
		return ans;
	}
	if(b.m_MSB==1)
		return BigBinaryInteger(*this);
	if(this->m_MSB==1)
		return std::move(BigBinaryInteger(b));
	
	//ans = ZERO;
	uint_type ceilInt = ceilIntByUInt(b.m_MSB);
	for(sint i= m_nSize-1;i>= m_nSize-ceilInt;i--){
		ans += (this->MulIntegerByChar(b.m_value[i]))<<=( m_nSize-1-i)*m_uintBitLength;
	}

	return ans;
}

template<typename uint_type,usint BITLENGTH>
const BigBinaryInteger<uint_type,BITLENGTH>& BigBinaryInteger<uint_type,BITLENGTH>::operator+=(const BigBinaryInteger &b){
	const BigBinaryInteger* A = NULL;//two operands A and B for addition, A is the greater one, B is the smaller one
	const BigBinaryInteger* B = NULL;

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
	if(b.m_state==GARBAGE || b.m_MSB==0){
		return *this;
	}

	if(*this>b){
		A = this; B = &b;
	}
	else {A = &b; B = this;}
	
	Duint_type ofl=0;//overflow variable
	
	uint_type ceilIntA = ceilIntByUInt(A->m_MSB);
	uint_type ceilIntB = ceilIntByUInt(B->m_MSB);

	sint i;//counter
	for(i=m_nSize-1;i>=m_nSize-ceilIntB;i--){
		ofl =(Duint_type)A->m_value[i]+ (Duint_type)B->m_value[i]+ofl;//sum of the two apint and the carry over
		this->m_value[i] = (uint_type)ofl;
		ofl>>=m_uintBitLength;//current overflow
	}

	if(ofl){
		for(;i>=m_nSize-ceilIntA;i--){
			ofl = (Duint_type)A->m_value[i]+ofl;//sum of the two apint and the carry over
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
		for(;i>=m_nSize-ceilIntA;i--){//NChar-ceil(MSB/8)
			this->m_value[i] = A->m_value[i];
		}
		this->m_MSB = (m_nSize-i-2)*m_uintBitLength;
		this->m_MSB += GetMSBUint_type(this->m_value[++i]);
	}	

	return *this;
}

template<typename uint_type,usint BITLENGTH>
const BigBinaryInteger<uint_type,BITLENGTH>& BigBinaryInteger<uint_type,BITLENGTH>::operator-=(const BigBinaryInteger &b){
	//this->PrintValueInDec();
	//std::cout << std::endl;
	//b.PrintValueInDec();
	//std::cout << std::endl;
	//std::cout <<*this<<" THIS"<< std::endl;
	//std::cout << b << " bVal" << std::endl;

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

	int endValA = m_nSize-ceilIntByUInt(this->m_MSB);
	int endValB = m_nSize-ceilIntByUInt(b.m_MSB);
	sint i;
	for(i=m_nSize-1;i>=endValB;i--){
		if(this->m_value[i]<b.m_value[i]){
			current=i;
			cntr = current-1;
			while(this->m_value[cntr]==0){
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

template<typename uint_type,usint BITLENGTH>
BigBinaryInteger<uint_type,BITLENGTH> BigBinaryInteger<uint_type,BITLENGTH>::MulIntegerByChar(uint_type b) const{
	
	if(this->m_state==GARBAGE)
		throw std::logic_error("ERROR \n");
	if(b==0 || this->m_MSB==0)
		return BigBinaryInteger(ZERO);
	
	BigBinaryInteger ans;

	usint endVal = m_nSize-ceilIntByUInt(m_MSB);
	Duint_type temp=0;
	uint_type ofl=0;
	sint i= m_nSize-1;

	for(;i>=endVal ;i--){
		temp = ((Duint_type)m_value[i]*(Duint_type)b) + ofl;
		ans.m_value[i] = (uint_type)temp;
		ofl = temp>>m_uintBitLength;
	}
	if(ofl){
		ans.m_value[i]=ofl;
	}
	ans.m_MSB = (m_nSize-1-endVal)*m_uintBitLength;
	ans.m_MSB += GetMSBDUint_type(temp);
	ans.m_state = INITIALIZED;
	//ans.PrintValueInDec();

	return ans;
}

template<typename uint_type,usint BITLENGTH>
BigBinaryInteger<uint_type,BITLENGTH> BigBinaryInteger<uint_type,BITLENGTH>::DividedBy(const BigBinaryInteger& b) const{

	if(b.m_state==GARBAGE || b==ZERO)
		throw std::logic_error("DIVISION BY ZERO");

	if(b.m_MSB>this->m_MSB || this->m_state==GARBAGE)
		return std::move(BigBinaryInteger(ZERO));
	else if(b==*this)
		return std::move(BigBinaryInteger(ONE));
	
		
	
	BigBinaryInteger ans;
	
	BigBinaryInteger normalised_dividend( this->Minus( this->Mod(b) ) );

	uint_type ncharInDivisor = ceilIntByUInt(b.m_MSB);
	uint_type msbCharInDivisor = b.m_value[(usint)( m_nSize-ncharInDivisor)];
	uint_type ncharInNormalised_dividend = ceilIntByUInt(normalised_dividend.m_MSB);
	uint_type msbCharInRunning_Normalised_dividend = normalised_dividend.m_value[(usint)( m_nSize-ncharInNormalised_dividend)];
	BigBinaryInteger running_dividend;
	BigBinaryInteger runningRemainder;
	BigBinaryInteger expectedProd;
	BigBinaryInteger estimateFinder;
	//BigBinaryInteger ep;
	//Initialize the running dividend
	for(usint i=0;i<ncharInDivisor;i++){
		running_dividend.m_value[ m_nSize-ncharInDivisor+i] = normalised_dividend.m_value[ m_nSize-ncharInNormalised_dividend+i]; 
	}
	running_dividend.m_MSB = GetMSBUint_type(running_dividend.m_value[m_nSize-ncharInDivisor]) + (ncharInDivisor-1)*m_uintBitLength;
	running_dividend.m_state = INITIALIZED;
	//running_dividend.PrintValueInDec();
	//normalised_dividend.PrintValueInDec();
	
	uint_type estimate=0;
	uint_type maskBit = 0;
	uint_type shifts =0;
	usint ansCtr = m_nSize - ncharInNormalised_dividend+ncharInDivisor-1;
	for(usint i=ncharInNormalised_dividend-ncharInDivisor;i>=0;){
		//running_dividend.PrintValueInDec();std::cout<<std::endl;
		//memManager = runningRemainder;
		runningRemainder = running_dividend.Mod(b);
		//runningRemainder.PrintValueInDec();std::cout<<std::endl;
		
		expectedProd = running_dividend-runningRemainder;
		estimateFinder = expectedProd;
		//expectedProd.PrintValueInDec();
		//std::cout<<expectedProd<<std::endl;
		estimate =0;
		//std::cout<<expectedProd<<std::endl;
		//if(ceilIntByUInt(expectedProd.m_MSB)>ncharInDivisor){
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
				if(shifts==m_uintBitLength){
					maskBit= 1<<(m_uintBitLength-1);
				}
				else
					maskBit= 1<<(shifts);
				
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

		ans.m_value[ansCtr] = estimate;
		ansCtr++;		
		if(i==0)
			break;
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
	while(ans.m_value[ansCtr]==0){
		ansCtr++;
	}
	ans.m_MSB = GetMSBUint_type(ans.m_value[ansCtr]) + (m_nSize-1-ansCtr)*m_uintBitLength;
	ans.m_state = INITIALIZED;
	return ans;

}

template<typename uint_type,usint BITLENGTH>
void BigBinaryInteger<uint_type,BITLENGTH>::AssignVal(const std::string& v){

	uschar *DecValue;//array of decimal values
	int arrSize=v.length();
	//check if the array is large enough to store the decimal value, based upon max and min bit size calculation
	//if(m_nchar*8<(int)(floor(arrSize*LOG2_10)+1)){ //floor(arrSize*LOG2_10)+1 is bmax
	//	std::cout<<"BIT_LENGTH value chosen too small exiting application\n";
	//	exit(-1);
	//}
	DecValue = new uschar[arrSize];
	//memory allocated for decimal array
	for(sint i=0;i<arrSize;i++)//store the string to decimal array
		DecValue[i] = (uschar) stoi(v.substr(i,1));
	sshort zptr = 0;
	//index of highest non-zero number in decimal number
	//define  bit register array
	uschar *bitArr = new uschar[m_uintBitLength]();
	//array to store the value of one char
	//for(sint i=0;i<8;i++)//initiate to zero
	//	bitArr[i]=0;
	sint bitValPtr=m_nSize-1;
	//bitValPtr is a pointer to the Value char array, initially pointed to the last char
	//we increment the pointer to the next char when we get the complete value of the char array
	//for(sint i=0;i<m_nchar;i++)//initialie to zero
	//	*(m_value+i)=0;
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
	if(cnt==-1){//cnt8 = -1 indicates bitArr is ready for transfer
		cnt=m_uintBitLength-1;
		m_value[bitValPtr--]= UintInBinaryToDecimal(bitArr);//bin82dec converts bitArr to decimal and zeros the content of bitArr
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
	if(this->m_state==GARBAGE){
		for(usint i=0;i<m_nSize;i++){
			m_value[i] = 0;
		}
		m_state = INITIALIZED;
		return;
	}
	
	for(usint i=0;i<m_nSize;i++)//loops to find first nonzero number in char array
		if((Duint_type)m_value[i]!=0){
			//bitArr = dec2bin(m_value[i]);//assign the MSB char to bit Array
			m_MSB = (m_nSize-i-1)*m_uintBitLength; 
			m_MSB+= GetMSBUint_type(m_value[i]);
			break;
		}
}

//guessIdx is the actual index of array
template<typename uint_type, usint BITLENGTH>
void BigBinaryInteger<uint_type, BITLENGTH>::SetMSB(usint guessIdxChar){

	m_MSB = (m_nSize - guessIdxChar - 1)*m_uintBitLength;
	m_MSB += GetMSBUint_type(m_value[guessIdxChar]);
}

template<typename uint_type, usint BITLENGTH>
void BigBinaryInteger<uint_type, BITLENGTH>::SetValue(const std::string& str){
	
	AssignVal(str);
	m_state = INITIALIZED;

}

template<typename uint_type,usint BITLENGTH>
BigBinaryInteger<uint_type,BITLENGTH> BigBinaryInteger<uint_type,BITLENGTH>::Mod(const BigBinaryInteger& modulus) const{

	if(this->m_state==GARBAGE || modulus.m_state==GARBAGE)
		throw std::logic_error("Error \n");
	//std::cout << *this << "THIS" << std::endl;
	//std::cout << modulus << "modulus" << std::endl;


	if(*this<modulus){
		return std::move(BigBinaryInteger(*this));
	}
	if(modulus.m_MSB==2 && modulus.m_value[m_nSize-1]==2){
		if(this->m_value[m_nSize-1]%2==0)
			return BigBinaryInteger(ZERO);
		else
			return BigBinaryInteger(ONE);
	}
	Duint_type initial_shift = 0;
	if(this->m_MSB > modulus.m_MSB)
		initial_shift=this->m_MSB - modulus.m_MSB -1;

	//cout<<initial_shift<<endl;
	//std::cout << " \n********Before Shift*********" << std::endl;
	BigBinaryInteger j = modulus<<initial_shift;

	//std::cout << " \n********After Shift*********" << std::endl;
	//std::cout<<"initial j value"<<j<<std::endl;
	BigBinaryInteger result(*this);
	//cout<<"printing result "<<*result<<endl;
	BigBinaryInteger temp;
	while(true){
		if(result<modulus) break;
		if (result.m_MSB > j.m_MSB) {
			temp = j<<1;
			if (result.m_MSB == j.m_MSB + 1) {
				if(result>temp){
					j=temp;
				}
			}
		}
		//result = result - j;
		result -= j;
		
		//std::cout<<result<<std::endl;
		initial_shift = j.m_MSB - result.m_MSB +1;
		if(result.m_MSB-1>=modulus.m_MSB){
			j>>=initial_shift;
		}
		else{ 
			j = modulus;
		}
		//std::cout<<j<<std::endl;
	}

	return std::move(result);
}

template<typename uint_type,usint BITLENGTH>
BigBinaryInteger<uint_type,BITLENGTH> BigBinaryInteger<uint_type,BITLENGTH>::ModBarrett(const BigBinaryInteger& modulus, const BigBinaryInteger& mu) const{
	
	if(*this<modulus){
		return std::move(BigBinaryInteger(*this));
	}
	BigBinaryInteger z(*this);
	BigBinaryInteger q(*this);

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

template<typename uint_type,usint BITLENGTH>
BigBinaryInteger<uint_type,BITLENGTH> BigBinaryInteger<uint_type,BITLENGTH>::ModInverse(const BigBinaryInteger& modulus) const{

	if(m_state==GARBAGE || modulus.m_state==GARBAGE)
		throw std::logic_error("GARBAGE ERROR");

	//std::ofstream f("grs_Modinverse");

	//f << *this <<" THIS VALUE "<< std::endl;
	//f << modulus << " Modulus value " << std::endl;

	std::vector<BigBinaryInteger> mods;
	std::vector<BigBinaryInteger> quotient;
	mods.push_back(BigBinaryInteger(modulus));
	mods.push_back(BigBinaryInteger(*this));
	BigBinaryInteger first(mods[0]);
	BigBinaryInteger second(mods[1]);

	if(*this==ZERO){
		std::cout<<"ZERO HAS NO INVERSE\n";
		system("pause");
		throw std::logic_error("MOD INVERSE NOT FOUND");
	}

	

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
	mods.push_back(BigBinaryInteger(ZERO));
	mods.push_back(BigBinaryInteger(ONE));

	first = mods[0];
	second = mods[1];

	for(sint i=quotient.size()-1;i>=0;i--){
		mods.push_back(quotient[i]*second + first);
		first = second;
		second = mods.back();
	}

	BigBinaryInteger result;
	if(quotient.size()%2==1){
		result = (modulus - mods.back());
	}
	else{
		result = BigBinaryInteger(mods.back());
	}

	mods.clear();
	quotient.clear();
	//f.close();

	return result;

}

template<typename uint_type,usint BITLENGTH>
BigBinaryInteger<uint_type,BITLENGTH> BigBinaryInteger<uint_type,BITLENGTH>::ModAdd(const BigBinaryInteger& b, const BigBinaryInteger& modulus) const{
	return this->Plus(b).Mod(modulus);
}

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

	if(*this>modulus){

		*a = std::move(this->Mod(modulus));
	}

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

template<typename uint_type,usint BITLENGTH>
BigBinaryInteger<uint_type,BITLENGTH> BigBinaryInteger<uint_type,BITLENGTH>::ModBarrettSub(const BigBinaryInteger& b, const BigBinaryInteger& modulus,const BigBinaryInteger& mu) const{

	BigBinaryInteger* a = NULL;
	BigBinaryInteger* b_op = NULL;

	if(*this>modulus){
		*a = std::move(this->ModBarrett(modulus,mu));
	}
	else{
		a = const_cast<BigBinaryInteger*>(this);
	}

	if(b>modulus){
		*b_op = std::move(b.ModBarrett(modulus,mu));
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
		*a = std::move(this->ModBarrett(modulus,mu_arr));
	}
	else{
		a = const_cast<BigBinaryInteger*>(this);
	}

	if(b>modulus){
		*b_op = std::move(b.ModBarrett(modulus,mu_arr));
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

template<typename uint_type,usint BITLENGTH>
BigBinaryInteger<uint_type,BITLENGTH> BigBinaryInteger<uint_type,BITLENGTH>::ModBarrettMul(const BigBinaryInteger& b, const BigBinaryInteger& modulus,const BigBinaryInteger& mu) const{

	BigBinaryInteger* a  = const_cast<BigBinaryInteger*>(this);
	BigBinaryInteger* bb = const_cast<BigBinaryInteger*>(&b);

	//if a is greater than q reduce a to its mod value
	if(*this>modulus)
		*a = std::move(this->ModBarrett(modulus,mu));


	//if b is greater than q reduce b to its mod value
	if(b>modulus)
		*bb = std::move(b.ModBarrett(modulus,mu));

	return (*a**bb).ModBarrett(modulus,mu);

}

template<typename uint_type,usint BITLENGTH>
BigBinaryInteger<uint_type,BITLENGTH> BigBinaryInteger<uint_type,BITLENGTH>::ModBarrettMul(const BigBinaryInteger& b, const BigBinaryInteger& modulus,const BigBinaryInteger mu_arr[BARRETT_LEVELS]) const{
	BigBinaryInteger* a  = NULL;
	BigBinaryInteger* bb = NULL;

	//if a is greater than q reduce a to its mod value
	if(*this>modulus)
		*a = std::move(this->ModBarrett(modulus,mu_arr));
	else
		a = const_cast<BigBinaryInteger*>(this);

	//if b is greater than q reduce b to its mod value
	if(b>modulus)
		*bb = std::move(b.ModBarrett(modulus,mu_arr));
	else
		bb = const_cast<BigBinaryInteger*>(&b);

	//return a*b%q

	return (*a**bb).ModBarrett(modulus,mu_arr);
}

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
	BigBinaryInteger<uint_type,BITLENGTH> *print_obj;

	usint counter;

	//initiate to object to be printed
	print_obj = new BigBinaryInteger<uint_type,BITLENGTH>(*this);

	//print_obj->PrintValueInDec();

	//print_VALUE array stores the decimal value in the array
	uschar *print_VALUE = new uschar[NUM_DIGIT_IN_PRINTVAL];

	//reset to zero
	for(sint i=0;i<NUM_DIGIT_IN_PRINTVAL;i++)
		*(print_VALUE+i)=0;

	//starts the conversion from base 256 to decimal value
	for(sint i=print_obj->m_MSB;i>0;i--){

		//print_VALUE = print_VALUE*2
		BigBinaryInteger<uint_type,BITLENGTH>::double_bitVal(print_VALUE);	

		//adds the bit value to the print_VALUE
		BigBinaryInteger<uint_type,BITLENGTH>::add_bitVal(print_VALUE,print_obj->GetBitAtIndex(i));


	}

	//find the first occurence of non-zero value in print_VALUE
	for(counter=0;counter<NUM_DIGIT_IN_PRINTVAL-1;counter++){
		if((sint)print_VALUE[counter]!=0)break;							
	}

	//append this BigBinaryInteger's digits to this method's returned string object
	for (; counter < NUM_DIGIT_IN_PRINTVAL; counter++) {
		bbiString += std::to_string(print_VALUE[counter]);
	}

	delete [] print_VALUE;
	//deallocate the memory since values are inserted into the ostream object
	delete print_obj;

	return bbiString;

}

template<typename uint_type,usint BITLENGTH>
sint BigBinaryInteger<uint_type,BITLENGTH>::Compare(const BigBinaryInteger& a) const
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

	if(this->m_state==GARBAGE || a.m_state==GARBAGE)
		throw std::logic_error("ERROR \n");
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
bool BigBinaryInteger<uint_type,BITLENGTH>::CheckPowerofTwos(const BigBinaryInteger& m_numToCheck){
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
	
	if(this->m_state==GARBAGE || a.m_state==GARBAGE)
		throw std::logic_error("ERROR \n");

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

	if(this->m_state==GARBAGE || a.m_state==GARBAGE)
		throw std::logic_error("ERROR \n");

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
uint64_t BigBinaryInteger<uint_type,BITLENGTH>::GetMSB32(uint64_t x)
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

template<typename uint_type,usint BITLENGTH>
BigBinaryInteger<uint_type,BITLENGTH> BigBinaryInteger<uint_type,BITLENGTH>::BinaryToBigBinaryInt(const std::string& bitString){
	std::string zero = "0";
	BigBinaryInteger value("0");
	usint len = bitString.length();
	for (usint index = 0; index < len; index++)
  	{
  		if((zero[0] == bitString[index]))
  			continue;
  		else {
  			value += BigBinaryInteger<uint_type,BITLENGTH>::TWO.Exp(len - 1 - index);
  		}
  	}
  	return value;
}

template<typename uint_type,usint BITLENGTH>
BigBinaryInteger<uint_type,BITLENGTH> BigBinaryInteger<uint_type,BITLENGTH>::Exp(usint p) const{
	if (p == 0) return BigBinaryInteger(BigBinaryInteger::ONE);
	BigBinaryInteger x(*this);
  	if (p == 1) return x;

	BigBinaryInteger tmp = x.Exp(p/2);
	if (p%2 == 0) return tmp * tmp;
	else return tmp * tmp * x;
}


template<typename uint_type,usint BITLENGTH>
usint BigBinaryInteger<uint_type,BITLENGTH>::GetMSBDUint_type(Duint_type x){
	return BigBinaryInteger<uint_type,BITLENGTH>::GetMSB32(x);
}

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

template<typename uint_type_c,usint BITLENGTH_c>
std::ostream& operator<<(std::ostream& os, const BigBinaryInteger<uint_type_c,BITLENGTH_c>& ptr_obj){

	//create reference for the object to be printed
	BigBinaryInteger<uint_type_c,BITLENGTH_c> *print_obj;

	usint counter;

	//initiate to object to be printed
	print_obj = new BigBinaryInteger<uint_type_c,BITLENGTH_c>(ptr_obj);

	//print_obj->PrintValueInDec();

	//print_VALUE array stores the decimal value in the array
	uschar *print_VALUE = new uschar[NUM_DIGIT_IN_PRINTVAL];

	//reset to zero
	for(sint i=0;i<NUM_DIGIT_IN_PRINTVAL;i++)
		*(print_VALUE+i)=0;

	//starts the conversion from base 256 to decimal value
	for(sint i=print_obj->m_MSB;i>0;i--){

		//print_VALUE = print_VALUE*2
		BigBinaryInteger<uint_type_c,BITLENGTH_c>::double_bitVal(print_VALUE);	
#ifdef DEBUG_OSTREAM
		for(sint i=0;i<NUM_DIGIT_IN_PRINTVAL;i++)
		 std::cout<<(sint)*(print_VALUE+i);
		std::cout<<endl;
#endif
		//adds the bit value to the print_VALUE
		BigBinaryInteger<uint_type_c,BITLENGTH_c>::add_bitVal(print_VALUE,print_obj->GetBitAtIndex(i));
#ifdef DEBUG_OSTREAM
		for(sint i=0;i<NUM_DIGIT_IN_PRINTVAL;i++)
		 std::cout<<(sint)*(print_VALUE+i);
		std::cout<<endl;
#endif

	}

	//find the first occurence of non-zero value in print_VALUE
	for(counter=0;counter<NUM_DIGIT_IN_PRINTVAL-1;counter++){
		if((sint)print_VALUE[counter]!=0)break;							
	}

	//start inserting values into the ostream object 
	for(;counter<NUM_DIGIT_IN_PRINTVAL;counter++){
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
	for(sint i=NUM_DIGIT_IN_PRINTVAL-1;i>-1;i--){
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
	*(a+NUM_DIGIT_IN_PRINTVAL-1)+=b;
	for(sint i=NUM_DIGIT_IN_PRINTVAL-1;i>-1;i--){
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

/*
	This method can be used to convert int to BigBinaryInteger
*/
template<typename uint_type,usint BITLENGTH>
BigBinaryInteger<uint_type,BITLENGTH> BigBinaryInteger<uint_type,BITLENGTH>::intToBigBinaryInteger(usint m){

	return BigBinaryInteger(m);

}


} // namespace cpu_int ends
