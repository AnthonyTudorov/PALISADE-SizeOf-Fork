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
		Nishanth Pasham, np386@njit.edu
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
#include "../nbtheory.h"

namespace cpu8bit {

//YSP - these 5 methods should either be moved to a separate header file or encapsulated in this class
static uschar bin82dec(sshort *a);
static uschar* dec2bin(uschar a);
static uschar MSB_in_char(uschar in);
static void double_bitVal(uschar* a);
static void add_bitVal(uschar* a,uschar b);

usshort BigBinaryInteger::m_nchar = ceilIntBy8(BIT_LENGTH) + 1;
//MemoryPool_uschar BigBinaryInteger::memReserve = MemoryPool_uschar();
MemoryPoolChar BigBinaryInteger::m_memReserve = MemoryPoolChar();

const BigBinaryInteger BigBinaryInteger::ZERO = BigBinaryInteger();
const BigBinaryInteger BigBinaryInteger::ONE = BigBinaryInteger("1");
const BigBinaryInteger BigBinaryInteger::TWO = BigBinaryInteger("2");
const BigBinaryInteger BigBinaryInteger::THREE = BigBinaryInteger("3");
const BigBinaryInteger BigBinaryInteger::FOUR = BigBinaryInteger("4");
const BigBinaryInteger BigBinaryInteger::FIVE = BigBinaryInteger("5");


//usshort BigBinaryInteger::m_nchar = ceilIntBy8(BIT_LENGTH)+1;

//CONSTRUCTORS

BigBinaryInteger::BigBinaryInteger()
{

	//m_value = new uschar[m_nchar]();
	m_value = m_memReserve.Allocate();
	for(usint i=0;i<m_nchar;i++)
		m_value[i] = 0;
	//std::memset(m_value,0,m_nchar);
	//std::cout<<(int)m_nchar<<std::endl;
	//AssignVal("0");
	//m_MSB = SetMSB(m_value);
	m_MSB = 0;
}

std::function<unique_ptr<BigBinaryInteger>()> BigBinaryInteger::Allocator = [=](){
    return make_unique<BigBinaryInteger>();
};


//this constructor is used in the functions where all elements of the character array are set
/*BigBinaryInteger::BigBinaryInteger(uschar init)
{
	if (init==1) {
		m_value = m_memReserve.Allocate();
		m_MSB = 0;
	}
	else
	{
		m_value = m_memReserve.Allocate();
		for(usint i=0;i<m_nchar;i++)
			m_value[i] = 0;
		m_MSB = 0;
	}
}*/

BigBinaryInteger::BigBinaryInteger(usint init){

	m_value = m_memReserve.Allocate();
	usint msb = lbcrypto::GetMSB32(init);
	uschar ceilInt8 = ceilIntBy8(msb);

	for(sint i= m_nchar-1;i>= m_nchar-ceilInt8;i--){
		this->m_value[i] = (uschar) init;
		init>>=8;
	}
	this->m_MSB = msb;
}

BigBinaryInteger::BigBinaryInteger(const std::string& str){
	//m_nchar= ceilIntBy8(BIT_LENGTH)+1;
	//number of character in the arrays

	//m_value = new uschar[m_nchar]();
	//memory allocated
	m_value = m_memReserve.Allocate();
	for(usint i=0;i<m_nchar;i++)
		m_value[i] = 0;
	AssignVal(str);
	//AssignVals the m_value by repeated division
	SetMSB();
	//sets the MSB
}

BigBinaryInteger::BigBinaryInteger(const BigBinaryInteger& bigInteger){
	//m_nchar =  bigInteger.m_nchar; //copy the number of character array
	//m_value = new uschar[m_nchar]();//allocate memory for the new character array
	m_value = m_memReserve.Allocate();
	m_MSB=bigInteger.m_MSB; //copy MSB
	uschar tempChar = ceilIntBy8(bigInteger.m_MSB);
	for(usint i=0;i<m_nchar - tempChar;i++)
		m_value[i] = 0;
	//std::memset(m_value,0,m_nchar - tempChar);
	for(int i=m_nchar - tempChar;i<m_nchar;i++){//copy array value
		m_value[i]=bigInteger.m_value[i];
	}
}

BigBinaryInteger::BigBinaryInteger(BigBinaryInteger &&bigInteger){

	m_MSB = bigInteger.m_MSB;
	m_value = bigInteger.m_value;
	bigInteger.m_value = NULL;
}

BigBinaryInteger::~BigBinaryInteger()
{
	//std::cout<<"destructor called \n";
	//delete []m_value;
	m_memReserve.Deallocate(m_value);
}

BigBinaryInteger&  BigBinaryInteger::operator=(const BigBinaryInteger &rhs){

	//cout<<"Assignment operator called \n";
	usint copyStart = this->m_MSB > rhs.m_MSB ? this->m_MSB:rhs.m_MSB;
	copyStart = m_nchar - ceilIntBy8(copyStart);

	if(this!=&rhs){
		this->m_MSB=rhs.m_MSB;
		//this->m_nchar=rhs.m_nchar;
		for(int i=copyStart;i<m_nchar;i++){//copy array value
			this->m_value[i]=rhs.m_value[i];
		}
	}
	return *this;
}

BigBinaryInteger&  BigBinaryInteger::operator=(BigBinaryInteger &&rhs){

	if(this!=&rhs){
		this->m_MSB = rhs.m_MSB;
		//delete []m_value;
		m_memReserve.Deallocate(m_value);
		this->m_value = rhs.m_value;
		rhs.m_value = NULL;

	}

	return *this;
}

//ACCESSORS
void BigBinaryInteger::PrintValueInDec() const{

	sint i= m_MSB%8==0&&m_MSB!=0? m_MSB/8:(sint)m_MSB/8 +1;
	for(i=m_nchar-i;i<m_nchar;i++)//actual
    //(i=0;i<Nchar;i++)//for debug
	    std::cout<<std::dec<<(sint)m_value[i]<<".";

    std::cout<<std::endl;
}

void BigBinaryInteger::SetValue(const std::string& str){
	for (usint i = 0; i<m_nchar; i++)
		m_value[i] = 0;
	AssignVal(str);
	SetMSB();
}

void BigBinaryInteger::SetValue(const BigBinaryInteger& a){
	for(usint i=0;i<a.m_nchar;i++){
		this->m_value[i] = a.m_value[i];
	}

	this->m_MSB = a.m_MSB;

 }

usint BigBinaryInteger::GetMSB()const{
	return m_MSB;
}

usint BigBinaryInteger::ConvertToInt() const{
	usint ans = -1;
	if(m_MSB>32){
		std::cout<<"Cannot convert to integer\n";
		exit(-20);//just random error code
	}
	else{
		ans = 0;
		usint exp = 1;
		for(usint i=0;i<4;i++){
			ans += (usint)m_value[m_nchar-1-i]*exp;
			exp <<= 8;
		}
	}

	return ans;
}

double BigBinaryInteger::ConvertToDouble() const{
	return std::stod(this->ToString());
}

//PUBLIC FUNCTIONS

BigBinaryInteger BigBinaryInteger::Plus(const BigBinaryInteger& b) const{

	const BigBinaryInteger* A = NULL;//two operands A and B for addition, A is the greater one, B is the smaller one
	const BigBinaryInteger* B = NULL;
	if(*this>b){
		A = this; B = &b;
	}
	else {A = &b; B = this;}

	if(B->m_MSB==0)
		return BigBinaryInteger(*A);

	BigBinaryInteger result;//result initiated to the greater APint
	usshort ofl=0;//overflow variable
	//cout<<"A printing  "<<*A<<endl;
	//A->printVal_in_Dec();
	//cout<<"\nB printing  "<<*B<<endl;
	//B->printVal_in_Dec();
	uschar ceilInt8 = ceilIntBy8(A->m_MSB);
	for(sint i=m_nchar-1;i>=m_nchar-ceilInt8;i--){//NChar-ceil(MSB/8)
		ofl = A->m_value[i]+ B->m_value[i]+ofl;//sum of the two apint and the carry over
		//ofl = A->m_value[i]+ B->m_value[i]+ofl;
		result.m_value[i] = (uschar)ofl;
		ofl>>=8;//current overflow
	}

	if(ofl==1){//in the end if overflow is set it indicates MSB is one greater than the one we started with
		//result.m_value[(sint)(m_nchar-ceilIntBy8(A->m_MSB))-1]+=1;
		usshort x = (m_nchar-ceilInt8)-1;
		result.m_value[x] = A->m_value[x]+1;
		//result.m_MSB++;
		result.m_MSB = A->m_MSB+1;
	}
	else{//we find the overflow within the MSB char
		result.m_MSB = A->m_MSB;
		ofl = result.m_value[(sint)(m_nchar-ceilIntBy8(A->m_MSB))];
		usint shift_test = A->m_MSB%8==0? 8:A->m_MSB%8;
		if(ofl>>shift_test!=0)
				result.m_MSB++;
	}

	return result;

}

const BigBinaryInteger& BigBinaryInteger::operator+=(const BigBinaryInteger &b){

	const BigBinaryInteger* A = NULL;//two operands A and B for addition, A is the greater one, B is the smaller one
	const BigBinaryInteger* B = NULL;

	if(b.m_MSB==0)
		return *this;

	if(*this>b){
		A = this; B = &b;
	}
	else {A = &b; B = this;}

	usshort ofl=0;//overflow variable

	uschar ceilInt8 = ceilIntBy8(A->m_MSB);

	for(sint i=m_nchar-1;i>=m_nchar-ceilInt8;i--){//NChar-ceil(MSB/8)
		ofl=A->m_value[i]+ B->m_value[i]+ofl;//sum of the two apint and the carry over
		this->m_value[i] = (uschar)ofl;
		ofl>>=8;//current overflow
	}

	this->m_MSB = A->m_MSB;

	if(ofl==1){//in the end if overflow is set it indicates MSB is one greater than the one we started with
		this->m_value[(sint)(m_nchar-ceilInt8)-1]+=1;
		this->m_MSB++;
	}

	else{//we find the overflow within the MSB char
		ofl = this->m_value[(sint)(m_nchar-ceilInt8)];
		//usint shift_test = (A->m_MSB&7)==0? 8:(A->m_MSB&7);
		usint shift_test;
		usint remainder = m_MSB&7;
		if (remainder==0)
			shift_test = 8;
		else
			shift_test = remainder;
		if(ofl>>shift_test!=0)
				this->m_MSB++;
	}

	return *this;

}

BigBinaryInteger BigBinaryInteger::Minus(const BigBinaryInteger& b) const{

	if(*this<b||*this==b)return std::move(BigBinaryInteger());
	int cntr=0,current=0;

	BigBinaryInteger result(*this);

	int endVal = m_nchar-ceilIntBy8(this->m_MSB);

	for(sint i=m_nchar-1;i>=endVal;i--){
		if(result.m_value[i]<b.m_value[i]){
			current=i;
			cntr = current-1;
			while(result.m_value[cntr]==0){
				result.m_value[cntr]=255;cntr--;
			}
			result.m_value[cntr]--;
			/*cntr++;
			while(cntr!=current){
				result.m_value[cntr]=255;
				cntr++;
			}*/
			result.m_value[i]=result.m_value[i]- b.m_value[i]+256;
		}
		else{
			result.m_value[i]=result.m_value[i]- b.m_value[i];
		}
		cntr=0;
	}

	while(true){
		if(result.m_value[endVal]!=0)break;
		endVal++;
	}
	result.m_MSB = (m_nchar-endVal-1)*8 + MSB_in_char(result.m_value[endVal]);


	return result;

}

const BigBinaryInteger& BigBinaryInteger::operator-=(const BigBinaryInteger &b){

	if(*this<b||*this==b){
		*this=ZERO;
		return *this;
	}
	int cntr=0,current=0;

	int endVal = m_nchar-ceilIntBy8(this->m_MSB);

	for(sint i=m_nchar-1;i>=endVal;i--){
		if(this->m_value[i]<b.m_value[i]){
			current=i;
			cntr = current-1;
			while(this->m_value[cntr]==0)
				cntr--;
			this->m_value[cntr]--;cntr++;
			while(cntr!=current){
				this->m_value[cntr]=255;
				cntr++;
			}
			this->m_value[i]=this->m_value[i]- b.m_value[i]+256;
		}
		else{
			this->m_value[i]=this->m_value[i]- b.m_value[i];
		}
		cntr=0;
	}

	while(true){
		if(this->m_value[endVal]!=0)break;
		endVal++;
	}
	this->m_MSB = (m_nchar-endVal-1)*8 + MSB_in_char(this->m_value[endVal]);

	return *this;

}

BigBinaryInteger BigBinaryInteger::Times(const BigBinaryInteger& b) const{

	BigBinaryInteger ans;//ans to be returned
	if(b.m_MSB==0)
		return ans;
	if(b.m_MSB==1)
		return BigBinaryInteger(*this);

	uschar ceilInt8 = ceilIntBy8(b.m_MSB);
	for(sint i= m_nchar-1;i>= m_nchar-ceilInt8;i--){
		ans += (this->MulIntegerByChar(b.m_value[i]))<<=( m_nchar-1-i)*8;
	}

	return ans;
}

BigBinaryInteger BigBinaryInteger::DividedBy(const BigBinaryInteger& b) const{
	//std::cout<<*this<<std::endl<<b<<std::endl;

	//std::cout<<*this<<std::endl<<b<<std::endl;

	if(b.m_MSB>this->m_MSB)
		return std::move(BigBinaryInteger(ZERO));
	else if(b==*this)
		return std::move(BigBinaryInteger(ONE));
	else if(b==ZERO)
		throw std::logic_error("DIVISION BY ZERO");

	BigBinaryInteger ans;

	BigBinaryInteger normalised_dividend(*this - this->Mod(b));

	uschar ncharInDivisor = ceilIntBy8(b.m_MSB);
	uschar msbCharInDivisor = b.m_value[(usint)( m_nchar-ncharInDivisor)];
	uschar ncharInNormalised_dividend = ceilIntBy8(normalised_dividend.m_MSB);
	uschar msbCharInRunning_Normalised_dividend = normalised_dividend.m_value[(usint)( m_nchar-ncharInNormalised_dividend)];
	BigBinaryInteger running_dividend;
	BigBinaryInteger runningRemainder;
	BigBinaryInteger expectedProd;
	//BigBinaryInteger ep;
	//Initialize the running dividend
	for(usint i=0;i<ncharInDivisor;i++){
		running_dividend.m_value[ m_nchar-ncharInDivisor+i] = normalised_dividend.m_value[ m_nchar-ncharInNormalised_dividend+i];
	}
	running_dividend.SetMSB();

	uschar estimate=0;

	for(usint i=ncharInNormalised_dividend-ncharInDivisor;i>=0;){
		//running_dividend.PrintValueInDec();std::cout<<std::endl;
		//memManager = runningRemainder;
		runningRemainder = running_dividend.Mod(b);
		//runningRemainder.PrintValueInDec();std::cout<<std::endl;

		expectedProd = running_dividend-runningRemainder;


		//std::cout<<expectedProd<<std::endl;
		if(ceilIntBy8(expectedProd.m_MSB)>ncharInDivisor)
			estimate=255;
		else if(expectedProd.m_MSB==0)
			estimate = 0;
		else
			estimate = expectedProd.m_value[ m_nchar- ceilIntBy8(expectedProd.m_MSB)]/msbCharInDivisor;
		if(estimate<255)
			estimate++;
		//ep = expectedProd;
		while(true){

			if(b.MulIntegerByChar(estimate)==expectedProd){
				break;
			}

			/*std::cout<<b.MulIntegerByChar(estimate)<<std::endl;
			std::cout<<ep<<std::endl;
			ep = ep-b;
			estimate = ep.m_value[ep.m_nchar- (int)ceil((float)ep.m_MSB/8)]/msbCharInDivisor;*/
			estimate--;
		}
		ans = ans<<8;
		ans.m_value[ m_nchar-1] = estimate;
		ans.SetMSB();
		if(i==0)
			break;
		running_dividend = runningRemainder<<8;
		running_dividend.m_value[ m_nchar-1] = normalised_dividend.m_value[m_nchar-i];
		running_dividend.SetMSB();
		//running_dividend.PrintValueInDec();
		//std::cout<<std::endl;
		i--;
	}


	return ans;
}

sint BigBinaryInteger::Compare(const BigBinaryInteger& a) const{
	if(this->m_MSB<a.m_MSB)
		return -1;
	else if(this->m_MSB>a.m_MSB)
		return 1;
	if(this->m_MSB==a.m_MSB){
		uschar ceilInt8 = ceilIntBy8(this->m_MSB);
		sshort testChar;
		for(usint i= m_nchar-ceilInt8;i< m_nchar;i++){
			testChar = this->m_value[i]-a.m_value[i] ;
			if(testChar<0)return -1;
			else if(testChar>0)return 1;
		}
	}

	return 0;
}

BigBinaryInteger BigBinaryInteger::Mod(const BigBinaryInteger& modulus) const{

	if(*this<modulus){
		BigBinaryInteger result(*this);
		return result;
	}
	if(modulus.m_MSB==2 && modulus.m_value[m_nchar-1]==2){
		if(this->m_value[m_nchar-1]%2==0)
			return BigBinaryInteger();
		else
			return BigBinaryInteger(ONE);
	}
	usshort initial_shift = 0;
	if(this->m_MSB > modulus.m_MSB)
		initial_shift=this->m_MSB - modulus.m_MSB -1;
	//cout<<initial_shift<<endl;
	//std::cout << " \n********Before Shift*********" << std::endl;
	BigBinaryInteger j = modulus<<initial_shift;
	//std::cout << " \n********After Shift*********" << std::endl;
	//cout<<"initial j value"<<j<<endl;
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

		//cout<<*result<<endl;
		initial_shift = j.m_MSB - result.m_MSB +1;
		if(result.m_MSB-1>=modulus.m_MSB){
			j>>=initial_shift;
		}
		else{
			j = modulus;
		}
		//cout<<j<<endl;
	}

	return result;

}

BigBinaryInteger BigBinaryInteger::ModBarrett(const BigBinaryInteger& modulus, const BigBinaryInteger& mu) const{

	if(*this<modulus){
		BigBinaryInteger z(*this);
		return z;
	}
	BigBinaryInteger z(*this);
	BigBinaryInteger q(*this);

	uschar n = modulus.m_MSB;
	uschar alpha = n + 3;
	schar beta = -2;

	q>>=n + beta;
	q=q*mu;
	q>>=alpha-beta;
	z-=q*modulus;

	if(z>=modulus)
		z-=modulus;

	return z;

}

BigBinaryInteger BigBinaryInteger::ModBarrett(const BigBinaryInteger& modulus, const BigBinaryInteger mu_arr[BARRETT_LEVELS+1]) const{

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


/*
BigBinaryInteger BigBinaryInteger::ModBarrettKnezevic(const BigBinaryInteger& modulus, const BigBinaryInteger& mu, uschar flag) const{

	if(*this<modulus){
		BigBinaryInteger z(*this);
		return z;
	}
	BigBinaryInteger z(*this);
	BigBinaryInteger q(*this);

	uschar n = modulus.m_MSB;

	if (flag==0)
		q>>=n;
	else
		q>>=n-1;

	z-=q*modulus;

	if(z>=modulus)
		z-=modulus;
	while(z<BigBinaryInteger::ZERO)
		z+=modulus;

	return z;

}
*/
BigBinaryInteger BigBinaryInteger::ModInverse(const BigBinaryInteger& modulus) const{

	//std::cout<<*this<<"This value\n";
	//std::cout<<modulus<<std::endl;

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
		mods.push_back(first.Mod(second));
		quotient.push_back(first.DividedBy(second));
		if(mods.back()==ONE)
			break;
		if(mods.back()==ZERO){
			std::cout<<"NO INVERSE FOUND, GOING TO THROW ERROR\n";
			system("pause");
			throw std::logic_error("MOD INVERSE NOT FOUND");
		}

		first = second;
		second = mods.back();

		//std::cout<<first<<"first value\n";
		//std::cout<<second<<std::endl;

		//system("pause");
	}

	////delete here all the pointer in the mod vector
	//for(usint i=0;i<mods.size();i++)
	//	delete mods[i];

	mods.clear();
	//begin south algorithm
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

	////clean-up section:
	//for(usint i=0;i<mods.size();i++)
	//	delete mods[i];
	mods.clear();

	/*for(usint i=0;i<quotient.size();i++)
		delete quotient[i];*/
	quotient.clear();


	return result;

}

BigBinaryInteger BigBinaryInteger::ModAdd(const BigBinaryInteger& b, const BigBinaryInteger& modulus) const{

	//BigBinaryInteger result = this->Plus(b).Mod(modulus);

	//std::cout << "Function 1 : " << std::endl;
	return this->Plus(b).Mod(modulus);
	//std::cout << "Function 2 : " << std::endl;

}

BigBinaryInteger BigBinaryInteger::ModBarrettAdd(const BigBinaryInteger& b, const BigBinaryInteger& modulus, const BigBinaryInteger mu_arr[BARRETT_LEVELS]) const{

	//BigBinaryInteger result = this->Plus(b).Mod(modulus);

	return this->Plus(b).ModBarrett(modulus,mu_arr);

}

BigBinaryInteger BigBinaryInteger::ModBarrettAdd(const BigBinaryInteger& b, const BigBinaryInteger& modulus, const BigBinaryInteger& mu) const{

	//BigBinaryInteger result = this->Plus(b).Mod(modulus);

	return this->Plus(b).ModBarrett(modulus,mu);

}

BigBinaryInteger BigBinaryInteger::ModSub(const BigBinaryInteger& b, const BigBinaryInteger& modulus) const{

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

BigBinaryInteger BigBinaryInteger::ModBarrettSub(const BigBinaryInteger& b, const BigBinaryInteger& modulus, const BigBinaryInteger& mu) const{

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

BigBinaryInteger BigBinaryInteger::ModBarrettSub(const BigBinaryInteger& b, const BigBinaryInteger& modulus, const BigBinaryInteger mu_arr[BARRETT_LEVELS]) const{

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

BigBinaryInteger BigBinaryInteger::ModMul(const BigBinaryInteger& b, const BigBinaryInteger& modulus) const{

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

BigBinaryInteger BigBinaryInteger::ModBarrettMul(const BigBinaryInteger& b, const BigBinaryInteger& modulus, const BigBinaryInteger& mu) const{

	BigBinaryInteger* a  = const_cast<BigBinaryInteger*>(this);
	BigBinaryInteger* bb = const_cast<BigBinaryInteger*>(&b);

	//if a is greater than q reduce a to its mod value
	if(*this>modulus)
		*a = std::move(this->ModBarrett(modulus,mu));
//	else
//		a = const_cast<BigBinaryInteger*>(this);

	//if b is greater than q reduce b to its mod value
	if(b>modulus)
		*bb = std::move(b.ModBarrett(modulus,mu));
//	else
//		bb = const_cast<BigBinaryInteger*>(&b);

	//return a*b%q

	return (*a**bb).ModBarrett(modulus,mu);
}

BigBinaryInteger BigBinaryInteger::ModBarrettMul(const BigBinaryInteger& b, const BigBinaryInteger& modulus, const BigBinaryInteger mu_arr[BARRETT_LEVELS]) const{

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


BigBinaryInteger BigBinaryInteger::ModExp(const BigBinaryInteger& b, const BigBinaryInteger& modulus) const{
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
		if(Exp.m_value[m_nchar-1]%2==1){
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
/*
BigBinaryInteger  BigBinaryInteger::operator<<(usshort shift) const{

	BigBinaryInteger ans(*this);

	//first check whether shifts are possible without overflow
	if(ans.m_MSB+shift > lbcrypto::BIT_LENGTH)
		throw std::exception("OVERFLOW \n");

	//calculate the no.of 8shifts
	usint shiftByEight = shift>>3;

	uschar remShift = (shift&7);

	if(remShift!=0){

		uschar endVal = m_nchar-ceilIntBy8(m_MSB);
		uschar oFlow = 0;
		usshort temp = 0;
		//std::cout<<std::endl;
		sint i ;
		for(i= m_nchar-1; i>= endVal ; i-- ){
			temp = ans.m_value[i];
			temp <<= remShift;
			ans.m_value[i] = (uschar)temp + oFlow;
			oFlow = temp>>8;
		}

		if(i>-1)
			ans.m_value[i] = oFlow;

		ans.m_MSB += remShift;

	}

	if(shiftByEight!=0){
		usint i= m_nchar-ceilIntBy8(ans.m_MSB);
		for(;i<m_nchar;i++){
			ans.m_value[i-shiftByEight] = ans.m_value[i];
		}

		for(usint j=0;j<shiftByEight;j++)
			ans.m_value[m_nchar-1-j] = 0;

	}


	ans.m_MSB += shiftByEight*8;

	return ans;


}
*/

BigBinaryInteger  BigBinaryInteger::operator<<(usshort shift) const{

	if(this->m_MSB==0)
		return BigBinaryInteger();

	BigBinaryInteger ans(*this);

	//first check whether shifts are possible without overflow
	if(ans.m_MSB+shift > cpu8bit::BIT_LENGTH)
		throw std::logic_error("OVERFLOW \n");

	//calculate the no.of 8shifts
	usint shiftByEight = shift>>3;

	uschar remShift = (shift&7);

	if(remShift!=0){

		uschar endVal = m_nchar-ceilIntBy8(m_MSB);
		uschar oFlow = 0;
		usshort temp = 0;
		//std::cout<<std::endl;
		sint i ;
		for(i= m_nchar-1; i>= endVal ; i-- ){
			temp = ans.m_value[i];
			temp <<= remShift;
			ans.m_value[i] = (uschar)temp + oFlow;
			oFlow = temp>>8;
		}

		if(i>-1)
			ans.m_value[i] = oFlow;

		ans.m_MSB += remShift;

	}

	if(shiftByEight!=0){
		usint i= m_nchar-ceilIntBy8(ans.m_MSB);
		for(;i<m_nchar;i++){
			ans.m_value[i-shiftByEight] = ans.m_value[i];
		}

		for(usint i=0;i<shiftByEight;i++)
			ans.m_value[m_nchar-1-i] = 0;

	}


	ans.m_MSB += shiftByEight*8;

	return ans;

 }


const BigBinaryInteger& BigBinaryInteger::operator<<=(usshort shift){

	if(this->m_MSB==0)
		return *this;

	//first check whether shifts are possible without overflow
	if(this->m_MSB+shift > cpu8bit::BIT_LENGTH)
		throw std::logic_error ("OVERFLOW \n");

	//calculate the no.of 8shifts
	usint shiftByEight = shift>>3;

	uschar remShift = (shift&7);

	if(remShift!=0){

		uschar endVal = m_nchar-ceilIntBy8(this->m_MSB);
		uschar oFlow = 0;
		usshort temp = 0;
		//std::cout<<std::endl;
		sint i ;
		for(i= m_nchar-1; i>= endVal ; i-- ){
			temp = this->m_value[i];
			temp <<= remShift;
			this->m_value[i] = (uschar)temp + oFlow;
			oFlow = temp>>8;
		}

		if(i>-1)
			this->m_value[i] = oFlow;

		this->m_MSB += remShift;

	}

	if(shiftByEight!=0){
		usint i= m_nchar-ceilIntBy8(this->m_MSB);
		for(;i<m_nchar;i++){
			this->m_value[i-shiftByEight] = this->m_value[i];
		}

		for(usint i=0;i<shiftByEight;i++)
			this->m_value[m_nchar-1-i] = 0;

	}


	this->m_MSB += shiftByEight*8;

	return *this;

}
/*
BigBinaryInteger  BigBinaryInteger::operator<<(usshort shift) const{

	//ans is the APint to be returned
	BigBinaryInteger ans(*this);

	//counter to divide a in multiples of 4
	sint counter=(sint)floor((float)shift/4);

	//perform the shifts
	for(sint i=0;i<counter;i++){
		ans = ans.ShiftLeft(4);
	}

	//perform the remaining shifts
	if(shift%4!=0){
		ans=ans.ShiftLeft(shift%4);
	}

	return ans;


}
*/


/*BigBinaryInteger  BigBinaryInteger::operator>>(usshort shift) const{
	//ans is the APint to be returned
	BigBinaryInteger ans(*this);

	//counter to divide a in multiples of 4
	sint counter=(sint)floor((float)shift/4);

	//perform the shifts
	for(sint i=0;i<counter;i++){
		ans= ans.ShiftRight(4);
	}

	//perform the remaining shifts, if a is not a multiple of 4
	if(shift%4!=0){
		ans= (ans.ShiftRight(shift%4));
	}

	return ans;

}
*/

BigBinaryInteger  BigBinaryInteger::operator>>(usshort shift) const{

	if(this->m_MSB==0 || this->m_MSB <= shift)
		return BigBinaryInteger();


	BigBinaryInteger ans(*this);

	//calculate the no.of 8shifts
	usint shiftByEight = shift>>3;

	uschar remShift = (shift&7);

	if(shiftByEight!=0){

		usint endVal= m_nchar-ceilIntBy8(ans.m_MSB);
		usint j= endVal;

		for(sint i= m_nchar-1-shiftByEight;i>=endVal;i--){
			ans.m_value[i+shiftByEight] = ans.m_value[i];
		}

		ans.m_MSB -= shiftByEight<<3;

		while(shiftByEight>0){
			ans.m_value[j] = 0;
			shiftByEight--;
			j++;
		}

		//ans.PrintValueInDec();
	}

	if(remShift!=0){

		uschar overFlow = 0;
		uschar oldVal;
		uschar maskVal = (1<<(remShift))-1;
		uschar compShiftVal = 8- remShift;

		usint startVal = m_nchar - ceilIntBy8(ans.m_MSB);

		for( ;startVal<m_nchar;startVal++){

			oldVal = ans.m_value[startVal];

			ans.m_value[startVal] = (ans.m_value[startVal]>>remShift) + overFlow;

			overFlow = (oldVal &  maskVal);
			overFlow <<= compShiftVal ;
		}

		ans.m_MSB -= remShift;

		//ans.PrintValueInDec();

	}

	return ans;

}

const BigBinaryInteger& BigBinaryInteger::operator>>=(usshort shift){

	if(this->m_MSB==0 )
		return *this;
	else if(this->m_MSB<=shift){
		*this = ZERO;
		return *this;
	}

	//calculate the no.of 8shifts
	usint shiftByEight = shift>>3;

	uschar remShift = (shift&7);

	if(shiftByEight!=0){

		usint endVal= m_nchar-ceilIntBy8(this->m_MSB);
		usint j= endVal;

		for(sint i= m_nchar-1-shiftByEight;i>=endVal;i--){
			this->m_value[i+shiftByEight] = this->m_value[i];
		}

		this->m_MSB -= shiftByEight<<3;

		while(shiftByEight>0){
			this->m_value[j] = 0;
			shiftByEight--;
			j++;
		}

		//ans.PrintValueInDec();
	}



	if(remShift!=0){

		uschar overFlow = 0;
		uschar oldVal;
		uschar maskVal = (1<<(remShift))-1;
		uschar compShiftVal = 8- remShift;

		usint startVal = m_nchar - ceilIntBy8(this->m_MSB);

		for( ;startVal<m_nchar;startVal++){

			oldVal = this->m_value[startVal];

			this->m_value[startVal] = (this->m_value[startVal]>>remShift) + overFlow;

			overFlow = (oldVal &  maskVal);
			overFlow <<= compShiftVal ;
		}

		this->m_MSB -= remShift;

		//ans.PrintValueInDec();

	}

	return *this;

}


std::ostream& operator<<(std::ostream& os, const BigBinaryInteger &ptr_obj){

	//create reference for the object to be printed
	BigBinaryInteger *print_obj;

	usint counter;

	//initiate to object to be printed
	print_obj = new BigBinaryInteger(ptr_obj);

	//print_VALUE array stores the decimal value in the array
	uschar *print_VALUE = new uschar[NUM_DIGIT_IN_PRINTVAL];

	//reset to zero
	for(sint i=0;i<NUM_DIGIT_IN_PRINTVAL;i++)
		*(print_VALUE+i)=0;

	//starts the conversion from base 256 to decimal value
	for(sint i=print_obj->m_MSB;i>0;i--){

		//print_VALUE = print_VALUE*2
		double_bitVal(print_VALUE);
#ifdef DEBUG_OSTREAM
		for(sint i=0;i<NUM_DIGIT_IN_PRINTVAL;i++)
		 std::cout<<(sint)*(print_VALUE+i);
		std::cout<<endl;
#endif
		//adds the bit value to the print_VALUE
		add_bitVal(print_VALUE,print_obj->GetBitAtIndex(i));

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

/**
* This method's logic is based on the
* std::ostream& operator<<(std::ostream& os, const BigBinaryInteger &ptr_obj)
* method in this class.
*
* Added by Arnab Deb Gupta <ad479@njit.edu> on 9/21/15.
*
*/
const std::string BigBinaryInteger::ToString() const {

	//this string object will store this BigBinaryInteger's value
	std::string bbiString;

	//create reference for object to be converted to string
	BigBinaryInteger *print_obj;

	usint counter;

	//initiate to object to be converted
	print_obj = new BigBinaryInteger(*this);

	//print_VALUE array stores the decimal value in the array
	uschar *print_VALUE = new uschar[NUM_DIGIT_IN_PRINTVAL];

	//reset to zero
	for (sint i = 0; i < NUM_DIGIT_IN_PRINTVAL; i++) {
		*(print_VALUE + i) = 0;
	}

	//starts the conversion from base 256 to decimal value
	for (sint i = print_obj->m_MSB; i > 0; i--) {

		double_bitVal(print_VALUE);

		//adds the bit value to the print_VALUE
		add_bitVal(print_VALUE, print_obj->GetBitAtIndex(i));
	}

	//find the first occurrence of non-zero value in print_VALUE
	for (counter = 0; counter < NUM_DIGIT_IN_PRINTVAL - 1; counter++) {
		if ((sint)print_VALUE[counter] != 0) {
			break;
		}
	}

	//append this BigBinaryInteger's digits to this method's returned string object
	for (; counter < NUM_DIGIT_IN_PRINTVAL; counter++) {
		bbiString += std::to_string(print_VALUE[counter]);
	}

	delete[] print_VALUE;
	//deallocate the memory since values are inserted into the string object
	delete print_obj;

	return bbiString;
}


//Check if number is power of two i.e. 16 = 2^4 etc.
bool CheckPowerofTwos(BigBinaryInteger& m_numToCheck){
	usint m_MSB = m_numToCheck.m_MSB;
	for(int i=m_MSB-1;i>0;i--){
		if((sint)m_numToCheck.GetBitAtIndex(i)==(sint)1){
			return false;
		}
	}
	return true;
}

//PRIVATE FUNCTIONS

void BigBinaryInteger::AssignVal(const std::string& v){
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
	sshort bitArr[8] = {};
	//array to store the value of one char
	//for(sint i=0;i<8;i++)//initiate to zero
	//	bitArr[i]=0;
	sint bitValPtr=m_nchar-1;
	//bitValPtr is a pointer to the Value char array, initially pointed to the last char
	//we increment the pointer to the next char when we get the complete value of the char array
	//for(sint i=0;i<m_nchar;i++)//initialie to zero
	//	*(m_value+i)=0;
	sint cnt8=7;
	//cnt8 is a pointer to the bit position in bitArr, when bitArr is compelete it is ready to be transfered to Value

	while(zptr!=arrSize){
		bitArr[cnt8]=DecValue[arrSize-1]%2;
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
	cnt8--;
	if(cnt8==-1){//cnt8 = -1 indicates bitArr is ready for transfer
		cnt8=7;
		m_value[bitValPtr--]=bin82dec(bitArr);//bin82dec converts bitArr to decimal and zeros the content of bitArr
	}
	if(DecValue[zptr]==0)zptr++;//division makes Most significant digit zero, hence we increment zptr to next value
	if(zptr==arrSize&&DecValue[arrSize-1]==0)m_value[bitValPtr]=bin82dec(bitArr);//Value assignment
	}
	delete[] DecValue;//deallocate memory
}

void BigBinaryInteger::SetMSB() {

	m_MSB = 0;
	for(usint i=0;i<m_nchar;i++)//loops to find first nonzero number in char array
		if((short)m_value[i]!=0){
			//bitArr = dec2bin(m_value[i]);//assign the MSB char to bit Array
			m_MSB = (m_nchar-i-1)*8;
			m_MSB+= MSB_in_char(m_value[i]);
			break;
		}

}

uschar BigBinaryInteger::GetBitAtIndex(usint index) const{
	if(index<=0){
		std::cout<<"Invalid index \n";
		return 0;
	}
	uschar result;
	sint idx = m_nchar - ceilIntBy8(index);//idx is the index of the character array
	uschar temp = this->m_value[idx];
	uschar bmask_counter = index%8==0? 8:index%8;//bmask is the bit number in the 8 bit array
	uschar bmask = 1;
	for(sint i=1;i<bmask_counter;i++)
		bmask<<=1;//generate the bitmask number
	result = temp&bmask;//finds the bit in  bit format
	result>>=bmask_counter-1;//shifting operation gives bit either 1 or 0
	return result;

}

usint BigBinaryInteger::GetDigitAtIndexForBase(usint index, usint base) const {
	usint digit = 0;
	usint newIndex = index;
	for (usint i = 1; i < base; i = i*2)
	{
		digit += GetBitAtIndex(newIndex)*i;
		newIndex++;
	}
	return digit;
}

BigBinaryInteger BigBinaryInteger::MulIntegerByChar(uschar b) const{

	if(b==0 || this->m_MSB==0)
		return BigBinaryInteger();
	else if(b==1 )
		return BigBinaryInteger(*this);
	//call constructor without initializing character elements
	BigBinaryInteger ans(1);
	usshort temp, temp1=0;
	usshort mid, mid1=0;
	uschar ofl=0;
	sint endVal = m_nchar-ceilIntBy8(this->m_MSB);
	sint i = m_nchar-1;
	for(;i>= endVal;i--){
		temp = this->m_value[i]*b;//multiplication of two chars
		mid = (uschar)temp + ofl;
		ans.m_value[i] = (uschar)mid;

		//faster in Linux
		//mid>>=8;
		//faster in Windows
		//mid=((uschar*)&mid)[1];
		mid1 = mid>>8;

		//faster in Linux
		//temp>>=8;//flush the first byte
		//faster in Windows
		//temp=((uschar*)&temp)[1];
		temp1 = temp>>8;

		ofl = (uschar)mid1+(uschar)temp1;
	}



	if(endVal==0 && ofl!=0)
		throw "OVERFLOW\n";

	if(ofl!=0){
		ans.m_value[i] = ofl;
		ans.m_MSB = (m_nchar - endVal)*8 + MSB_in_char(ofl);
	}
	else
		ans.m_MSB = (m_nchar - endVal-1)*8 + MSB_in_char(ans.m_value[endVal]);

	return ans;

}

/*
BigBinaryInteger BigBinaryInteger::MulIntegerByChar(uschar b) const{

	if(b==0 || this->m_MSB==0)
		return BigBinaryInteger();
	BigBinaryInteger mid;
	BigBinaryInteger ans;
	usshort temp=0;
	for(sint i= m_nchar-1;i>= m_nchar-ceilIntBy8(this->m_MSB);i--){
		temp = this->m_value[i]*b;//multiplication of two chars
		//mid is a two byte APint constructed to store temp
		mid.m_MSB = MSB_in_short(temp);//gets MSB from temp
		//mid.m_value[m_nchar-1]= temp&255;//stores the first byte
		mid.m_value[m_nchar-1]= (uschar)temp;
		temp>>=8;//flush the first byte
		mid.m_value[m_nchar-2]=(uschar) temp;//store the second byte
		//mid=(mid<<(m_nchar-1-i)*8);//shifts mid by the amount depending on position of i in Value(0,8,16 and so on)
		mid<<=((m_nchar-1-i)*8);//shifts mid by the amount depending on position of i in Value(0,8,16 and so on)
		ans += mid;

	}

	return ans;

}
*/

BigBinaryInteger BigBinaryInteger::ShiftLeft(uschar shift) const{

	if(shift>4)exit(10);//checks if more than 4 shifts are asked
	BigBinaryInteger ans(*this);////answer initiated to APint to be shifted
    usshort temp=0;//temp stores the unshifted value and also calculates the overflow
	usshort bitmask=65280;
	uschar overflow=0;
	for(sint i=m_nchar-1;i>-1;i--){
		temp = ans.m_value[i];
		ans.m_value[i]<<= shift;
		ans.m_value[i]+=overflow;//overflow added from previous calculation
		temp<<= shift;
		overflow=temp>>8;//overflow calulated by bit right shift
		//overflow=temp/256;
	}
	if(ans.m_MSB!=0){
		ans.m_MSB+= shift;//MSB UPDATED
	}
	if(ans.m_MSB>BIT_LENGTH&&BIT_LENGTH%8!=0){
		ans.m_value[0]<<=8-BIT_LENGTH%8;
		ans.m_value[0]>>=8-BIT_LENGTH%8;
	}

	if(ans.m_MSB>=BIT_LENGTH)ans.m_MSB=BIT_LENGTH;//CHECK IF THE OVERFLOW BITS ARE CROSSING THE BIT LENGHT BOUNDARY

	return ans;


}

BigBinaryInteger BigBinaryInteger::ShiftRight(uschar shift) const{

	if(shift>4)exit(10);
	BigBinaryInteger ans(*this);//answer initiated to APint to be shifted
	usshort temp=0;//temporary is used to perform short shifts and calculate overflow
	uschar overflow=0;//stores the overflow
	sint beginValue = m_nchar-ceilIntBy8(ans.m_MSB);///beginValue points to the start of the char array or MSB char
	for(sint i=beginValue;i<m_nchar;i++){
		temp=ans.m_value[i];//temp stores unshifted value
		ans.m_value[i]>>= shift;//shift performed
		ans.m_value[i]+=overflow;//overflow added to finalize char
		temp<<=8;
		temp>>= shift;
		overflow=temp&255;//overflow calculated
	}
	sint sign_check = ans.m_MSB;
	if(sign_check-shift<0)
		ans.m_MSB=0;//boundary condition
	else{
	    ans.m_MSB-= shift;//MSB value set
	}

	return ans;

}



//AUXILIARY FUNCTIONS

static uschar bin82dec(sshort *a){
	uschar Val=0;
	uschar one=1;
	for(sint i=7;i>=0;i--){
		Val+= one**(a+i);
		one<<=1;
		*(a+i)=0;
	}
	return Val;
}

static uschar* dec2bin(uschar a){
	uschar *arr = new uschar[8]();
	uschar arrPtr=7;
	/*for(usint i=0;i<8;i++)
		arr[i]=0;*/
	while(a!=0){
		arr[arrPtr]=a%2;
		a>>=1;
		arrPtr--;
	}
	return arr;
}

static uschar MSB_in_short(usshort in){

	return lbcrypto::GetMSB32(in);

}

static uschar MSB_in_char(uschar in){

	return lbcrypto::GetMSB32(in);

}

static void double_bitVal(uschar* a){
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

static void add_bitVal(uschar* a,uschar b){
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

uschar BigBinaryInteger::ceilIntBy8(uschar Number){
	//if(Number%8!=0){
	if((Number&7) != 0){
		return (Number>>3)+1;
	}
	else{
		return Number>>3;
	}
}

bool operator==(const BigBinaryInteger& a, const BigBinaryInteger& b){

	if(a.m_MSB!=b.m_MSB)
		return false;
	else{
		uschar ceilInt8 = BigBinaryInteger::ceilIntBy8(a.m_MSB);
		for(usint i= BigBinaryInteger::m_nchar-ceilInt8;i< BigBinaryInteger::m_nchar;i++)
			if(a.m_value[i]!=b.m_value[i])
				return false;
	}
	return true;

}
bool operator!=(const BigBinaryInteger& a, const BigBinaryInteger& b){
	return !(a==b);
}
bool operator>(const BigBinaryInteger& a, const BigBinaryInteger& b){
	if(a.m_MSB<b.m_MSB)
		return false;
	else if(a.m_MSB>b.m_MSB)
		return true;
	else{
		uschar ceilInt8 = BigBinaryInteger::ceilIntBy8(a.m_MSB);
		for(usint i= BigBinaryInteger::m_nchar-ceilInt8;i< BigBinaryInteger::m_nchar;i++){
			if(a.m_value[i]<b.m_value[i])
				return false;
			else if(a.m_value[i]>b.m_value[i])
				return true;
		}

	}
	return false;
}
bool operator>=(const BigBinaryInteger& a, const BigBinaryInteger& b){
	return (a>b || a==b);
}
bool operator< (const BigBinaryInteger& a, const BigBinaryInteger& b){

	if(a.m_MSB<b.m_MSB)
		return true;
	else if(a.m_MSB>b.m_MSB)
		return false;
	else{
		uschar ceilInt8 = BigBinaryInteger::ceilIntBy8(a.m_MSB);
		for(usint i= BigBinaryInteger::m_nchar-ceilInt8;i< BigBinaryInteger::m_nchar;i++){
			if(a.m_value[i]>b.m_value[i])
				return false;
			else if(a.m_value[i]<b.m_value[i])
				return true;
		}

	}
	return false;

}
bool operator<=(const BigBinaryInteger& a, const BigBinaryInteger& b){
	return (a<b || a==b);
}

/*
	This method can be used to convert int to BigBinaryInteger
*/
BigBinaryInteger BigBinaryInteger::intToBigBinaryInteger(usint m){

	BigBinaryInteger result;
	usint msb = lbcrypto::GetMSB32(m);
	uschar ceilInt8 = ceilIntBy8(msb);

	for(sint i= m_nchar-1;i>= m_nchar-ceilInt8;i--){
		result.m_value[i] = (uschar) m;
		m>>=8;
	}
	result.m_MSB = msb;

	return result;

}

BigBinaryInteger BigBinaryInteger::BinaryToBigBinaryInt(const std::string& bitString){
	std::string zero = "0";
	BigBinaryInteger value("0");
	usint len = bitString.length();
	for (usint index = 0; index < len; index++)
  	{
  		if((zero[0] == bitString[index]))
  			continue;
  		else {
  			value += BigBinaryInteger::TWO.Exp(len - 1 - index);
  		}
  	}
  	return value;
}

BigBinaryInteger BigBinaryInteger::Exp(usint p) const{
	if (p == 0) return BigBinaryInteger(BigBinaryInteger::ONE);
	BigBinaryInteger x(*this);
  	if (p == 1) return x;

	BigBinaryInteger tmp = x.Exp(p/2);
	if (p%2 == 0) return tmp * tmp;
	else return tmp * tmp * x;
}

} // namespace lbcrypto ends


