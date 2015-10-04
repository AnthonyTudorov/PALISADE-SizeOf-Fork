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

#include "binvect.h"
#include "../nbtheory.h"


namespace cpu8bit {

//CTORS
BigBinaryVector::BigBinaryVector(){
	this->m_length = 1;
	this->m_modulus;
	
	m_data = NULL;
}

BigBinaryVector::BigBinaryVector(usint length){
	this->m_length = length;
	this->m_modulus;
	this->m_data = new BigBinaryInteger*[m_length];
	
	for(usint i=0;i<m_length;i++)
		m_data[i]=new BigBinaryInteger();
		
}

BigBinaryVector::BigBinaryVector(usint length, const BigBinaryInteger& modulus){
	this->m_length = length;
	this->m_modulus = modulus;
	this->m_data = new BigBinaryInteger*[m_length];
	for(usint i=0;i<m_length;i++)
		m_data[i]=new BigBinaryInteger();

}

BigBinaryVector::BigBinaryVector(const BigBinaryVector &bigBinaryVector){
	
	m_length = bigBinaryVector.m_length;
	m_modulus = bigBinaryVector.m_modulus;
	m_data = new BigBinaryInteger*[m_length];
	for(usint i=0;i<m_length;i++)
		m_data[i]= new BigBinaryInteger(*bigBinaryVector.m_data[i]);
	
}

BigBinaryVector::BigBinaryVector(BigBinaryVector &&bigBinaryVector){
	m_data = bigBinaryVector.m_data;
	m_length = bigBinaryVector.m_length;
	m_modulus = bigBinaryVector.m_modulus;
	bigBinaryVector.m_data = NULL;
}

//ASSIGNMENT OPERATOR
BigBinaryVector& BigBinaryVector::operator=(const BigBinaryVector &rhs){
	if(this!=&rhs){
		if(this->m_length==rhs.m_length){
			for(usint i=0;i<m_length;i++)
				*this->m_data[i] = *rhs.m_data[i];				
		}
		else{
			//throw std::logic_error("Trying to copy vectors of different size");	
			delete m_data;
			m_length = rhs.m_length;
			m_modulus = rhs.m_modulus;
			m_data = new BigBinaryInteger*[m_length];
			for(usint i=0;i<m_length;i++)
				m_data[i] = new BigBinaryInteger(*rhs.m_data[i]);
		}
	}

	return *this;
}

BigBinaryVector& BigBinaryVector::operator=(BigBinaryVector &&rhs){

	if(this!=&rhs){

		if(m_data!=NULL){
			for(usint i=0;i<m_length;i++)
				delete m_data[i];
			delete []m_data;
		}
		m_data = rhs.m_data;
		m_length = rhs.m_length;
		m_modulus = rhs.m_modulus;
		rhs.m_data = NULL;
	}

	return *this;

}

BigBinaryVector::~BigBinaryVector(){
	//std::cout<<"destructor called for vector of size: "<<this->m_length<<"  "<<std::endl;
	if(m_data!=NULL){
		for(usint i=0;i<m_length;i++){
			delete  m_data[i];
		}
		delete [] m_data;
	}
	
}

//ACCESSORS
std::ostream& operator<<(std::ostream& os, const BigBinaryVector &ptr_obj){
	
	os<<std::endl;
	for(usint i=0;i<ptr_obj.m_length;i++){
		os<<*ptr_obj.m_data[i] <<std::endl;
	}

	return os;
}

void BigBinaryVector::SetValAtIndex(usint index, const BigBinaryInteger& value){
	
	if(!this->IndexCheck(index)){
			std::cout<<"Invalid index input \n";
	}
	else{
		*this->m_data[index] = value; 
	}
}

void BigBinaryVector::SetValAtIndex(usint index, const std::string& str){
	if(!this->IndexCheck(index)){
		std::cout<<"Invalid index input \n";
	}
	else{
		this->m_data[index]->SetValue(str);  
	}
}

const BigBinaryInteger& BigBinaryVector::GetValAtIndex(usint index) const{
	if(!this->IndexCheck(index)){
		std::cout<<"Invalid index input \n";
		return (BigBinaryInteger)NULL;
	}
	return *this->m_data[index];
}

void BigBinaryVector::SetModulus(const BigBinaryInteger& value){
	this->m_modulus = value; 
}

const BigBinaryInteger& BigBinaryVector::GetModulus() const{
	
	return this->m_modulus;

}

usint BigBinaryVector::GetLength() const{
	return this->m_length;
}

BigBinaryVector BigBinaryVector::Mod(const BigBinaryInteger& modulus) const{
	
	BigBinaryVector ans(*this);
	
	for(usint i=0;i<this->m_length;i++){
		*ans.m_data[i] = ans.m_data[i]->Mod(modulus);
	}
	return ans;
}

BigBinaryVector BigBinaryVector::ModAdd(const BigBinaryInteger &b) const{
	BigBinaryVector ans(*this);
	//for(usint i=0;i<this->m_length;i++){
	//	*ans.m_data[i] = ans.m_data[i]->ModAdd(b,this->m_modulus);
	//}
	*ans.m_data[0] = ans.m_data[0]->ModAdd(b, this->m_modulus);
	return ans;
}

BigBinaryVector BigBinaryVector::ModSub(const BigBinaryInteger &b) const{
	BigBinaryVector ans(*this);
	
	for(usint i=0;i<this->m_length;i++){
		*ans.m_data[i] = ans.m_data[i]->ModSub(b,this->m_modulus);
	}
	return ans;
}

BigBinaryVector BigBinaryVector::ModMul(const BigBinaryInteger &b) const{
	BigBinaryVector ans(*this);

	//Precompute the Barrett mu parameter
	BigBinaryInteger temp(BigBinaryInteger::ONE);
	temp<<=2*this->GetModulus().GetMSB()+3;
	BigBinaryInteger mu = temp.DividedBy(this->GetModulus());

	//Precompute the Barrett mu values
	/*BigBinaryInteger temp;
	uschar gamma;
	uschar modulusLength = this->GetModulus().GetMSB() ;
	BigBinaryInteger mu_arr[BARRETT_LEVELS+1];
	for(usint i=0;i<BARRETT_LEVELS+1;i++) {
		temp = BigBinaryInteger::ONE;
		gamma = modulusLength*i/BARRETT_LEVELS;
		temp<<=modulusLength+gamma+3;
		mu_arr[i] = temp.DividedBy(this->GetModulus());
	}*/

	for(usint i=0;i<this->m_length;i++){
		*ans.m_data[i] = ans.m_data[i]->ModBarrettMul(b,this->m_modulus,mu);
	}

	return ans;
}

BigBinaryVector BigBinaryVector::ModExp(const BigBinaryInteger &b) const{
	BigBinaryVector ans(*this);
	for(usint i=0;i<this->m_length;i++){
		*ans.m_data[i] = ans.m_data[i]->ModExp(b,this->m_modulus);
	}
	return ans;
}

BigBinaryVector BigBinaryVector::ModInverse() const{
		
	BigBinaryVector ans(*this);
	for(usint i=0;i<this->m_length;i++){
		*ans.m_data[i] = ans.m_data[i]->ModInverse(this->m_modulus);
	}
	return ans;
		
}

BigBinaryVector BigBinaryVector::ModAdd(const BigBinaryVector &b) const{
		
	if(this->m_length!=b.m_length){
		std::cout<<" Invalid argument \n";
		return (BigBinaryVector)NULL;
	}

	BigBinaryVector ans(*this);

	for(usint i=0;i<ans.m_length;i++){
		*ans.m_data[i] = ans.m_data[i]->ModAdd(*b.m_data[i],this->m_modulus);
	}
	return ans;

}

const BigBinaryVector& BigBinaryVector::operator+=(const BigBinaryVector &b) {
		
	if(this->m_length!=b.m_length){
		std::cout<<" Invalid argument \n";
		return (BigBinaryVector)NULL;
	}

	for(usint i=0;i<this->m_length;i++){
		*this->m_data[i] = this->m_data[i]->ModAdd(*b.m_data[i],this->m_modulus);
	}
	return *this;

}

BigBinaryVector BigBinaryVector::ModMul(const BigBinaryVector &b) const{

	if(this->m_length!=b.m_length){
		std::cout<<" Invalid argument \n";
		return (BigBinaryVector)NULL;
	}

	BigBinaryVector ans(*this);

	//Precompute the Barrett mu parameter
	BigBinaryInteger temp(BigBinaryInteger::ONE);
	temp<<=2*this->GetModulus().GetMSB()+3;
	BigBinaryInteger mu = temp.DividedBy(this->GetModulus());

	//Precompute the Barrett mu values
	/*BigBinaryInteger temp;
	uschar gamma;
	uschar modulusLength = this->GetModulus().GetMSB() ;
	BigBinaryInteger mu_arr[BARRETT_LEVELS+1];
	for(usint i=0;i<BARRETT_LEVELS+1;i++) {
		temp = BigBinaryInteger::ONE;
		gamma = modulusLength*i/BARRETT_LEVELS;
		temp<<=modulusLength+gamma+3;
		mu_arr[i] = temp.DividedBy(this->GetModulus());
	}*/

	for(usint i=0;i<ans.m_length;i++){
		//*ans.m_data[i] = ans.m_data[i]->ModMul(*b.m_data[i],this->m_modulus);
		*ans.m_data[i] = ans.m_data[i]->ModBarrettMul(*b.m_data[i],this->m_modulus,mu);
	}
	return ans;
}

BigBinaryVector BigBinaryVector::ModMatrixMul(const BigBinaryMatrix &a) const{
	if(a.GetColumnSize()!=this->m_length){
		std::cout<<" Invalid arguements \n";
		return (BigBinaryVector)NULL;
	}
	BigBinaryVector ans(a.GetRowSize());
	BigBinaryInteger mid_ans("0");
	for(usint i=0;i<a.GetRowSize();i++){
		mid_ans.SetValue("0");
		for(usint j=0;j<this->m_length;j++){
			mid_ans = mid_ans + a.GetValAtIndex(i,j)**this->m_data[j];
		}
		*ans.m_data[i] = mid_ans.Mod(m_modulus);
	}

	return ans;				
	
}

//Gets the ind
BigBinaryVector BigBinaryVector::GetDigitAtIndexForBase(usint index, usint base) const{
	BigBinaryVector ans(*this);
	for(usint i=0;i<this->m_length;i++){
		*ans.m_data[i] = lbcrypto::intToBigBinaryInteger(ans.m_data[i]->GetDigitAtIndexForBase(index,base));
	}

	return ans;
}

//Private functions
bool BigBinaryVector::IndexCheck(usint length) const{
	if(length>this->m_length)
		return false;
	return true;
}

} // namespace lbcrypto ends
