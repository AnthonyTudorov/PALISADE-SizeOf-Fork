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
//#include "../nbtheory.h"


namespace cpu_int {

//CTORS
template<class IntegerType>
BigBinaryVector<IntegerType>::BigBinaryVector(){
	this->m_length = 0;
	//this->m_modulus;
	m_data = NULL;
}

template<class IntegerType>
BigBinaryVector<IntegerType>::BigBinaryVector(usint length){
	this->m_length = length;
	this->m_modulus;
	this->m_data = new IntegerType*[m_length];
	for (usint i = 0; i < m_length; i++){
		m_data[i] = new IntegerType();
	}

}

template<class IntegerType>
BigBinaryVector<IntegerType>::BigBinaryVector(usint length, const IntegerType& modulus){
	this->m_length = length;
	this->m_modulus = modulus;
	this->m_data = new IntegerType*[m_length];
	for (usint i = 0; i < m_length; i++){
		m_data[i] = new IntegerType();
	}

}

template<class IntegerType>
BigBinaryVector<IntegerType>::BigBinaryVector(const BigBinaryVector &bigBinaryVector){

	m_length = bigBinaryVector.m_length;
	m_modulus = bigBinaryVector.m_modulus;
	m_data = new IntegerType*[m_length];
	for(usint i=0;i<m_length;i++){
		m_data[i]= new IntegerType(*bigBinaryVector.m_data[i]);
	}

}

template<class IntegerType>
BigBinaryVector<IntegerType>::BigBinaryVector(BigBinaryVector &&bigBinaryVector){
	m_data = bigBinaryVector.m_data;
	m_length = bigBinaryVector.m_length;
	m_modulus = bigBinaryVector.m_modulus;
	bigBinaryVector.m_data = NULL;
}

//ASSIGNMENT OPERATOR
template<class IntegerType>
BigBinaryVector<IntegerType>& BigBinaryVector<IntegerType>::operator=(const BigBinaryVector &rhs){
	if(this!=&rhs){
		if(this->m_length==rhs.m_length){
			for (usint i = 0; i < m_length; i++){
				*this->m_data[i] = *rhs.m_data[i];
			}
		}
		else{
			//throw std::logic_error("Trying to copy vectors of different size");
			delete m_data;
			m_length = rhs.m_length;
			m_modulus = rhs.m_modulus;
			m_data = new IntegerType*[m_length];
			for (usint i = 0; i < m_length; i++){
				m_data[i] = new IntegerType(*rhs.m_data[i]);
			}
		}
	}

	return *this;
}

template<class IntegerType>
BigBinaryVector<IntegerType>& BigBinaryVector<IntegerType>::operator=(BigBinaryVector &&rhs){

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

template<class IntegerType>
BigBinaryVector<IntegerType>::~BigBinaryVector(){
	//std::cout<<"destructor called for vector of size: "<<this->m_length<<"  "<<std::endl;
	if(m_data!=NULL){
		for(usint i=0;i<m_length;i++){
			delete  m_data[i];
		}
		delete [] m_data;
	}

}

//ACCESSORS
template<class IntegerType_c>
std::ostream& operator<<(std::ostream& os, const BigBinaryVector<IntegerType_c> &ptr_obj){

	os<<std::endl;
	for(usint i=0;i<ptr_obj.m_length;i++){
		os<<*ptr_obj.m_data[i] <<std::endl;
	}

	return os;
}

template<class IntegerType>
void BigBinaryVector<IntegerType>::SetValAtIndex(usint index, const IntegerType& value){

	if(!this->IndexCheck(index)){
			std::cout<<"Invalid index input \n";
	}
	else{
		*this->m_data[index] = value;
	}
}

template<class IntegerType>
void BigBinaryVector<IntegerType>::SetValAtIndex(usint index, const std::string& str){
	if(!this->IndexCheck(index)){
		std::cout<<"Invalid index input \n";
	}
	else{
		this->m_data[index]->SetValue(str);
	}
}

template<class IntegerType>
const IntegerType& BigBinaryVector<IntegerType>::GetValAtIndex(usint index) const{
	if(!this->IndexCheck(index)){
		std::cout<<"Invalid index input \n";
		return (IntegerType)NULL;
	}
	return *this->m_data[index];
}

template<class IntegerType>
const IntegerType& BigBinaryVector<IntegerType>::operator[](usint index) const{
	return  this->GetValAtIndex(index);
}

template<class IntegerType>
void BigBinaryVector<IntegerType>::SetModulus(const IntegerType& value){
	this->m_modulus = value;
}

template<class IntegerType>
const IntegerType& BigBinaryVector<IntegerType>::GetModulus() const{

	return this->m_modulus;

}


template<class IntegerType>
usint BigBinaryVector<IntegerType>::GetLength() const{
	return this->m_length;
}

template<class IntegerType>
BigBinaryVector<IntegerType> BigBinaryVector<IntegerType>::Mod(const IntegerType& modulus) const{

	//BigBinaryVector ans(*this);

	//for(usint i=0;i<this->m_length;i++){
	//	*ans.m_data[i] = ans.m_data[i]->Mod(modulus);
	//}
	//return ans;

	if (modulus==IntegerType::TWO)
		return this->ModByTwo();
	else 
	{
		BigBinaryVector ans(this->GetLength());
		IntegerType halfQ(this->GetModulus() >> 1);
		for (usint i = 0; i<ans.GetLength(); i++) {
			if (this->GetValAtIndex(i)>halfQ) {
				ans.SetValAtIndex(i,this->GetValAtIndex(i).ModSub(this->GetModulus(),modulus));
			}
			else {
				ans.SetValAtIndex(i,this->GetValAtIndex(i).Mod(modulus));
			}
		}
		return ans;
	}
}

template<class IntegerType>
BigBinaryVector<IntegerType> BigBinaryVector<IntegerType>::ModAdd(const IntegerType &b) const{
	BigBinaryVector ans(*this);
//	for(usint i=0;i<this->m_length;i++){
//		*ans.m_data[0] = ans.m_data[0]->ModAdd(b,this->m_modulus);
//		*ans.m_data[i] = ans.m_data[i]->ModAdd(b, this->m_modulus);
//	}
	*ans.m_data[0] = ans.m_data[0]->ModAdd(b, this->m_modulus);
	return ans;
}

template<class IntegerType>
BigBinaryVector<IntegerType> BigBinaryVector<IntegerType>::ModSub(const IntegerType &b) const{
	BigBinaryVector ans(*this);

	for(usint i=0;i<this->m_length;i++){
		*ans.m_data[i] = ans.m_data[i]->ModSub(b,this->m_modulus);
	}
	return ans;
}

template<class IntegerType>
BigBinaryVector<IntegerType> BigBinaryVector<IntegerType>::ModMul(const IntegerType &b) const{
	BigBinaryVector ans(*this);

	//Precompute the Barrett mu parameter
	IntegerType temp(IntegerType::ONE);

	// std::cout << "A : " << std::endl;

	temp<<=2*this->GetModulus().GetMSB()+3;

	// std::cout << "B : " << std::endl;

	IntegerType mu = temp.DividedBy(this->GetModulus());

	// std::cout << "C : " << std::endl;

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

		// std::cout << "D : " << std::endl;

//		*ans.m_data[i] = ans.m_data[i]->ModAdd(*b.m_data[i],this->m_modulus);
		*ans.m_data[i] = ans.m_data[i]->ModBarrettMul(b,this->m_modulus,mu);
	}

	return ans;
}

template<class IntegerType>
BigBinaryVector<IntegerType> BigBinaryVector<IntegerType>::ModExp(const IntegerType &b) const{
	BigBinaryVector ans(*this);
	for(usint i=0;i<this->m_length;i++){
		*ans.m_data[i] = ans.m_data[i]->ModExp(b,this->m_modulus);
	}
	return ans;
}

template<class IntegerType>
BigBinaryVector<IntegerType> BigBinaryVector<IntegerType>::ModInverse() const{

	BigBinaryVector ans(*this);
	//std::cout << ans << std::endl;
	for(usint i=0;i<this->m_length;i++){
		//std::cout << *ans.m_data[i] << std::endl;
		//ans.m_data[i]->PrintValueInDec();
		*ans.m_data[i] = ans.m_data[i]->ModInverse(this->m_modulus);
	}
	return ans;

}

template<class IntegerType>
BigBinaryVector<IntegerType> BigBinaryVector<IntegerType>::ModAdd(const BigBinaryVector &b) const{

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

template<class IntegerType>
BigBinaryVector<IntegerType> BigBinaryVector<IntegerType>::ModSub(const BigBinaryVector &b) const{

	if(this->m_length!=b.m_length){
		std::cout<<" Invalid argument \n";
		return (BigBinaryVector)NULL;
	}

	BigBinaryVector ans(*this);

	for(usint i=0;i<ans.m_length;i++){
		*ans.m_data[i] = ans.m_data[i]->ModSub(*b.m_data[i],this->m_modulus);
	}
	return ans;

}

template<class IntegerType>
BigBinaryVector<IntegerType> BigBinaryVector<IntegerType>::ModByTwo() const {

	BigBinaryVector ans(this->GetLength());
	IntegerType halfQ(this->GetModulus() >> 1);
	for (usint i = 0; i<ans.GetLength(); i++) {
		if (this->GetValAtIndex(i)>halfQ) {
			if (this->GetValAtIndex(i).Mod(IntegerType::TWO) == IntegerType::ONE)
				ans.SetValAtIndex(i, IntegerType::ZERO);
			else
				ans.SetValAtIndex(i, IntegerType::ONE);
		}
		else {
			if (this->GetValAtIndex(i).Mod(IntegerType::TWO) == IntegerType::ONE)
				ans.SetValAtIndex(i, IntegerType::ONE);
			else
				ans.SetValAtIndex(i, IntegerType::ZERO);
		}

	}
	return ans;
}

template<class IntegerType>
const BigBinaryVector<IntegerType>& BigBinaryVector<IntegerType>::operator+=(const BigBinaryVector &b) {

	if(this->m_length!=b.m_length){
		std::cout<<" Invalid argument \n";
		return (BigBinaryVector)NULL;
	}

	for(usint i=0;i<this->m_length;i++){
		*this->m_data[i] = this->m_data[i]->ModAdd(*b.m_data[i],this->m_modulus);
	}
	return *this;

}

template<class IntegerType>
BigBinaryVector<IntegerType> BigBinaryVector<IntegerType>::ModMul(const BigBinaryVector &b) const{

	if(this->m_length!=b.m_length){
		std::cout<<" Invalid argument \n";
		return (BigBinaryVector)NULL;
	}

	BigBinaryVector ans(*this);

	//Precompute the Barrett mu parameter
	IntegerType temp(IntegerType::ONE);
	temp<<=2*this->GetModulus().GetMSB()+3;
	IntegerType mu = temp.DividedBy(this->GetModulus());

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

/*
template<class IntegerType>
BigBinaryVector<IntegerType> BigBinaryVector<IntegerType>::ModMatrixMul(const BigBinaryMatrix &a) const{
	if(a.GetColumnSize()!=this->m_length){
		std::cout<<" Invalid arguements \n";
		return (BigBinaryVector)NULL;
	}
	BigBinaryVector ans(a.GetRowSize());
	IntegerType mid_ans("0");
	for(usint i=0;i<a.GetRowSize();i++){
		mid_ans.SetValue("0");
		for(usint j=0;j<this->m_length;j++){
			mid_ans = mid_ans + a.GetValAtIndex(i,j)**this->m_data[j];
		}
		*ans.m_data[i] = mid_ans.Mod(m_modulus);
	}

	return ans;

}
*/

//Gets the ind
template<class IntegerType>
BigBinaryVector<IntegerType> BigBinaryVector<IntegerType>::GetDigitAtIndexForBase(usint index, usint base) const{
	BigBinaryVector ans(*this);
	for(usint i=0;i<this->m_length;i++){
		*ans.m_data[i] = IntegerType(ans.m_data[i]->GetDigitAtIndexForBase(index,base));
	}

	return ans;
}

// JSON FACILITY - SetIdFlag Operation
template<class IntegerType>
std::unordered_map <std::string, std::unordered_map <std::string, std::string>> BigBinaryVector<IntegerType>::SetIdFlag(std::unordered_map <std::string, std::unordered_map <std::string, std::string>> serializationMap, std::string flag) const {

	//Place holder

	return serializationMap;
}

// JSON FACILITY - Serialize Operation
template<class IntegerType>
std::unordered_map <std::string, std::unordered_map <std::string, std::string>> BigBinaryVector<IntegerType>::Serialize(std::unordered_map <std::string, std::unordered_map <std::string, std::string>> serializationMap, std::string fileFlag) const {

	std::unordered_map <std::string, std::string> bbvMap;

	bbvMap.emplace("Modulus", this->GetModulus().ToString());

	std::string pkBufferString;
	IntegerType pkVectorElem;
	usint pkVectorLength = 0;
	std::string pkVectorElemVal;
	pkVectorLength = GetLength();
	for (int i = 0; i < pkVectorLength; i++) {
		pkVectorElem = GetValAtIndex(i);

		pkVectorElemVal = pkVectorElem.ToString();

		pkBufferString += pkVectorElemVal;
		if (i != (pkVectorLength - 1)) {
			pkBufferString += "|";
		}
	}
	bbvMap.emplace("VectorValues", pkBufferString);

	serializationMap.emplace("BigBinaryVector", bbvMap);

	return serializationMap;
}

// JSON FACILITY - Deserialize Operation
template<class IntegerType>
void BigBinaryVector<IntegerType>::Deserialize(std::unordered_map <std::string, std::unordered_map <std::string, std::string>> serializationMap) {

	std::unordered_map<std::string, std::string> bbvMap = serializationMap["BigBinaryVector"];

	IntegerType bbiModulus(bbvMap["Modulus"]);
	this->SetModulus(bbiModulus);

	std::string vectorVals = bbvMap["VectorValues"];
	IntegerType vectorElem;
	std::string vectorElemVal;
	usint i = 0;
	while (vectorVals.find("|", 0)) {
		size_t pos = vectorVals.find("|", 0);
		vectorElemVal = vectorVals.substr(0, pos);

		std::string::size_type posTrim = vectorElemVal.find_last_not_of(' ');
		if (posTrim != std::string::npos) {
			if (vectorElemVal.length() != posTrim + 1) {
				vectorElemVal.erase(posTrim + 1);
			}
			posTrim = vectorElemVal.find_first_not_of(' ');
			if (posTrim != 0) {
				vectorElemVal.erase(0, posTrim);
			}
		}
		else {
			vectorElemVal = "";
		}

		vectorElem.SetValue(vectorElemVal);
		vectorVals.erase(0, pos + 1);
		this->SetValAtIndex(i, vectorElem);
		i++;

		if (i == this->GetLength()) {
			break;
		}
	}
}

//Private functions
template<class IntegerType>
bool BigBinaryVector<IntegerType>::IndexCheck(usint length) const{
	if(length>this->m_length)
		return false;
	return true;
}

} // namespace lbcrypto ends