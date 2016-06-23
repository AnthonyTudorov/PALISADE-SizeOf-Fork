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

#include "../../utils/serializable.h"
#include "../cpu_int/binvect.h"
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
	//this->m_modulus;
	this->m_data = new IntegerType[m_length] ();
}

template<class IntegerType>
BigBinaryVector<IntegerType>::BigBinaryVector(usint length, const IntegerType& modulus){
	this->m_length = length;
	this->m_modulus = modulus;
	this->m_data = new IntegerType[m_length] ();
}

template<class IntegerType>
BigBinaryVector<IntegerType>::BigBinaryVector(const BigBinaryVector &bigBinaryVector){

	m_length = bigBinaryVector.m_length;
	m_modulus = bigBinaryVector.m_modulus;
	m_data = new IntegerType[m_length];
	for(usint i=0;i<m_length;i++){
		m_data[i] = bigBinaryVector.m_data[i];
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
				this->m_data[i] = rhs.m_data[i];
			}
		}
		else{
			//throw std::logic_error("Trying to copy vectors of different size");
			delete [] m_data;
			m_length = rhs.m_length;
			m_modulus = rhs.m_modulus;
			m_data = new IntegerType[m_length];
			for (usint i = 0; i < m_length; i++){
				m_data[i] = rhs.m_data[i];
			}
		}
	}

	return *this;
}

template<class IntegerType>
BigBinaryVector<IntegerType>& BigBinaryVector<IntegerType>::operator=(BigBinaryVector &&rhs){

	if(this!=&rhs){

		delete [] m_data;
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
	delete [] m_data;
}

//ACCESSORS
template<class IntegerType_c>
std::ostream& operator<<(std::ostream& os, const BigBinaryVector<IntegerType_c> &ptr_obj){

	os<<std::endl;
	for(usint i=0;i<ptr_obj.m_length;i++){
		os<< ptr_obj.m_data[i] <<std::endl;
	}

	return os;
}

template<class IntegerType>
void BigBinaryVector<IntegerType>::SetValAtIndex(usint index, const IntegerType& value){

	if(!this->IndexCheck(index)){
			std::cout<<"Invalid index input \n";
	}
	else{
		this->m_data[index] = value;
	}
}

template<class IntegerType>
void BigBinaryVector<IntegerType>::SetValAtIndex(usint index, const std::string& str){
	if(!this->IndexCheck(index)){
		std::cout<<"Invalid index input \n";
	}
	else{
		this->m_data[index].SetValue(str);
	}
}

template<class IntegerType>
const IntegerType& BigBinaryVector<IntegerType>::GetValAtIndex(usint index) const{
	if(!this->IndexCheck(index)){
		std::cout<<"Invalid index input \n";
		return (IntegerType)NULL;
	}
	return this->m_data[index];
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
	//	ans.m_data[i] = ans.m_data[i].Mod(modulus);
	//}
	//return ans;

	if (modulus==IntegerType::TWO)
		return this->ModByTwo();
	else 
	{
		BigBinaryVector ans(this->GetLength(),this->GetModulus());
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
//		ans.m_data[0] = ans.m_data[0].ModAdd(b,this->m_modulus);
//		ans.m_data[i] = ans.m_data[i].ModAdd(b, this->m_modulus);
//	}
	ans.m_data[0] = ans.m_data[0].ModAdd(b, this->m_modulus);
	return ans;
}

template<class IntegerType>
BigBinaryVector<IntegerType> BigBinaryVector<IntegerType>::ModSub(const IntegerType &b) const{
	BigBinaryVector ans(*this);

	for(usint i=0;i<this->m_length;i++){
		ans.m_data[i] = ans.m_data[i].ModSub(b,this->m_modulus);
	}
	return ans;
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
template<class IntegerType>
BigBinaryVector<IntegerType> BigBinaryVector<IntegerType>::ModMul(const IntegerType &b) const{
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

	for(usint i=0;i<this->m_length;i++){

		ans.m_data[i] = ans.m_data[i].ModBarrettMul(b,this->m_modulus,mu);
	}

	return ans;
}

template<class IntegerType>
BigBinaryVector<IntegerType> BigBinaryVector<IntegerType>::ModExp(const IntegerType &b) const{
	BigBinaryVector ans(*this);
	for(usint i=0;i<this->m_length;i++){
		ans.m_data[i] = ans.m_data[i].ModExp(b,this->m_modulus);
	}
	return ans;
}

template<class IntegerType>
BigBinaryVector<IntegerType> BigBinaryVector<IntegerType>::ModInverse() const{

	BigBinaryVector ans(*this);
	//std::cout << ans << std::endl;
	for(usint i=0;i<this->m_length;i++){
		//std::cout << ans.m_data[i] << std::endl;
		//ans.m_data[i].PrintValueInDec();
		ans.m_data[i] = ans.m_data[i].ModInverse(this->m_modulus);
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
		ans.m_data[i] = ans.m_data[i].ModAdd(b.m_data[i],this->m_modulus);
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
		ans.m_data[i] = ans.m_data[i].ModSub(b.m_data[i],this->m_modulus);
	}
	return ans;

}

template<class IntegerType>
BigBinaryVector<IntegerType> BigBinaryVector<IntegerType>::ModByTwo() const {

	BigBinaryVector ans(this->GetLength(),this->GetModulus());
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
		this->m_data[i] = this->m_data[i].ModAdd(b.m_data[i],this->m_modulus);
	}
	return *this;

}

template<class IntegerType>
const BigBinaryVector<IntegerType>& BigBinaryVector<IntegerType>::operator-=(const BigBinaryVector &b) {

	if(this->m_length!=b.m_length){
		std::cout<<" Invalid argument \n";
		return (BigBinaryVector)NULL;
	}

	for(usint i=0;i<this->m_length;i++){
		this->m_data[i] = this->m_data[i].ModSub(b.m_data[i],this->m_modulus);
	}
	return *this;

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
		//ans.m_data[i] = ans.m_data[i].ModMul(b.m_data[i],this->m_modulus);
		ans.m_data[i] = ans.m_data[i].ModBarrettMul(b.m_data[i],this->m_modulus,mu);
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
			mid_ans = mid_ans + a.GetValAtIndex(i,j)* this->m_data[j];
		}
		ans.m_data[i] = mid_ans.Mod(m_modulus);
	}

	return ans;

}
*/

//Gets the ind
template<class IntegerType>
BigBinaryVector<IntegerType> BigBinaryVector<IntegerType>::GetDigitAtIndexForBase(usint index, usint base) const{
	BigBinaryVector ans(*this);
	for(usint i=0;i<this->m_length;i++){
		ans.m_data[i] = IntegerType(ans.m_data[i].GetDigitAtIndexForBase(index,base));
	}

	return ans;
}

// JSON FACILITY - Serialize Operation
template<class IntegerType>
bool BigBinaryVector<IntegerType>::Serialize(lbcrypto::Serialized* serObj, const std::string) const {

	if( !serObj->IsObject() )
		return false;

	lbcrypto::SerialItem bbvMap(rapidjson::kObjectType);

	bbvMap.AddMember("Modulus", this->GetModulus().ToString(), serObj->GetAllocator());

	usint pkVectorLength = GetLength();
	if( pkVectorLength > 0 ) {
		std::string pkBufferString = GetValAtIndex(0).Serialize();
		for (int i = 1; i < pkVectorLength; i++) {
			pkBufferString += "|";
			pkBufferString += GetValAtIndex(i).Serialize();
		}
		bbvMap.AddMember("VectorValues", pkBufferString, serObj->GetAllocator());
	}

	serObj->AddMember("BigBinaryVector", bbvMap, serObj->GetAllocator());

	return true;
}

// JSON FACILITY - Deserialize Operation
template<class IntegerType>
bool BigBinaryVector<IntegerType>::Deserialize(const lbcrypto::Serialized& serObj) {

	lbcrypto::Serialized::ConstMemberIterator mIter = serObj.FindMember("BigBinaryVector");
	if( mIter == serObj.MemberEnd() )
		return false;

	lbcrypto::SerialItem::ConstMemberIterator vIt;

	if( (vIt = mIter->value.FindMember("Modulus")) == mIter->value.MemberEnd() )
		return false;
	IntegerType bbiModulus(vIt->value.GetString());

	if( (vIt = mIter->value.FindMember("VectorValues")) == mIter->value.MemberEnd() )
		return false;

	this->SetModulus(bbiModulus);

	IntegerType vectorElem;
	usint ePos = 0;
	const char *vp = vIt->value.GetString();
	while( *vp != '\0' ) {
		vp = vectorElem.Deserialize(vp);
		this->SetValAtIndex(ePos++, vectorElem);

		if( *vp == '|' )
			vp++;
	}

	return true;
}

//Private functions
template<class IntegerType>
bool BigBinaryVector<IntegerType>::IndexCheck(usint length) const{
	if(length>this->m_length)
		return false;
	return true;
}

} // namespace lbcrypto ends
