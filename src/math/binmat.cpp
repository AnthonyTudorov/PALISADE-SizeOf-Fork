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

#include "binmat.h"

namespace lbcrypto {

BigBinaryMatrix::BigBinaryMatrix(){
	this->m_columns = 1;
	this->m_rows = 1;
	this->m_modulus.SetValue("0");
	this->m_data = new BigBinaryInteger**[m_rows];
	for(usint i=0;i<m_rows;i++)
		m_data[i] = new BigBinaryInteger*[m_columns];
	for(usint i=0;i<m_rows;i++)
		for(usint j=0;j<m_columns;j++)
			m_data[i][j] = new BigBinaryInteger();
}

BigBinaryMatrix::BigBinaryMatrix(usint dimension1,usint dimension2){
	this->m_columns = dimension2;
	this->m_rows = dimension1;
	this->m_modulus.SetValue("0");
	this->m_data = new BigBinaryInteger**[m_rows];
	for(usint i=0;i<m_rows;i++)
		m_data[i] = new BigBinaryInteger*[m_columns];
	for(usint i=0;i<m_rows;i++)
		for(usint j=0;j<m_columns;j++)
			m_data[i][j] = new BigBinaryInteger();
}

BigBinaryMatrix::BigBinaryMatrix(const BigBinaryMatrix& binaryMatrix){
	this->m_columns = binaryMatrix.m_columns;
	this->m_rows = binaryMatrix.m_rows;
	this->m_modulus = binaryMatrix.m_modulus;
	this->m_data = new BigBinaryInteger**[m_rows];
	for(usint i=0;i<m_rows;i++)
		m_data[i] = new BigBinaryInteger*[m_columns];
	for(usint i=0;i<m_rows;i++)
		for(usint j=0;j<m_columns;j++)
			*m_data[i][j] = *binaryMatrix.m_data[i][j];
}

BigBinaryMatrix&  BigBinaryMatrix::operator=(const BigBinaryMatrix& rhs){
	if(this!=&rhs){
		if(this->IndexCheck(rhs.GetRowSize(),rhs.GetColumnSize())){
			this->m_modulus = rhs.GetModulus();
			for(usint i=0;i<this->m_rows;i++)
				for(usint j=0;i<this->m_columns;j++)
					*this->m_data[i][j] = *rhs.m_data[i][j];
			return *this;
		}
		else{
			std::cout<<"Assisnment operator error, Invalid parameters \n";
		}
	
	}

	return *this;
}

BigBinaryMatrix::~BigBinaryMatrix(){
	for(usint i=0;i<m_rows;i++){
		for(usint j=0;j<m_columns;j++){
			delete m_data[i][j]; 
		}
	}

	delete [] m_data;
}

//ACCESORS
std::ostream& operator<<(std::ostream& os, const BigBinaryMatrix &ptr_obj){
	os<<std::endl;
	for(usint i=0;i<ptr_obj.m_rows;i++){
		for(usint j=0;j<ptr_obj.m_columns;j++)
			os<<*ptr_obj.m_data[i][j]<<"  ";
				os<<std::endl;
	}
	return os;
}

void BigBinaryMatrix::SetValAtIndex(usint rowindex, usint columnindex, const BigBinaryInteger& value){
	if(!this->IndexCheck(rowindex,columnindex)){
		std::cout<<"Invalid inputs "<<std::endl;
	}
	else{
		*this->m_data[rowindex][columnindex] = value;
	}
	
}

void BigBinaryMatrix::SetValAtIndex(usint rowindex, usint columnindex, const std::string& str){
	if(!this->IndexCheck(rowindex,columnindex)){
		std::cout<<"Invalid inputs "<<std::endl;
	}
	else{
		BigBinaryInteger *copy = new BigBinaryInteger(str);
		*this->m_data[rowindex][columnindex] = *copy;
		delete copy;
	}

}

void BigBinaryMatrix::SetModulus(const BigBinaryInteger& value){
	this->m_modulus = value;
}

void BigBinaryMatrix::SetModulus(std::string value) {
	this->m_modulus.SetValue(value);
}

BigBinaryInteger& BigBinaryMatrix::GetModulus() const{
	return *(new BigBinaryInteger(this->m_modulus));
}

usint BigBinaryMatrix::GetRowSize() const{
	return this->m_rows;
}

usint BigBinaryMatrix::GetColumnSize() const{
	return this->m_columns;
}

BigBinaryInteger& BigBinaryMatrix::GetValAtIndex(usint rowindex, usint columnindex) const{
	if(!this->IndexCheck(rowindex,columnindex)){
		throw std::logic_error("Index out of range");
	}

	else{
		return *this->m_data[rowindex][columnindex];
	}

}

//Public functions

BigBinaryMatrix& BigBinaryMatrix::KroneckerProduct(BigBinaryMatrix &rhs) const{
	
	BigBinaryMatrix *ans = new BigBinaryMatrix(this->m_rows*rhs.m_rows,this->m_columns*rhs.m_columns);
	usint rowidx = 0;
	usint columnidx = 0;

	for(usint u=0;u<this->m_rows;u++){
		for(usint v=0;v<rhs.m_rows;v++){
			for(usint i=0;i<this->m_columns;i++){
				for(usint j=0;j<rhs.m_columns;j++){
					rowidx = u*rhs.m_rows + v;
					columnidx = i*rhs.m_columns + j;
					*ans->m_data[rowidx][columnidx] = *this->m_data[u][i]**rhs.m_data[v][j];
				}
			}
		}
	}

	return *ans;

}

//Operators
BigBinaryMatrix& BigBinaryMatrix::operator+(BigBinaryMatrix &rhs) const{
	BigBinaryMatrix *ans=NULL; 
	if(this->IndexCheck(rhs.GetRowSize(),rhs.GetColumnSize())){
		ans = new BigBinaryMatrix();
		for(usint i=0;i<this->m_rows;i++)
			for(usint j=0;j<this->m_columns;j++)
				*ans->m_data[i][j] = *this->m_data[i][j]+rhs.GetValAtIndex(i,j); 
	}

	return *ans;
}

BigBinaryMatrix& BigBinaryMatrix::operator-(BigBinaryMatrix &rhs) const{

	BigBinaryMatrix *ans=NULL; 
	if(this->IndexCheck(rhs.GetRowSize(),rhs.GetColumnSize())){
		ans = new BigBinaryMatrix();
		for(usint i=0;i<this->m_rows;i++)
			for(usint j=0;j<this->m_columns;j++)
				*ans->m_data[i][j] = *this->m_data[i][j]-rhs.GetValAtIndex(i,j); 
	}

	return *ans;
}

BigBinaryMatrix& BigBinaryMatrix::ModAdd(BigBinaryMatrix &rhs) const{
	BigBinaryMatrix *ans=NULL; 
	if(this->IndexCheck(rhs.GetRowSize(),rhs.GetColumnSize())){
		ans = new BigBinaryMatrix();
		for(usint i=0;i<this->m_rows;i++)
			for(usint j=0;j<this->m_columns;j++)
				*ans->m_data[i][j] = this->m_data[i][j]->ModAdd(rhs.GetValAtIndex(i,j),this->m_modulus);
		return *ans; 
	}

	return *ans;
}

BigBinaryMatrix& BigBinaryMatrix::ModSub(BigBinaryMatrix &rhs) const{
	BigBinaryMatrix *ans=NULL; 
	if(this->IndexCheck(rhs.GetRowSize(),rhs.GetColumnSize())){
		ans = new BigBinaryMatrix();
		for(usint i=0;i<this->m_rows;i++)
			for(usint j=0;j<this->m_columns;j++)
				*ans->m_data[i][j] = this->m_data[i][j]->ModSub(rhs.GetValAtIndex(i,j),this->m_modulus);
		return *ans; 
	}

	return *ans;
}


//Private functions
bool BigBinaryMatrix::IndexCheck(usint rowindex,usint columnindex) const{
	if(rowindex > this->m_rows || columnindex > this->m_columns )
		return false;
	return true;
}

}  // namespace lbcrypto ends
