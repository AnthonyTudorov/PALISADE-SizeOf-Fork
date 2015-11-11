//LAYER 1 : PRIMITIVE DATA STRUCTURES AND OPERATIONS
/*
PRE SCHEME PROJECT, Crypto Lab, NJIT
Version: 
	v00.04 
Last Edited: 
	10/27/2015 5:37AM
List of Authors:
	TPOC: 
		Dr. Kurt Rohloff, rohloff@njit.edu
	Programmers:
		Dr. Yuriy Polyakov, polyakov@njit.edu
		Gyana Sahu, grs22@njit.edu
		Nishanth Pasham, np386@njit.edu
Description:	
	This code provides basic noise generation functionality.

License Information:

Copyright (c) 2015, New Jersey Institute of Technology (NJIT)
All rights reserved.
Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:
1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

*/

#include <random>
#include "distrgen.h"
#include "nbtheory.h"
#include "time.h"

namespace lbcrypto {

DiscreteGaussianGenerator::DiscreteGaussianGenerator(){
	
	m_std = 1;
	m_modulus = BigBinaryInteger("1");

}

DiscreteGaussianGenerator::DiscreteGaussianGenerator(sint std,BigBinaryInteger &mod){
	
	m_std = std;
	m_modulus = mod;
	InitiateVals();
	std::random_device rd;
	std::srand(rd());
	//srand (time(NULL));
	/*
	for(usint i=0;i<m_vals.size();i++)
		std::cout<<m_vals[i]<<std::endl;

	std::cout<<std::endl;
	*/
	

}

DiscreteGaussianGenerator::~DiscreteGaussianGenerator(){
	//std::cout<<"Discrete Guassian destructor called \n\n";
}

// BigBinaryInteger DiscreteGaussianGenerator::GetModulus(){
// 	return m_modulus;
// }

void DiscreteGaussianGenerator::SetModulus(BigBinaryInteger &modulus){
	
	m_modulus = modulus;

}

void DiscreteGaussianGenerator::InitiateVals(){

		const double pi = 3.1415926;
		//weightDiscreteGaussian
		double acc = 0.00000001;
	
		int fin = ceil(sqrt(2*pi)*m_std*sqrt(-1*log(acc)/pi));

		double cusum = 1.0; 
    
		for(sint x=1;x<=fin;x++){
               
			cusum = cusum + 2* exp(-pi*(x*x)/(m_std*m_std*2*pi));

		}
    
		m_a = 1/cusum;

		fin = ceil(sqrt(-2*(m_std*m_std)*log(acc)));  
		double temp;

		for(sint i=1;i<=fin;i++){
			temp = m_a*exp((double)-((double)(i*i)/(2*m_std*m_std)));
			m_vals.push_back(temp);
		}
		
		/*
		for(usint i=0;i<m_vals.size();i++){
			std::cout<<m_vals[i]<<std::endl;
		}
		std::cout<<std::endl<<std::endl;
		*/
		
		//take cumulative summation
		for(usint i=1;i<m_vals.size();i++){
			m_vals[i] += m_vals[i-1]; 
		}

		//std::cout<<m_a<<std::endl;

		/*
		for(usint i=0;i<m_vals.size();i++){
			std::cout<<m_vals[i]<<std::endl;
		}
		std::cout<<std::endl<<std::endl;
		*/
}

schar* DiscreteGaussianGenerator::GenerateCharVector(usint size) const{

	//std::default_random_engine generator;
	//std::uniform_real_distribution<double> distribution(0.0,1.0);
	//generator.seed(time(NULL));
	double val =0,seed;
	schar *ans = new schar[size];
	for(usint i=0;i<size;i++){
		//generator.seed(time(NULL));
		seed = ((double) std::rand() / (RAND_MAX)) - 0.5;
		//std::cout<<seed<<std::endl;
		//seed = distribution(generator)-0.5;
        if(std::abs(seed) <= m_a/2)
			val = 0;
        else if(seed>0)
			val = FindInVector(m_vals,(std::abs(seed)-m_a/2));
        else
            val = -(int)FindInVector(m_vals,(std::abs(seed)-m_a/2));
        
        ans[i] = val;
	}

	return ans;
}

usint DiscreteGaussianGenerator::FindInVector(const std::vector<double> &S,double search)const{
	for(int i=0;i<S.size();i++){
		if(S[i]>=search){
			return i;
		}
	}

}

BigBinaryVector DiscreteGaussianGenerator::DiscreteGaussianPositiveGenerator(usint vectorLength,const BigBinaryInteger &modValue){

       BigBinaryVector ans(vectorLength);
       ans.SetModulus(modValue);

          
       for(usint i=0;i<vectorLength;i++){
		   ans.SetValAtIndex(i,UintToBigBinaryInteger(std::rand()%8));
       }

       return ans;
}

BigBinaryInteger DiscreteGaussianGenerator::GenerateInteger() const{

	return std::move(*(new BigBinaryInteger()));
}

BigBinaryVector DiscreteGaussianGenerator::GenerateVector(usint size) const{

	
	//BigBinaryVector ans(DiscreteGaussianGenerator::DiscreteGaussianPositiveGenerator(size,this->m_modulus));

	//return ans;
	
	
	schar* result_vector = GenerateCharVector(size);

	BigBinaryVector ans(size);
	ans.SetModulus(m_modulus);

	for(usint i=0;i<size;i++){
		if( result_vector[i]<0 ){
			result_vector[i] *= -1;
			ans.SetValAtIndex(i,UintToBigBinaryInteger(result_vector[i]));
			ans.SetValAtIndex(i, m_modulus-ans.GetValAtIndex(i) );
		}
		else{
			ans.SetValAtIndex(i,UintToBigBinaryInteger(result_vector[i]));
		}
	}

	delete []result_vector;

	return ans;


}

DiscreteUniformGenerator::DiscreteUniformGenerator(){
	m_modulus = BigBinaryInteger("2");
	InitializeVals();
}

DiscreteUniformGenerator::DiscreteUniformGenerator(BigBinaryInteger &mod){
	m_modulus = mod;
	InitializeVals();
}

DiscreteUniformGenerator::~DiscreteUniformGenerator(){
	//Destructor of DiscreteUniformGenerator is called
}

const BigBinaryInteger& DiscreteUniformGenerator::GetModulus() const{
	return m_modulus;
}

void DiscreteUniformGenerator::SetModulus(BigBinaryInteger &mod){
	m_modulus = mod;
}

void DiscreteUniformGenerator::InitializeVals(){
	moduloLength = m_modulus.GetMSB();
	noOfIter = ((moduloLength % LENOFMAX) == 0) ? (moduloLength/LENOFMAX) : (moduloLength/LENOFMAX) + 1;
	remainder = moduloLength % LENOFMAX;
	// std::cout << "moduloLength = " << moduloLength << std::endl;
	// std::cout << "noOfIter = " << noOfIter << std::endl;
	// std::cout << "remainder = " << remainder << std::endl;
	// std::cout << "MAXVAL = " << MAXVAL << std::endl;
}

BigBinaryInteger DiscreteUniformGenerator::GenerateInteger() const{
	usint randNum;
	std::string temp;
	std::string bigBinaryInteger = "";
	std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(DiscreteUniformGenerator::MINVAL, DiscreteUniformGenerator::MAXVAL);
	for(usint i=0; i< noOfIter; ++i) {
		randNum = dis(gen);
		if(remainder != 0 && i == noOfIter-1) {
			temp = std::bitset<DiscreteUniformGenerator::LENOFMAX>(randNum).to_string();
			bigBinaryInteger += temp.substr(LENOFMAX-remainder, LENOFMAX);
		} else {
			bigBinaryInteger += std::bitset<DiscreteUniformGenerator::LENOFMAX>(randNum).to_string();
		}
	}
	BigBinaryInteger randBigBinaryInteger(BigBinaryInteger::BinaryToBigBinaryInt(bigBinaryInteger));
	if(randBigBinaryInteger < m_modulus)
		return randBigBinaryInteger;
	else
		return DiscreteUniformGenerator::GenerateInteger();
}

BigBinaryVector DiscreteUniformGenerator::GenerateVector(usint size) const{
	BigBinaryVector randBigBinaryVector(size);
	for(usint index = 0; index<size; ++index) {
		BigBinaryInteger temp(this->GenerateInteger());
		randBigBinaryVector.SetValAtIndex(index, temp);
	}
	return randBigBinaryVector;
}

BinaryUniformGenerator::BinaryUniformGenerator(){
}

BigBinaryInteger BinaryUniformGenerator::GenerateInteger() const{
	std::random_device rd;
	std::mt19937 gen(rd());
    std::bernoulli_distribution distribution(0.5);
	return (distribution(gen) ? BigBinaryInteger(BigBinaryInteger::ONE) : BigBinaryInteger(BigBinaryInteger::ZERO)); 
}

BigBinaryVector BinaryUniformGenerator::GenerateVector(usint size) const{
	BigBinaryVector randBigBinaryVector(size);
	for(usint index = 0; index<size; ++index) {
		BigBinaryInteger temp(this->GenerateInteger());
		randBigBinaryVector.SetValAtIndex(index, temp);
	}
	return randBigBinaryVector;
}

} // namespace lbcrypto ends
