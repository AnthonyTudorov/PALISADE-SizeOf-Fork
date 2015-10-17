// LAYER 2 : LATTICE DATA STRUCTURES AND OPERATIONS
/*
PRE SCHEME PROJECT, Crypto Lab, NJIT
Version: 
	v00.01 
Last Edited: 
	6/1/2015 5:37AM
List of Authors:
	TPOC: 
		Dr. Kurt Rohloff, rohloff@njit.edu
	Programmers:
		Dr. Yuriy Polyakov, polyakov@njit.edu
		Gyana Sahu, grs22@njit.edu
Description:	
	This code provides basic lattice ideal manipulation functionality.

License Information:

Copyright (c) 2015, New Jersey Institute of Technology (NJIT)
All rights reserved.
Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:
1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

*/

#include "il2n.h"
#include <fstream>

namespace lbcrypto {

	//need to be added because m_dggSamples is static and not initialized
	std::vector<ILVector2n> ILVector2n::m_dggSamples;
	
	ILVector2n::ILVector2n():m_values(NULL),m_format(EVALUATION){
	
	}

	ILVector2n::ILVector2n(const ILParams &params):m_params(params),m_values(NULL),m_format(EVALUATION){
	
	}

	ILVector2n::ILVector2n(const ILVector2n &element):m_params(element.m_params),m_format(element.m_format),
		m_values(new BigBinaryVector(*element.m_values)){
	
	}

	ILVector2n::ILVector2n(ILVector2n &&element):m_params(element.m_params),m_format(element.m_format),
		m_values(element.m_values){
			element.m_values = NULL;
	}

	ILVector2n& ILVector2n::operator=(const ILVector2n &rhs){
		
		if(this!=&rhs){
			if (m_values==NULL)
				m_values = new BigBinaryVector(*rhs.m_values);
			else {
				*this->m_values = *rhs.m_values;
			}
			this->m_params = rhs.m_params;
		    this->m_format = rhs.m_format;
		}
		
		return *this;
	}

	ILVector2n& ILVector2n::operator=(ILVector2n &&rhs){

		if(this!=&rhs){
			delete m_values;
			m_values = rhs.m_values;
			rhs.m_values = NULL;
			m_params = rhs.m_params;
			m_format = rhs.m_format;
		}

		return *this;
	}

	ILVector2n::ILVector2n (DiscreteGaussianGenerator &dgg,const ILParams &params,Format format):m_params(params){
		/*
		//usint vectorSize = EulerPhi(params.GetOrder());
		usint vectorSize = params.GetOrder()/2;
		m_values = new BigBinaryVector(dgg.GenerateVector(vectorSize));
		(*m_values).SetModulus(params.GetModulus());
		m_format = COEFFICIENT;
		//std::cout<<"before switchformat: "<<GetFormat()<<std::endl;
		if (format == EVALUATION)
			SwitchFormat();
		*/
		
		if (format == COEFFICIENT)
		{
			//usint vectorSize = EulerPhi(params.GetOrder());
			usint vectorSize = params.GetOrder()/2;
			m_values = new BigBinaryVector(dgg.GenerateVector(vectorSize));
			(*m_values).SetModulus(params.GetModulus());
			m_format = COEFFICIENT;
		}
		else
		{
			if (m_dggSamples.size() == 0)
			{
				PreComputeDggSamples(dgg,params);
			}
			ILVector2n randomElement = GetPrecomputedVector(params);
			m_values = new BigBinaryVector(*randomElement.m_values);
			(*m_values).SetModulus(params.GetModulus());
			m_format = EVALUATION;
		}
	}

	ILVector2n::~ILVector2n()
	{
		/*if(m_values!=NULL)
			m_values->~BigBinaryVector();*/
		delete m_values;
	}

	const BigBinaryInteger &ILVector2n::GetModulus() const{
		return m_params.GetModulus();
	}

	const BigBinaryVector &ILVector2n::GetValues() const {
		return *m_values;
	}

	const BigBinaryInteger &ILVector2n::GetRootOfUnity() {
		return m_params.GetRootOfUnity();
	}

	Format ILVector2n::GetFormat(){
		return m_format;
	}

	const ILParams &ILVector2n::GetParams() {
		return m_params;
	}

	usint ILVector2n::GetLength() {
		return m_values->GetLength();
	}

	void ILVector2n::SetValues(const BigBinaryVector& values, Format format){
		if(m_values!=NULL){
			delete m_values;
		}
		m_values = new BigBinaryVector(values);
		m_format = format;
	}

	 // addition operation - PREV1
	ILVector2n ILVector2n::Plus(const BigBinaryInteger &element) const{
		ILVector2n tmp(*this);
		*tmp.m_values = m_values->ModAdd(element);
		return tmp;
	}

	
	// multiplication operation - PREV1
	ILVector2n ILVector2n::Times(const BigBinaryInteger &element) const{
		ILVector2n tmp(*this);
		*tmp.m_values = m_values->ModMul(element);
		return tmp;
	}

	// modulo operation - PREV1
	ILVector2n ILVector2n::Mod(const BigBinaryInteger & modulus) const{
		ILVector2n tmp(*this);
		*tmp.m_values = m_values->Mod(modulus);
		return tmp;
	}

	BigBinaryVector ILVector2n::ModByTwo() const{
		
		BigBinaryVector ans(this->m_values->GetLength());
		BigBinaryInteger halfQ(m_params.GetModulus()>>1);
		for(usint i=0;i<ans.GetLength();i++){
			if(m_values->GetValAtIndex(i)>halfQ){
				if(m_values->GetValAtIndex(i).Mod(BigBinaryInteger::TWO)==BigBinaryInteger::ONE)
					ans.SetValAtIndex(i,BigBinaryInteger::ZERO);
				else
					ans.SetValAtIndex(i,BigBinaryInteger::ONE);
			}
			else{
				if(m_values->GetValAtIndex(i).Mod(BigBinaryInteger::TWO)==BigBinaryInteger::ONE)
					ans.SetValAtIndex(i,BigBinaryInteger::ONE);
				else
					ans.SetValAtIndex(i,BigBinaryInteger::ZERO);
			}

		}
		return ans;
	}

	// VECTOR OPERATIONS
	
	// addition operation - PREV1
	ILVector2n ILVector2n::Plus(const ILVector2n &element) const{
		ILVector2n tmp(*this);
		*tmp.m_values = m_values->ModAdd(*element.m_values);
		return tmp;
	}

	const ILVector2n& ILVector2n::operator+=(const ILVector2n &element) {
		*this->m_values = this->m_values->ModAdd(*element.m_values);
		return *this;
	}

	// multiplication operation - PREV1
	ILVector2n ILVector2n::Times(const ILVector2n &element) const{
		ILVector2n tmp(*this);
		*tmp.m_values = m_values->ModMul(*element.m_values);
		return tmp;
	}

	// multiplicative inverse operation
	ILVector2n ILVector2n::MultiplicativeInverse() const{
		ILVector2n tmp(*this);
		*tmp.m_values = m_values->ModInverse();
		return tmp;
	}

	// OTHER METHODS

	// convert from Coefficient to CRT or vice versa; calls FFT and inverse FFT
	void ILVector2n::SwitchFormat(){

		if(m_format == COEFFICIENT){

			m_format = EVALUATION;
			//std::cout << "starting CRT" << std::endl;
			/*std::cout << *m_values << std::endl;
			std::cout << m_params.GetRootOfUnity() << std::endl;
			std::cout << m_params.GetOrder() << std::endl;*/

			*m_values = ChineseRemainderTransformFTT::GetInstance().ForwardTransform(*m_values,m_params.GetRootOfUnity(),m_params.GetOrder());

		}

		else {
			m_format  = COEFFICIENT;
			*m_values = ChineseRemainderTransformFTT::GetInstance().InverseTransform(*m_values,m_params.GetRootOfUnity(),m_params.GetOrder());
		}

	}

	// get digit for a specific based - used for PRE scheme
	ILVector2n ILVector2n::GetDigitAtIndexForBase(usint index, usint base) const{
		ILVector2n tmp(*this);
		*tmp.m_values = m_values->GetDigitAtIndexForBase(index,base);
		return tmp;
	}


	//Represent the lattice in binary format
	void ILVector2n::DecodeElement(ByteArrayPlaintextEncoding *text, const BigBinaryInteger &modulus) const{

		ByteArray byteArray;
		usint mod = modulus.ConvertToInt();
		usint p  = ceil((float)log((double)255)/log((double)mod));
		usint resultant_char;

		for(usint i=0;i<m_values->GetLength();i=i+p){
			usint exp = 1;
			resultant_char = 0;
			for(usint j=0;j<p;j++){
				resultant_char += m_values->GetValAtIndex(i+j).ConvertToInt()*exp ;
				exp *= mod;
			}
			byteArray+=((char)resultant_char);
		}
		*text = ByteArrayPlaintextEncoding(byteArray);

	}
		
	//Convert binary string to lattice format; do p=2 first but document that we need to generalize it later
	void ILVector2n::EncodeElement(const ByteArrayPlaintextEncoding &encodedPlaintext, const BigBinaryInteger &modulus){
	
		ByteArray encoded = encodedPlaintext.GetData();
		
		if(m_values!=NULL){
			delete m_values;
		}

		usint mod = modulus.ConvertToInt();
		usint p  = ceil((float)log((double)255)/log((double)mod));

		m_values = new BigBinaryVector(p*encoded.length());
		(*m_values).SetModulus(m_params.GetModulus());
		m_format = COEFFICIENT;
		
		for(usint i=0;i<encoded.length();i++){	
			usint Num = encoded.at(i);
			usint exp = mod,Rem=0;
			for(usint j=0;j<p;j++){
				Rem = Num%exp;
				m_values->SetValAtIndex(i*p+j,UintToBigBinaryInteger((Rem/(exp/mod))));
				Num -= Rem;
				exp*=mod;
			}
		}

	}
	
	//Precompute a sample of disrete gaussian polynomials
	void ILVector2n::PreComputeDggSamples(DiscreteGaussianGenerator &dgg,const ILParams &params) {

		for(usint i = 0; i < m_sampleSize; ++i)
		{
			ILVector2n current(params);
			usint vectorSize = params.GetOrder()/2;
			current.m_values = new BigBinaryVector(dgg.GenerateVector(vectorSize));
			(*current.m_values).SetModulus(params.GetModulus());
			current.m_format = COEFFICIENT;

			auto start = std::chrono::steady_clock::now();

			current.SwitchFormat();

			if ((i>5)&&(i < 9)) {
				auto end = std::chrono::steady_clock::now();
				auto diff = end - start;
				std::cout << "NTT time: " << std::chrono::duration <double,std::milli> (diff).count() << " ms" << std::endl;
			}

			m_dggSamples.push_back(current);
		}

	}

	//Select a precomputed vector randomly
	const ILVector2n ILVector2n::GetPrecomputedVector(const ILParams &params) {
	
		//std::default_random_engine generator;
		//std::uniform_real_distribution<int> distribution(0,SAMPLE_SIZE-1);
		//int randomIndex = distribution(generator);
		int randomIndex = rand() % SAMPLE_SIZE;
		//std::cout << "random index: " << randomIndex << std::endl;
		//std::cout << "random vector: " << m_dggSamples[randomIndex].GetValues() << std::endl;
		return m_dggSamples[randomIndex];

	}

} // namespace lbcrypto ends
