/*
PRE SCHEME PROJECT, Crypto Lab, NJIT
Version: 
	v00.01 
Last Edited: 
	6/14/2015 5:37AM
List of Authors:
	TPOC: 
		Dr. Kurt Rohloff, rohloff@njit.edu
	Programmers:
		Dr. Yuriy Polyakov, polyakov@njit.edu
		Gyana Sahu, grs22@njit.edu
Description:	

Description:	
	This file contains the linear transform interface functionality.

License Information:

Copyright (c) 2015, New Jersey Institute of Technology (NJIT)
All rights reserved.
Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:
1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

*/

#include "transfrm.h"

namespace lbcrypto {

//static Initializations
NumberTheoreticTransform* NumberTheoreticTransform::m_onlyInstance = 0;
ChineseRemainderTransform* ChineseRemainderTransform::m_onlyInstance = 0;
BigBinaryVector* ChineseRemainderTransform::m_rootOfUnityInverseTable = 0;
BigBinaryVector* ChineseRemainderTransform::m_rootOfUnityTable = 0;
ChineseRemainderTransformFTT* ChineseRemainderTransformFTT::m_onlyInstance = 0;
//BigBinaryVector* ChineseRemainderTransformFTT::m_rootOfUnityInverseTable = 0;
//BigBinaryVector* ChineseRemainderTransformFTT::m_rootOfUnityTable = 0;
//BigBinaryVector* ChineseRemainderTransformFTT::m_phiInverseTable = 0;
//BigBinaryVector* ChineseRemainderTransformFTT::m_phiTable = 0;

std::map<std::string,BigBinaryVector> ChineseRemainderTransformFTT::m_rootOfUnityTableByModulus = std::map<std::string,BigBinaryVector>();
std::map<std::string,BigBinaryVector> ChineseRemainderTransformFTT::m_rootOfUnityInverseTableByModulus = std::map<std::string,BigBinaryVector>();


NumberTheoreticTransform& NumberTheoreticTransform::GetInstance(){
	if(m_onlyInstance==NULL){
		m_onlyInstance = new NumberTheoreticTransform();//lazy instantiation
	}
	return *m_onlyInstance;
}

//Number Theoretic Transform - ITERATIVE IMPLEMENTATION -  twiddle factor table precomputed
BigBinaryVector NumberTheoreticTransform::ForwardTransformIterative(const BigBinaryVector& element, const BigBinaryVector &rootOfUnityTable,const usint cycloOrder) {
	
	
	usint n = cycloOrder;
	BigBinaryVector result(n);
	result.SetModulus( element.GetModulus() );

	//reverse coefficients (bit reversal)
	usint msb = GetMSB32(n-1);
	for(usint i=0;i<n;i++)
		result.SetValAtIndex( i, element.GetValAtIndex(ReverseBits(i,msb)));
		
	BigBinaryInteger omegaFactor;
	BigBinaryInteger product;
	BigBinaryInteger butterflyPlus;
	BigBinaryInteger butterflyMinus;

	//Precompute the Barrett mu values
	/*BigBinaryInteger temp;
	uschar gamma;
	uschar modulusLength = element.GetModulus().GetMSB() ;
	BigBinaryInteger mu_arr[BARRETT_LEVELS+1];
	for(usint i=0;i<BARRETT_LEVELS+1;i++) {
		temp = BigBinaryInteger::ONE;
		gamma = modulusLength*i/BARRETT_LEVELS;
		temp<<=modulusLength+gamma+3;
		mu_arr[i] = temp.DividedBy(element.GetModulus());
	}*/

	//Precompute the Barrett mu parameter
	BigBinaryInteger temp(BigBinaryInteger::ONE);
	temp<<=2*element.GetModulus().GetMSB()+3;
	BigBinaryInteger mu = temp.DividedBy(element.GetModulus());

	
	for(usint m=2;m<=n;m=2*m)
	{
		
		for(usint j=0;j<n;j=j+m)
		{
			for(usint i=0;i<=m/2-1;i++)
			{

				usint x = 2*i*n/m;

				const BigBinaryInteger& omega = rootOfUnityTable.GetValAtIndex(x);

				//std::cout<<omega<<std::endl;

				usint indexEven = j + i;
				usint indexOdd = j + i + m/2;

				if (result.GetValAtIndex(indexOdd).GetMSB()>0)
				{

					if (result.GetValAtIndex(indexOdd).GetMSB()==1)
						omegaFactor = omega;
					else
					{
						product = omega*result.GetValAtIndex(indexOdd);
						//omegaFactor = product.ModBarrett(element.GetModulus(),mu_arr);
						omegaFactor = product.ModBarrett(element.GetModulus(),mu);
					}

					butterflyPlus = result.GetValAtIndex(indexEven); 
					butterflyPlus += omegaFactor;
					if (butterflyPlus >= element.GetModulus())
						butterflyPlus -= element.GetModulus();

					butterflyMinus = result.GetValAtIndex(indexEven);
					if (result.GetValAtIndex(indexEven) < omegaFactor)
						butterflyMinus += element.GetModulus();
					butterflyMinus -= omegaFactor;

					result.SetValAtIndex( indexEven, butterflyPlus );
					result.SetValAtIndex( indexOdd, butterflyMinus);

				}
				else
					result.SetValAtIndex( indexOdd, result.GetValAtIndex(indexEven));

			}
		}
	}
	
	return result;

}

//Number Theoretic Transform - ITERATIVE IMPLEMENTATION -  twiddle factor table precomputed
BigBinaryVector NumberTheoreticTransform::InverseTransformIterative(const BigBinaryVector& element,const BigBinaryVector& rootOfUnityInverseTable,const usint cycloOrder){

	BigBinaryVector ans = NumberTheoreticTransform::GetInstance().ForwardTransformIterative(element,rootOfUnityInverseTable,cycloOrder);

	ans.SetModulus(element.GetModulus());

	ans = ans.ModMul(UintToBigBinaryInteger(cycloOrder).ModInverse(element.GetModulus()));

	return ans;
}

void NumberTheoreticTransform::SetElement(const BigBinaryVector &element){
	m_element = &element;
}

void NumberTheoreticTransform::Destroy(){

	//delete m_onlyInstance;
	m_element = NULL;
}


ChineseRemainderTransform& ChineseRemainderTransform::GetInstance(){
	if(m_onlyInstance==NULL){
		m_onlyInstance = new ChineseRemainderTransform();
	}

	return *m_onlyInstance;
}

ChineseRemainderTransformFTT& ChineseRemainderTransformFTT::GetInstance(){
	if(m_onlyInstance==NULL){
		m_onlyInstance = new ChineseRemainderTransformFTT();
	}

	return *m_onlyInstance;
}


//main CRT Transform - uses iterative FFT as a subroutine
//includes precomputation of twidle factor table
BigBinaryVector ChineseRemainderTransform::ForwardTransform(const BigBinaryVector& element, const BigBinaryInteger& rootOfUnity,const usint CycloOrder){
	
	if(m_rootOfUnityTable==NULL){
		m_rootOfUnityTable = new BigBinaryVector( CycloOrder+1);  //We may be able to change length to CycloOrder/2
		BigBinaryInteger x(BigBinaryInteger::ONE);
		for(usint i=0;i<CycloOrder/2;i++){
			m_rootOfUnityTable->SetValAtIndex(i,x);
			m_rootOfUnityTable->SetValAtIndex(i+CycloOrder/2, element.GetModulus()-x);
			x = x.ModMul(rootOfUnity,element.GetModulus());
		}

		m_rootOfUnityTable->SetValAtIndex(CycloOrder, BigBinaryInteger::ONE);

	}

	if( !IsPowerOfTwo(CycloOrder) ){
		std::cout<<"Error in the FFT operation\n\n";
		exit(-10);
	}

	BigBinaryVector OpFFT;
	BigBinaryVector InputToFFT = ZeroPadForward(element,CycloOrder);

	if( !IsPowerOfTwo( element.GetLength() ) ){
		std::cout<<"Input to FFT is not a power of two\n ERROR BEFORE FFT\n";
		OpFFT = NumberTheoreticTransform::GetInstance().ForwardTransformIterative(InputToFFT,*m_rootOfUnityTable,CycloOrder);
	}
	else{
		
		//auto start = std::chrono::steady_clock::now();

		OpFFT = NumberTheoreticTransform::GetInstance().ForwardTransformIterative(InputToFFT,*m_rootOfUnityTable,CycloOrder);
		
		/*auto end = std::chrono::steady_clock::now();

		auto diff = end - start;

		std::cout << std::chrono::duration <double, std::milli> (diff).count() << " ms" << std::endl;
		system("pause");*/
	}

	BigBinaryVector ans(CycloOrder/2);

	for(usint i=0;i<CycloOrder/2;i++)
		ans.SetValAtIndex(i,OpFFT.GetValAtIndex(2*i+1));

	ans.SetModulus(OpFFT.GetModulus());

	return ans;
}

//main CRT Transform - uses iterative FFT as a subroutine
//includes precomputation of inverse twidle factor table
BigBinaryVector ChineseRemainderTransform::InverseTransform(const BigBinaryVector& element, const BigBinaryInteger& rootOfUnity,const usint CycloOrder){

	BigBinaryInteger rootOfUnityInverse = rootOfUnity.ModInverse(element.GetModulus());

	if( !IsPowerOfTwo(CycloOrder) ){
		std::cout<<"Error in the FFT operation\n\n";
		exit(-10);
	}
	if(m_rootOfUnityInverseTable==NULL){
		m_rootOfUnityInverseTable = new BigBinaryVector( CycloOrder+1);
		BigBinaryInteger x(BigBinaryInteger::ONE);
		for(usint i=0;i<CycloOrder/2;i++){
			m_rootOfUnityInverseTable->SetValAtIndex(i,x);
			m_rootOfUnityInverseTable->SetValAtIndex(i+CycloOrder/2, element.GetModulus()-x);
			x = x.ModMul(rootOfUnityInverse,element.GetModulus());
		}

		m_rootOfUnityInverseTable->SetValAtIndex(CycloOrder, BigBinaryInteger::ONE);

	}

	BigBinaryVector OpIFFT;
	BigBinaryVector InputToFFT = ZeroPadInverse(element,CycloOrder);

	if( !IsPowerOfTwo( element.GetLength() ) ){
		std::cout<<"Input to IFFT is not a power of two\n ERROR BEFORE FFT\n";
		OpIFFT = NumberTheoreticTransform::GetInstance().InverseTransformIterative(InputToFFT,*m_rootOfUnityInverseTable,CycloOrder);
	}
	else{
		OpIFFT = NumberTheoreticTransform::GetInstance().InverseTransformIterative(InputToFFT,*m_rootOfUnityInverseTable,CycloOrder);
	}

	BigBinaryVector ans(CycloOrder/2);

	for(usint i=0;i<CycloOrder/2;i++)
		ans.SetValAtIndex(i,(OpIFFT).GetValAtIndex(i).ModMul(BigBinaryInteger::TWO,(OpIFFT).GetModulus()));

	ans.SetModulus(OpIFFT.GetModulus());

	return ans;
}

//main Forward CRT Transform - implements FTT - uses iterative NTT as a subroutine
//includes precomputation of twidle factor table
BigBinaryVector ChineseRemainderTransformFTT::ForwardTransform(const BigBinaryVector& element, const BigBinaryInteger& rootOfUnity,const usint CycloOrder){
	
	if( !IsPowerOfTwo(CycloOrder) ){
		std::cout<<"Error in the FFT operation\n\n";
		exit(-10);
	}

	//Pre-compute mu for Barrett function
	BigBinaryInteger temp(BigBinaryInteger::ONE);
	temp<<=2*element.GetModulus().GetMSB()+3;
	BigBinaryInteger mu = temp.DividedBy(element.GetModulus());

	/*
	//Precomputes twiddle factor omega and FTT parameter phi
	if(m_rootOfUnityTable==NULL){
		m_rootOfUnityTable = new BigBinaryVector(CycloOrder/2);
		m_phiTable = new BigBinaryVector(CycloOrder/2);
		BigBinaryInteger x(BigBinaryInteger::ONE);
		BigBinaryInteger rootOfUnitySquare(rootOfUnity.ModBarrettMul(rootOfUnity,element.GetModulus(),mu));
		BigBinaryInteger phi(BigBinaryInteger::ONE);
		for(usint i=0;i<CycloOrder/2;i++){
			m_rootOfUnityTable->SetValAtIndex(i,x);
			x = x.ModBarrettMul(rootOfUnitySquare,element.GetModulus(),mu);
			m_phiTable->SetValAtIndex(i,phi);
			phi = phi.ModBarrettMul(rootOfUnity,element.GetModulus(),mu);
		}
	}
	*/
	
	BigBinaryVector *rootOfUnityTable = NULL;
	
	rootOfUnityTable = &m_rootOfUnityTableByModulus[element.GetModulus().ToString()];

	if (rootOfUnityTable->GetLength() != 0){
		/*std::cout << rootOfUnity << std::endl;
		std::cout << rootOfUnityTable->GetValAtIndex(1) << std::endl;*/
		if (rootOfUnityTable->GetValAtIndex(1) != rootOfUnity){
			this->m_rootOfUnityTableByModulus.clear();
			rootOfUnityTable = &m_rootOfUnityTableByModulus[element.GetModulus().ToString()];
		}	
	}

	if(rootOfUnityTable->GetLength()==0 ){

		BigBinaryVector rTable(CycloOrder/2);
		BigBinaryInteger modulus(element.GetModulus());

		BigBinaryInteger x(BigBinaryInteger::ONE);

		for (usint i = 0; i<CycloOrder / 2; i++){
			rTable.SetValAtIndex(i, x);
			x = x.ModBarrettMul(rootOfUnity, modulus,mu);
		}

		this->m_rootOfUnityTableByModulus[modulus.ToString()] = std::move(rTable);

		rootOfUnityTable = &m_rootOfUnityTableByModulus[element.GetModulus().ToString()];				
	}

	

	BigBinaryVector OpFFT;
	BigBinaryVector InputToFFT(element);

	for(usint i=0;i<CycloOrder/2;i++)
		InputToFFT.SetValAtIndex(i,element.GetValAtIndex(i).ModBarrettMul(rootOfUnityTable->GetValAtIndex(i),element.GetModulus(),mu));

	OpFFT = NumberTheoreticTransform::GetInstance().ForwardTransformIterative(InputToFFT,this->m_rootOfUnityTableByModulus[element.GetModulus().ToString()],CycloOrder/2);
	

	return OpFFT;
}

//main Inverse CRT Transform - implements FTT - uses iterative NTT as a subroutine
//includes precomputation of inverse twidle factor table
BigBinaryVector ChineseRemainderTransformFTT::InverseTransform(const BigBinaryVector& element, const BigBinaryInteger& rootOfUnity,const usint CycloOrder){

	if( !IsPowerOfTwo(CycloOrder) ){
		std::cout<<"Error in the FFT operation\n\n";
		exit(-10);
	}

	//Pre-compute mu for Barrett function
	BigBinaryInteger temp(BigBinaryInteger::ONE);
	temp<<=2*element.GetModulus().GetMSB()+3;
	BigBinaryInteger mu = temp.DividedBy(element.GetModulus());

	BigBinaryVector *rootOfUnityITable = NULL;

	//std::cout<<m_rootOfUnityTableByModulus[element.GetModulus().ToString()];
	
	rootOfUnityITable = &m_rootOfUnityInverseTableByModulus[element.GetModulus().ToString()];

	if (rootOfUnityITable->GetLength() != 0){
		if (rootOfUnityITable->GetValAtIndex(1) != rootOfUnity.ModInverse(element.GetModulus())){
			this->m_rootOfUnityInverseTableByModulus.clear();
			rootOfUnityITable = &m_rootOfUnityInverseTableByModulus[element.GetModulus().ToString()];
		}
	}

	if(rootOfUnityITable->GetLength()==0){
		
		
		BigBinaryVector TableI(CycloOrder / 2);
		BigBinaryInteger rootOfUnityInverse = rootOfUnity.ModInverse(element.GetModulus());

		BigBinaryInteger x(BigBinaryInteger::ONE);

		for (usint i = 0; i<CycloOrder / 2; i++){
			TableI.SetValAtIndex(i, x);
			x = x.ModBarrettMul(rootOfUnityInverse, element.GetModulus(),mu);
		}

		//this->m_rootOfUnityInverseTableByModulus.insert(std::make_pair(modulus.ToString(),TableI));
		this->m_rootOfUnityInverseTableByModulus[element.GetModulus().ToString()] = std::move(TableI);
		
	}

	

	BigBinaryVector OpIFFT;
	OpIFFT = NumberTheoreticTransform::GetInstance().InverseTransformIterative(element,m_rootOfUnityInverseTableByModulus[element.GetModulus().ToString()],CycloOrder/2);

	BigBinaryVector rInvTable(this->m_rootOfUnityInverseTableByModulus[element.GetModulus().ToString()]);
	for(usint i=0;i<CycloOrder/2;i++)
		OpIFFT.SetValAtIndex(i,OpIFFT.GetValAtIndex(i).ModBarrettMul(rInvTable.GetValAtIndex(i),element.GetModulus(),mu));

	return OpIFFT;
}

void ChineseRemainderTransformFTT::PreCompute(const BigBinaryInteger& rootOfUnity, const usint CycloOrder, const BigBinaryInteger &modulus){

	//Pre-compute mu for Barrett function
	BigBinaryInteger temp(BigBinaryInteger::ONE);
	temp <<= 2 * modulus.GetMSB() + 3;
	BigBinaryInteger mu = temp.DividedBy(modulus);

	BigBinaryInteger x(BigBinaryInteger::ONE);
	
	
	BigBinaryVector *rootOfUnityTableCheck = NULL;
	rootOfUnityTableCheck =	&m_rootOfUnityTableByModulus[modulus.ToString()];
	//Precomputes twiddle factor omega and FTT parameter phi for Forward Transform
	if (rootOfUnityTableCheck->GetLength() == 0){
		BigBinaryVector Table(CycloOrder / 2);
		

		for (usint i = 0; i<CycloOrder / 2; i++){
			Table.SetValAtIndex(i, x);
			x = x.ModBarrettMul(rootOfUnity, modulus,mu);
		}

		//this->m_rootOfUnityTableByModulus.insert( std::make_pair(modulus.ToString(),Table));
		this->m_rootOfUnityTableByModulus[modulus.ToString()] = std::move(Table);
		

		
	}

	//Precomputes twiddle factor omega and FTT parameter phi for Inverse Transform
	BigBinaryVector  *rootOfUnityInverseTableCheck= &m_rootOfUnityInverseTableByModulus[modulus.ToString()];
	if(rootOfUnityInverseTableCheck->GetLength()==0){
		BigBinaryVector TableI(CycloOrder / 2);
		BigBinaryInteger rootOfUnityInverse = rootOfUnity.ModInverse(modulus);

		x = BigBinaryInteger::ONE;

		for (usint i = 0; i<CycloOrder / 2; i++){
			TableI.SetValAtIndex(i, x);
			x = x.ModBarrettMul(rootOfUnityInverse, modulus,mu);
		}

		this->m_rootOfUnityInverseTableByModulus[modulus.ToString()] = std::move(TableI);
		
	}

}

void ChineseRemainderTransformFTT::PreCompute(std::vector<BigBinaryInteger> &rootOfUnity, const usint CycloOrder, std::vector<BigBinaryInteger> &moduliiChain){


	usint numOfRootU = rootOfUnity.size();
	usint numModulii = moduliiChain.size();

	if( numOfRootU != numModulii){
		throw std::logic_error("size of root of unity and size of moduli chain not of same size");
		system("pause");
	}

	for(usint i=numOfRootU;i<numOfRootU;++i){

		BigBinaryInteger currentRoot(rootOfUnity[i]);
		BigBinaryInteger currentMod(moduliiChain[i]);

		//Pre-compute mu for Barrett function
		BigBinaryInteger temp(BigBinaryInteger::ONE);
		temp <<= 2 * currentMod.GetMSB() + 3;
		BigBinaryInteger mu = temp.DividedBy(currentMod);

		if(this->m_rootOfUnityTableByModulus[moduliiChain[i].ToString()].GetLength()!=0)
			continue;

		

		BigBinaryInteger x(BigBinaryInteger::ONE);
		

		//computation of root of unity table
		BigBinaryVector rTable(CycloOrder/2);
		

		for (usint i = 0; i<CycloOrder / 2; i++){
			rTable.SetValAtIndex(i, x);
			x = x.ModBarrettMul(currentRoot, currentMod, mu);
		}

		this->m_rootOfUnityTableByModulus[currentMod.ToString()] = std::move(rTable);

		//computation of root of unity inverse table
		x = BigBinaryInteger::ONE;

		BigBinaryInteger rootOfUnityInverse = currentRoot.ModInverse(currentMod);

		BigBinaryVector rTableI(CycloOrder/2);


		for (usint i = 0; i<CycloOrder / 2; i++){
			rTableI.SetValAtIndex(i, x);
			x = x.ModBarrettMul(rootOfUnityInverse, currentMod, mu);
		}

		this->m_rootOfUnityInverseTableByModulus[currentMod.ToString()] = std::move(rTableI);
		

	}


}

void ChineseRemainderTransform::Destroy(){
	//delete m_onlyInstance;
	delete m_rootOfUnityTable;
	delete m_rootOfUnityInverseTable;
}

void ChineseRemainderTransformFTT::Destroy(){
	delete m_onlyInstance;
	//delete m_rootOfUnityTable;
	//delete m_rootOfUnityInverseTable;
	//delete m_phiTable;
	//delete m_phiInverseTable;
	//m_rootOfUnityTable = NULL;
	//m_rootOfUnityInverseTable = NULL;
	//m_phiTable = NULL;
	//m_phiInverseTable = NULL;
}


}//namespace ends here
