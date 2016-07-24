/**
* @file
* @author  TPOC: Dr. Kurt Rohloff <rohloff@njit.edu>,
*	Programmers: Dr. Yuriy Polyakov, <polyakov@njit.edu>, Gyana Sahu <grs22@njit.edu>, Hadi Sajjadpour <ss2959@njit.edu>
* @version 00_03
*
* @section LICENSE
*
* Copyright (c) 2015, New Jersey Institute of Technology (NJIT)
* All rights reserved.
* Redistribution and use in source and binary forms, with or without modification,
* are permitted provided that the following conditions are met:
* 1. Redistributions of source code must retain the above copyright notice, this
* list of conditions and the following disclaimer.
* 2. Redistributions in binary form must reproduce the above copyright notice, this
* list of conditions and the following disclaimer in the documentation and/or other
* materials provided with the distribution.
* THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONT0RIBUTORS "AS IS" AND
* ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
* WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
* DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR
* ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
* (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
* OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
* THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
* NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
* IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*
* @section DESCRIPTION
*
* On a high level, ILVectorArray2n stands for: IL = Ideal Lattice, ILVectorArray= An array of ILVector2n's, 2n = power of two cyclotomic. 
* for more information on ideal lattices please see here: 10.1007/978-3-540-88702-7_5
*
* This class provides a data structure for polynomial rings modulus a power of two cyclotomic order polynomial in double-CRT (Chinese remainder transform) format. The class
* can be viewed as a data structure that can support representing polynomials in double-CRT format. The double here means 
* two dimensions (like a n*m matrix) versus a 1*n dimension which the single-CRT or ILVector2n is. Each column of the 
* of the matrix is called a tower and is composed of an ILVector2n. 
* The purpose of having an array of ILVector2n's is to gain performance. A polynomial represented in ILVector2n with a large modulus and large coefficients,
* can be broken down into ILVector2ns with lower moduli and lower coefficients. The multiplication of the moduli must equal to the original large modulus. 
* It is possible to go from an ILVectorArray2n representation of a polynomial to an ILVector2n representation via the Chinese Remainder Transform Interpolation. 
* The function in this class that achieves this is the InterpolateILVectorArray2n function.
* The term ring dimension will be used throughout this code. Ring dimension in this class would refer to the size of each tower (as in how many elements the BigBinaryVector
* of it's corresponding ILVector2n holds). In the special case of this data structure (power of two cyclotomic order), the ring dimension is half the cyclotomic order.
* 
* This class has three private members: 
* std::vector<ILVector2n> m_vectors: This holds the towers
* Format m_format; The format of the ILVectorArray2n, which is either in coefficient or evaluation (CRT) format.
*
* The crypto layer code of the library is where this data structure can be utilized. 
*
*/

#ifndef LBCRYPTO_LATTICE_IL2VECTORARRAY2N_H
#define LBCRYPTO_LATTICE_IL2VECTORARRAY2N_H

#include <vector>
#include <string>

#include "../math/backend.h"
#include "../utils/inttypes.h"
#include "../math/distrgen.h"
#include "../lattice/elemparams.h"
#include "../lattice/ilparams.h"
#include "../lattice/ildcrtparams.h"
#include "../lattice/ilelement.h"
#include "../lattice/ilvector2n.h"
#include "../math/nbtheory.h"
#include "../math/transfrm.h"

/**
* @namespace lbcrypto
* The namespace of lbcrypto
*/
namespace lbcrypto {

	/**
	* @brief Ideal lattice in the double-CRT representation.  This is not fully implemented and is currently only stubs.
	*/
	class ILVectorArray2n : public ILElement
	{
	public:

		// CONSTRUCTORS

		/**
		* Constructor that initialized m_format to EVALUATION and calls m_params to nothing
		*/
		ILVectorArray2n();
		
		/**
		* Constructor that initializes parameters.
		*
		*@param &params parameter set required for ILVectorArray2n.
		*@param format the input format fixed to EVALUATION. Format is a enum type that indicates if the polynomial is in Evaluation representation or Coefficient representation. It is defined in inttypes.h.
		*/
		ILVectorArray2n(const ElemParams &params, Format format = EVALUATION);

		/**
		* Constructor based on discrete Gaussian generator.
		*
		* @param &dgg the input discrete Gaussian generator. The dgg will be the seed to populate the towers of the ILVectorArray2n with random numbers.
		* @param &params parameter set required for ILVectorArray2n. 
		* @param format the input format fixed to EVALUATION. Format is a enum type that indicates if the polynomial is in Evaluation representation or Coefficient representation. It is defined in inttypes.h.
		*/
		ILVectorArray2n(const DiscreteGaussianGenerator &dgg, const ElemParams &params, Format format = EVALUATION);

		/**
		* Construct using a single ILVector2n. The ILVector2n is copied into every tower. Each tower will be reduced to it's corresponding modulus  via GetModuli(at tower index). The format is derived from the passed in ILVector2n. 
		*
		* @param &element ILVector2n to build other towers from.
		* @param &params parameter set required for ILVectorArray2n.
		*/
		ILVectorArray2n(const ILVector2n &element, const ILDCRTParams &params);

		/**
		* Construct using an tower of ILVectro2ns. The params and format for the ILVectorArray2n will be derived from the towers.
		*
		* @param &towers vector of ILVector2ns which correspond to each tower of ILVectorArray2n.
		*/
		ILVectorArray2n(const std::vector<ILVector2n> &elements);

		/**
		* Copy constructor.
		*
		* @param &element ILVectorArray2n to copy from
		*/
		ILVectorArray2n(const ILVectorArray2n &element);

		/**
		* Move constructor.
		*
		* @param &&element ILVectorArray2n to move from
		*/
		ILVectorArray2n(const ILVectorArray2n &&element);

		//CLONE OPERATIONS
		/**
		* Clone
		*
		* Creates a new ILVectorArray2n and clones only the params. The tower values are empty. The tower values can be filled by another process/function or initializer list.
		*/
		ILVectorArray2n CloneWithParams() const;

		/**
		* Clone with noise
		*
		* Creates a new ILVectorArray2n and clones the params. The tower values will be filled up with noise based on the discrete gaussian.
		*
		* @param &dgg the input discrete Gaussian generator. The dgg will be the seed to populate the towers of the ILVectorArray2n with random numbers.
		* @param format the input format fixed to EVALUATION. Format is a enum type that indicates if the polynomial is in Evaluation representation or Coefficient representation. It is defined in inttypes.h.
		*/
		ILVectorArray2n CloneWithNoise(const DiscreteGaussianGenerator &dgg, Format format = EVALUATION) const;

		/**
		* Destructor.
		*/
		virtual ~ILVectorArray2n(); //must be virtual since member printvals() is virtual

		//GETTERS

		/**
		* Get method of the cyclotomic order
		*
		* @return the cyclotomic order.
		*/
		usint GetCyclotomicOrder() const ;

		/**
		* Get method of the modulus.
		*
		* @return the modulus.
		*/
		const BigBinaryInteger &GetModulus() const;
		
		/**
		* Get method for the number of towers of the ILVectorArray2n.
		*
		* @return the number of towers.
		*/
		usint GetLength() const {
			usint tot = 0;
			for( auto vec : m_vectors ) {
				tot += vec.GetLength();
			}
			return tot;
		}

		/**
		* Get method of individual towers.
		*
		* @param i index of tower to be returned.
		* @returns a reference to the ILVector2n at index i.
		*/
		const ILVector2n &GetElementAtIndex(usint i) const;

		/**
		* Get method of the tower length.
		*
		* @return the length of the tower.
		*/
		usint GetNumOfElements() const;
		
		/**
		* Get method that returns a vector of all towers.
		*
		* @returns values.
		*/
		const std::vector<ILVector2n>& GetAllElements() const;

		/**
		* Get method of the format.
		*
		* @return the format.
		*/
		Format GetFormat() const;
		
		/**
		* Get digit for a specific base.  Gets a binary polynomial from a given polynomial.  From every coefficient, it extracts the same digit.  This function only supports power of two operations. Used in bit decomposition/relinearization operations.
		*
		* @param index is the index to get.
		* @param base is the base the result should be in.
		* @return is the result.
		*/
		ILVectorArray2n GetDigitAtIndexForBase(usint index, usint base) const;

		/**
		* Write vector x (current value of the ILVector2n object) as \sum\limits{i=0}^{\lfloor {\log q/base} \rfloor} {(base^i u_i)} and
		* return the vector of {u_0, u_1,...,u_{\lfloor {\log q/base} \rfloor}} \in R_base^{\lceil {\log q/base} \rceil};
		* used as a subroutine in the relinearization procedure
		*
		* @param baseBits is the number of bits in the base, i.e., base = 2^baseBits
		* @result is the pointer where the base decomposition vector is stored
		*/
		void BaseDecompose(usint baseBits, std::vector<ILVectorArray2n> *result) const { };

		/**
		* Generate a vector of ILVector2n's as {x, base*x, base^2*x, ..., base^{\lfloor {\log q/base} \rfloor}*x, where x is the current ILVector2n object;
		* used as a subroutine in the relinearization procedure to get powers of a certain "base" for the secret key element
		*
		* @param baseBits is the number of bits in the base, i.e., base = 2^baseBits
		* @result is the pointer where the base decomposition vector is stored
		* @return true if operation is successful
		*/
		void PowersOfBase(usint baseBits, std::vector<ILVectorArray2n> *result) const { };


		//VECTOR OPERATIONS

		/**
		* Assignment Operator.
		*
		* @param &rhs the copied ILVectorArray2n.
		* @return the resulting ILVectorArray2n.
		*/
		const ILVectorArray2n& operator=(const ILVectorArray2n &rhs);

		/**
		* Initalizer list
		*
		* @param &rhs the list to initalized the ILVectorArray2n
		* @return the resulting ILVectorArray2n.
		*/
		ILVectorArray2n& operator=(std::initializer_list<sint> rhs);

		/**
		* Equal operator.
		*
		* @param &rhs is the specified ILVectorArray2n to be compared with this ILVectorArray2n.
		* @return true if this ILVectorArray2n represents the same values as the specified ILVectorArray2n, false otherwise
		*/
		bool operator==(const ILVectorArray2n &rhs) const;

		/**
		* Not equal operator compares this ILVectorArray2n to the specified ILVectorArray2n
		*
		* @param &rhs is the specified ILVectorArray2n to be compared with this ILVectorArray2n.
		* @return true if this ILVectorArray2n represents the same values as the specified ILVectorArray2n, false otherwise
		*/
        bool operator!=(const ILVectorArray2n &rhs) const;

		/**
		* Performs an entry-wise addition over all elements of each tower with the towers of the ILVectorArray2n on the right hand side.
		*
		* @param &rhs is the element to add with.
		* @return is the result of the addition.
		*/
		const ILVectorArray2n& operator+=(const ILVectorArray2n &rhs);

		/**
		* Performs an entry-wise subtraction over all elements of each tower with the towers of the ILVectorArray2n on the right hand side.
		*
		* @param &rhs is the element to add with.
		* @return is the result of the addition.
		*/
		const ILVectorArray2n& operator-=(const ILVectorArray2n &rhs);

		/**
		* Permutes coefficients in a polynomial. Moves the ith index to the first one, it only supports odd indices. 
		*
		* @param &i is the element to perform the automorphism transform with.
		* @return is the result of the automorphism transform.
		*/
		ILVectorArray2n AutomorphismTransform(const usint &i) const {return ILVectorArray2n(*this);};

		/**
		* Performs an addition operation and returns the result.
		*
		* @param &element is the element to add with.
		* @return is the result of the addition.
		*/
		ILVectorArray2n Plus(const ILVectorArray2n &element) const;

		/**
		* Performs a multiplication operation and returns the result.
		*
		* @param &element is the element to multiply with.
		* @return is the result of the multiplication.
		*/
		ILVectorArray2n Times(const ILVectorArray2n &element) const;

		/**
		* Performs a subtraction operation and returns the result.
		*
		* @param &element is the element to subtract from.
		* @return is the result of the subtraction.
		*/
		ILVectorArray2n Minus(const ILVectorArray2n &element) const;

		//SCALAR OPERATIONS

		/**
		* Scalar addition - add an element to the first index of each tower.
		*
		* @param &element is the element to add entry-wise.
		* @return is the result of the addition operation.
		*/
		ILVectorArray2n Plus(const BigBinaryInteger &element) const;

		/**
		* Scalar subtraction - subtract an element to all entries.
		*
		* @param &element is the element to subtract entry-wise.
		* @return is the return value of the minus operation.
		*/
		ILVectorArray2n Minus(const BigBinaryInteger &element) const;

		/**
		* Scalar multiplication - multiply all entries.
		*
		* @param &element is the element to multiply entry-wise.
		* @return is the return value of the times operation.
		*/
		ILVectorArray2n Times(const BigBinaryInteger &element) const;
		
		/**
		* Performs an addition operation and returns the result.
		*
		* @param &rhs is the element to add with.
		* @return is the result of the addition.
		*/
		const ILVectorArray2n& operator+=(const BigBinaryInteger &rhs);

		/**
		* Performs an addition operation and returns the result.
		*
		* @param &element is the element to subtract from.
		* @return is the result of the subtraction.
		*/
		const ILVectorArray2n& operator-=(const BigBinaryInteger &element);

		// multiplicative inverse operation
		/**
		* Performs a multiplicative inverse operation and returns the result.
		*
		* @return is the result of the multiplicative inverse.
		*/
		ILVectorArray2n MultiplicativeInverse() const;

		/**
		* Perform a modulus by 2 operation.  Returns the least significant bit.
		*
		* @return is the resulting value.
		*/
		ILVectorArray2n ModByTwo() const;

		// OTHER FUNCTIONS AND UTILITIES 

		/**
		* Prints values of each tower
		*/
		void PrintValues() const;

		/**
		* Adds BigBinaryInteger "1" to every entry in every tower.
		*/
		void AddILElementOne();

		/**
		* Make ILVectorArray2n Sparse. Sets every index of each tower not equal to zero mod the wFactor to zero.
		*
		* @param &wFactor ratio between the sparse and none-sparse values. 
		*/
		void MakeSparse(const BigBinaryInteger &wFactor);

		/**
		* Performs ILVector2n::Decompose on each tower and adjusts the ILVectorArray2n.m_parameters accordingly. This method also reduces the ring dimension by half.
		*/
		void Decompose();

		/**
		* Returns true if ALL the tower(s) are empty.  
		*/
		bool IsEmpty() const;

		/**
		* Drops the tower at the index passed to it. The resulting ILVectorArray2n will have one less tower.
		*
		* @param index is the index of the tower to be dropped.
		*/
		void DropElementAtIndex(usint index);

		/**
		* ModReduces reduces the ILVectorArray2n's composite modulus by dropping the last modulus from the chain of moduli as well as dropping the last tower.
		* 
		*@param plaintextModulus is the plaintextModulus used for the ILVectorArray2n
		*/
		void ModReduce(const BigBinaryInteger &plaintextModulus);

		/**
		* Interpolates the ILVectorArray2n to an ILVector2n based on the Chinese Remainder Transform Interpolation.
		*
		* @return the ILVector2n representation of the ILVectorArray2n.
		*/
		ILVector2n InterpolateIlArrayVector2n() const;

		/**
		* Convert from Coefficient to CRT or vice versa; calls FFT and inverse FFT.
		*/
		void SwitchFormat();

		/**
		* Switch modulus and adjust the values
		*
		* @param &modulus is the modulus to be set
		* @param &rootOfUnity is the corresponding root of unity for the modulus
		* ASSUMPTION: This method assumes that the caller provides the correct rootOfUnity for the modulus
		*/
		void SwitchModulus(const BigBinaryInteger &modulus, const BigBinaryInteger &rootOfUnity);

		/**
		* Switch modulus at tower i and adjust the values
		*
		* @param index is the index for the tower
		* @param &modulus is the modulus to be set
		* @param &rootOfUnity is the corresponding root of unity for the modulus
		* ASSUMPTION: This method assumes that the caller provides the correct rootOfUnity for the modulus
		*/
		void SwitchModulusAtIndex(usint index, const BigBinaryInteger &modulus, const BigBinaryInteger &rootOfUnity);

		/**
		* Determines if inverse exists
		*
		* @return is the Boolean representation of the existence of multiplicative inverse.
		*/
		bool InverseExists() const;

		//JSON FACILITY
		/**
		* Stores this object's attribute name value pairs to a map for serializing this object to a JSON file.
		* Invokes nested serialization of BigBinaryVector.
		*
		* @param serializationMap stores this object's serialized attribute name value pairs.
		* @param fileFlag TODO.
		* @return map updated with the attribute name value pairs required to serialize this object.
		*/
		bool Serialize(Serialized* serObj, const std::string fileFlag = "") const;

		/**
		* Populate the object from the deserialization of the Setialized
		* @param serObj contains the serialized object
		* @return true on success
		*/
		bool Deserialize(const Serialized& serObj);

	private:
		// array of vectors used for double-CRT presentation
		std::vector<ILVector2n> m_vectors;

		// Either Format::EVALUATION (0) or Format::COEFFICIENT (1)
		Format m_format;

		//Big Modulus, multiplied value of all tower moduli
		BigBinaryInteger m_modulus;

		usint m_cyclotomicOrder;

		//Number of ILVector Elements
		usint m_numberOfElements;
	};

	/**
	* Multiplication operator overload. 
	*
	* @param &a the first ILVectorArray2n.
	* @param &b the second ILVectorArray2n.
	*
	* @return an ILVectorArray2n with the resulting value.
	*/
	inline ILVectorArray2n operator*(const ILVectorArray2n &a, const ILVectorArray2n &b) { return a.Times(b); }

	/**
	* Scalar multiplication operator overload-multiply all entries.
	*
	* @param &a the BigBinaryInteger to multiply by every element of every tower of the second argument.
	* @param &b the ILVectorArray2n to be multiplied by the first argument.
	*
	* @return an ILVectorArray2n with the resulting value.
	*/
	inline ILVectorArray2n operator*(const BigBinaryInteger &a, const ILVectorArray2n &b) { return b.Times(a); }

	/**
	* Scalar multiplication operator overload-multiply all entries.
	*
	* @param &a the ILVectorArray2n to multiply by the second argument.
	* @param &b the BigBinaryInteger to multiply by the first argument.
	*
	* @return an ILVectorArray2n with the resulting value.
	*/
	inline ILVectorArray2n operator*(const ILVectorArray2n &a,const BigBinaryInteger &b) { return a.Times(b); }

	/**
	* Addition operator overload. 
	*
	* @param &a ILVectorArray2n to be added to the second argument.
	* @param &b ILVectorArray2n to be added to the first argument.
	*
	* @return an ILVectorArray2n with the resulting value.
	*/
	inline ILVectorArray2n operator+(const ILVectorArray2n &a, const ILVectorArray2n &b) { return a.Plus(b); }

	/**
	* Scalar addition operator overload-add an element to the first index of each tower.
	*
	* @param &a ILVectorArray2n to be used for addition.
	* @param &b BigBinaryInteger to be added to the first index of every tower of argument &a.
	*
	* @return an ILVectorArray2n with the resulting value.
	*/
	inline ILVectorArray2n operator+(const ILVectorArray2n &a, const BigBinaryInteger &b) { return a.Plus(b); }

	/**
	* Scalar addition operator overload-add an element to the first index of each tower.
	*
	* @param &a BigBinaryInteger to be added to the first index of every tower of argument &b.
	* @param &b ILVectorArray2n to be used for addition.
	*
	* @return an ILVectorArray2n with the resulting value.
	*/
	inline ILVectorArray2n operator+(const BigBinaryInteger &a, const ILVectorArray2n &b) { return b.Plus(a); }

} // namespace lbcrypto ends

#endif
