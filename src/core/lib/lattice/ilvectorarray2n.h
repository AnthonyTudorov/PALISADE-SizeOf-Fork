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
	class ILVectorArray2n : public ILElement<ILVectorArray2n>
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
		*@param params parameter set required for ILVectorArray2n.
		*@param format the input format fixed to EVALUATION. Format is a enum type that indicates if the polynomial is in Evaluation representation or Coefficient representation. It is defined in inttypes.h.
		*@param initializeElementToZero
		*/
		ILVectorArray2n(const shared_ptr<ElemParams> params, Format format = EVALUATION, bool initializeElementToZero = false);

		/**
		* Constructor based on discrete Gaussian generator. 
		*
		* @param &dgg the input discrete Gaussian generator. The dgg will be the seed to populate the towers of the ILVectorArray2n with random numbers.
		* @param params parameter set required for ILVectorArray2n. 
		* @param format the input format fixed to EVALUATION. Format is a enum type that indicates if the polynomial is in Evaluation representation or Coefficient representation. It is defined in inttypes.h.
		*/
		ILVectorArray2n(const DiscreteGaussianGenerator &dgg, const shared_ptr<ElemParams> params, Format format = EVALUATION);

		/**
		* Constructor based on binary Gaussian generator. This is not implemented. Will throw a logic_error.
		*
		* @param &bug the input binary uniform generator. The bug will be the seed to populate the towers of the ILVectorArray2n with random numbers.
		* @param params parameter set required for ILVectorArray2n.
		* @param format the input format fixed to EVALUATION. Format is a enum type that indicates if the polynomial is in Evaluation representation or Coefficient representation. It is defined in inttypes.h.
		*/
		ILVectorArray2n(const BinaryUniformGenerator &bug, const shared_ptr<ElemParams> params, Format format = EVALUATION) {
			throw std::logic_error("Cannot use BinaryUniformGenerator with ILVectorArray2n; not implemented");
		}

		/**
		* Constructor based on binary Gaussian generator. This is not implemented. Will throw a logic_error.
		*
		* @param &tug the input ternary uniform generator. The bug will be the seed to populate the towers of the ILVectorArray2n with random numbers.
		* @param params parameter set required for ILVectorArray2n.
		* @param format the input format fixed to EVALUATION. Format is a enum type that indicates if the polynomial is in Evaluation representation or Coefficient representation. It is defined in inttypes.h.
		*/
		ILVectorArray2n(const TernaryUniformGenerator &tug, const shared_ptr<ElemParams> params, Format format = EVALUATION) {
			throw std::logic_error("Cannot use TernaryUniformGenerator with ILVectorArray2n; not implemented");
		}

		/**
		* Constructor based on full methods.
		*
		* @param &dug the input discrete Uniform Generator.
		* @param params the input params.
		* @param &format the input format fixed to EVALUATION. Format is a enum type that indicates if the polynomial is in Evaluation representation or Coefficient representation. It is defined in inttypes.h.
		*/
		ILVectorArray2n(const DiscreteUniformGenerator &dug, const shared_ptr<ElemParams> params, Format format = EVALUATION);

		/**
		* Construct using a single ILVector2n. The ILVector2n is copied into every tower. Each tower will be reduced to it's corresponding modulus  via GetModuli(at tower index). The format is derived from the passed in ILVector2n. 
		*
		* @param &element ILVector2n to build other towers from.
		* @param params parameter set required for ILVectorArray2n.
		*/
		ILVectorArray2n(const ILVector2n &element, const shared_ptr<ILDCRTParams> params);

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
		 * Clone the object by making a copy of it and returning the copy
		 * @return new Element
		 */
		ILVectorArray2n Clone() const { return std::move(ILVectorArray2n(*this)); }

		/**
		 * Clone the object, but have it contain nothing
		 * @return new Element
		 */
		ILVectorArray2n CloneEmpty() const { return std::move( ILVectorArray2n() ); }

 		/**
		* Clone
		*
		* Creates a new ILVectorArray2n and clones only the params. The tower values are empty. The tower values can be filled by another process/function or initializer list.
		*/
		ILVectorArray2n CloneParametersOnly() const;

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
		~ILVectorArray2n();

		//GETTERS

		/**
		* Get method of the cyclotomic order
		*
		* @return the cyclotomic order.
		*/
		const usint GetCyclotomicOrder() const ;

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
		std::vector<ILVectorArray2n> BaseDecompose(usint baseBits) const ;

		/**
		* Generate a vector of ILVector2n's as {x, base*x, base^2*x, ..., base^{\lfloor {\log q/base} \rfloor}*x, where x is the current ILVector2n object;
		* used as a subroutine in the relinearization procedure to get powers of a certain "base" for the secret key element
		*
		* @param baseBits is the number of bits in the base, i.e., base = 2^baseBits
		* @result is the pointer where the base decomposition vector is stored
		* @return true if operation is successful
		*/
		std::vector<ILVectorArray2n> PowersOfBase(usint baseBits) const ;


		//VECTOR OPERATIONS

		/**
		* Assignment Operator.
		*
		* @param &rhs the copied ILVectorArray2n.
		* @return the resulting ILVectorArray2n.
		*/
		const ILVectorArray2n& operator=(const ILVectorArray2n &rhs);

		/**
		* Move Assignment Operator.
		*
		* @param &rhs the copied ILVectorArray2n.
		* @return the resulting ILVectorArray2n.
		*/
		const ILVectorArray2n& operator=(ILVectorArray2n &&rhs);

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
		* Performs an entry-wise addition over all elements of each tower with the towers of the ILVectorArray2n on the right hand side.
		*
		* @param &rhs is the element to add with.
		* @return is the result of the addition.
		*/
		const ILVectorArray2n& operator+=(const ILVectorArray2n &rhs);

		/**
		* Performs an entry-wise subtraction over all elements of each tower with the towers of the ILVectorArray2n on the right hand side.
		*
		* @param &rhs is the element to subtract from.
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
		ILVectorArray2n Plus(const ILVectorArray2n &element, bool tothis = false) const;

		/**
		* Performs a multiplication operation and returns the result.
		*
		* @param &element is the element to multiply with.
		* @return is the result of the multiplication.
		*/
		ILVectorArray2n Times(const ILVectorArray2n &element, bool bythis = false) const;

		/**
		* Performs a subtraction operation and returns the result.
		*
		* @param &element is the element to subtract from.
		* @return is the result of the subtraction.
		*/
		ILVectorArray2n Minus(const ILVectorArray2n &element, bool fromthis = false) const;

		//SCALAR OPERATIONS

		/**
		* Scalar addition - add an element to the first index of each tower.
		*
		* @param &element is the element to add entry-wise.
		* @return is the result of the addition operation.
		*/
		ILVectorArray2n Plus(const BigBinaryInteger &element, bool tothis = false) const;

		/**
		* Scalar subtraction - subtract an element to all entries.
		*
		* @param &element is the element to subtract entry-wise.
		* @return is the return value of the minus operation.
		*/
		ILVectorArray2n Minus(const BigBinaryInteger &element, bool fromthis = false) const;

		/**
		* Scalar multiplication - multiply all entries.
		*
		* @param &element is the element to multiply entry-wise.
		* @return is the return value of the times operation.
		*/
		ILVectorArray2n Times(const BigBinaryInteger &element, bool bythis = false) const;

		/**
		* Scalar multiplication followed by division and rounding operation - operation on all entries.
		*
		* @param &p is the element to multiply entry-wise.
		* @param &q is the element to divide entry-wise.
		* @return is the return value of the multiply, divide and followed by rounding operation.
		*/
		ILVectorArray2n MultiplyAndRound(const BigBinaryInteger &p, const BigBinaryInteger &q) const;

		/**
		* Scalar division followed by rounding operation - operation on all entries.
		*
		* @param &q is the element to divide entry-wise.
		* @return is the return value of the divide, followed by rounding operation.
		*/
		ILVectorArray2n DivideAndRound(const BigBinaryInteger &q) const;
		
		/**
		*Performs a negation operation and returns the result.
		*
		* @return is the result of the negation.
		*/
		ILVectorArray2n Negate() const;

		const ILVectorArray2n& operator+=(const BigBinaryInteger &element) {
			return *this = Plus(element);
		}
		
		/**
		* Performs a subtraction operation and returns the result.
		*
		* @param &element is the element to subtract from.
		* @return is the result of the subtraction.
		*/
		const ILVectorArray2n& operator-=(const BigBinaryInteger &element) {
			return *this = Minus(element);
		}

		/**
		* Performs a multiplication operation and returns the result.
		*
		* @param &element is the element to multiply by.
		* @return is the result of the subtraction.
		*/
		const ILVectorArray2n& operator*=(const BigBinaryInteger &element);

		/**
		* Performs an multiplication operation and returns the result.
		*
		* @param &element is the element to multiply with.
		* @return is the result of the multiplication.
		*/
		const ILVectorArray2n& operator*=(const ILVectorArray2n &element);

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

		/**
		* Modulus - perform a modulus operation. Does proper mapping of [-modulus/2, modulus/2) to [0, modulus)
		*
		* @param modulus is the modulus to use.
		* @return is the return value of the modulus.
		*/
		ILVectorArray2n SignedMod(const BigBinaryInteger &modulus) const;

		// OTHER FUNCTIONS AND UTILITIES 

		/**
		* Get method that should not be used
		*
		* @return will throw a logic_error
		*/
		const BigBinaryVector &GetValues() const {
			throw std::logic_error("GetValues not implemented on ILVectorArray2n");
		}
		/**
		* Set method that should not be used, will throw an error.
		*
		* @param &values
		* @param format
		*/
		void SetValues(const BigBinaryVector &values, Format format) {
			throw std::logic_error("SetValues not implemented on ILVectorArray2n");
		}

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
		*@return true if all towers are empty
		*/
		bool IsEmpty() const;

		/**
		* Drops the last element in the tower. The resulting ILVectorArray2n will have one less tower.
		*/
		void DropLastElement();

		/**
		* ModReduces reduces the ILVectorArray2n's composite modulus by dropping the last modulus from the chain of moduli as well as dropping the last tower.
		* 
		*@param plaintextModulus is the plaintextModulus used for the ILVectorArray2n
		*/
		void ModReduce(const BigBinaryInteger &plaintextModulus);

		/**
		* Interpolates the ILVectorArray2n to an ILVector2n based on the Chinese Remainder Transform Interpolation.
		* and then returns an ILVectorArray2n with that single element
		*
		* @return the interpolated ring element embeded into ILVectorArray2n.
		*/
		ILVectorArray2n CRTInterpolate() const;

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

		/**
		* Pre computes the CRI factors. CRI factors are used in the chinese remainder interpolation.
		* Note that different vector of moduli can co-exist as precomputed values.
		*
		* @param &moduli is the chain of moduli to construct the CRI factors from
		*/
		static void PreComputeCRIFactors(const std::vector<BigBinaryInteger> &moduli, const usint cyclotomicOrder);

		/**
		* Deletes the static pointer CRI factors pointer
		*
		* @param &moduli is the chain of moduli to construct the CRI factors from
		*/
		static void DestroyPrecomputedCRIFactors();

		//JSON FACILITY
		/**
		* Stores this object's attribute name value pairs to a map for serializing this object to a JSON file.
		* Invokes nested serialization of BigBinaryVector.
		*
		* @param serializationMap stores this object's serialized attribute name value pairs.
		* @return true on success
		*/
		bool Serialize(Serialized* serObj) const;

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

		//This table stores constant interpolation values. The map maps a moduli to a each tower of the moduli's CRI factor.
		static std::map<BigBinaryInteger, std::map<usint, BigBinaryInteger>> *m_towersize_cri_factors;

		//This variable holds the cyclotomic order that the precomputed values are set for
		static usint m_cyclotomicOrder_precompute;

	};

	// overloaded operators
	inline ILVectorArray2n operator+(const ILVectorArray2n &a, const ILVectorArray2n &b) { return a.Plus(b); }
	inline ILVectorArray2n operator+(const ILVectorArray2n &a, const BigBinaryInteger &b) { return a.Plus(b); }
	inline ILVectorArray2n operator+(const BigBinaryInteger &a, const ILVectorArray2n &b) { return b.Plus(a); }
	inline ILVectorArray2n operator-(const ILVectorArray2n &a, const ILVectorArray2n &b) { return a.Minus(b); }
	inline ILVectorArray2n operator-(const ILVectorArray2n &a, const BigBinaryInteger &b) { return a.Minus(b); }
	inline ILVectorArray2n operator*(const ILVectorArray2n &a, const ILVectorArray2n &b) { return a.Times(b); }
	inline ILVectorArray2n operator*(const ILVectorArray2n &a, const BigBinaryInteger &b) { return a.Times(b); }
	inline ILVectorArray2n operator*(const BigBinaryInteger &a, const ILVectorArray2n &b) { return b.Times(a); }

} // namespace lbcrypto ends

#endif
