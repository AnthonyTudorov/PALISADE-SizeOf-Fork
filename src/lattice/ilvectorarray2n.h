/**
* @file
* @author  TPOC: Dr. Kurt Rohloff <rohloff@njit.edu>,
*	Programmers: Dr. Yuriy Polyakov, <polyakov@njit.edu>, Gyana Sahu <grs22@njit.edu>
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
* THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
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
* This code provides basic lattice ideal manipulation functionality.
*/

#ifndef LBCRYPTO_LATTICE_IL2N_H
#define LBCRYPTO_LATTICE_IL2N_H

#include <vector>
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
#include "../encoding/ptxtencoding.h"

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
		* Constructor that initializes nothing.
		*/
		ILVectorArray2n();

		// copy constructor
		/*
		* Copy constructor.
		*
		* @param &element the copied element.
		*/

		/**
		* Constructor that initializes parameters.
		*
		* @param &params element parameters.
		*/
		ILVectorArray2n(const ElemParams &params);



		/**
		* Constructor that initializes from another ILVectorArray2n.
		*
		* @param &element the element to construct from.
		*/
		ILVectorArray2n(const ILVectorArray2n &element);

		// construct using an array in either Coefficient (0) or CRT format (1)
		/**
		* Construct using an array in either Coefficient (0) or CRT format (1).
		*
		* @param &params the input parameters.
		* @param &levels the levels.
		* @param format the intended format.
		*/
		ILVectorArray2n(const ILDCRTParams& params, std::vector<ILVector2n> &levels, Format format);

		/**
		* Construct using an array in either Coefficient (0) or CRT format (1).
		*
		* @param element the input parameter to build ILVectorArray2n from one vector for double-CRT representation.
		* @param params the input parameters.
		* @param format the intended format.
		*/
		ILVectorArray2n(ILVector2n element, const ILDCRTParams& params, Format format);

		/**
		* Constructor based on full methods.
		*
		* @param &dgg the input discrete Gaussian Generator.
		* @param &params the input params.
		* @param &format the input format fixed to EVALUATION. Format is a enum type that indicates if the polynomial is in Evaluation representation or Coefficient representation. It is defined in inttypes.h.
		*/
		ILVectorArray2n(DiscreteGaussianGenerator &dgg, const ElemParams &params, Format format = EVALUATION);


		/**
		* Assignment Operator.
		*
		* @param &rhs the copied vector.
		* @return the resulting vector.
		*/
		ILVectorArray2n& operator=(const ILVectorArray2n &rhs);

		/*
		* Assignment Operator.
		*
		* @param &rhs the copied vector.
		* @return the resulting vector.
		*/
	//	ILVectorArray2n& operator*(const ILVectorArray2n &rhs, const ILVectorArray2n &b) { return *this.Times(rhs); }


		/*
		* Construct using a discrete Gaussian generator and a set of parameters.
		*
		* @param &dgg the input discrete Gaussian Generator.
		* @param &params the input params.
		*/
		//	ILVectorArray2n(DiscreteGaussianGenerator &dgg, const ILDCRTParams &params);

		// DESTRUCTORS
		/**
		* Destructor.
		*/
		~ILVectorArray2n();

		// Get accessors
		/**
		* Get method of the vector values.
		*
		* @param i the index of the tower level to get
		* @return the vector.
		*/
		ILVector2n GetValues(usint i) const;

		/**
		* Get method of the format.
		*
		* @return the format.
		*/
		Format GetFormat();

		/**
		* Get method of the parameter set.
		*
		* @return the parameter set.
		*/

		const ILDCRTParams &GetParams() const;

		// Set accessors

		/**
		* Set method of the values.
		*
		* @param values is the set of values of the vector.
		* @param format the intended format.
		*/
		void SetValues(std::vector<ILVector2n>& values, Format format);



		// SCALAR OPERATIONS


		// multiplicative inverse operation
		/**
		* Performs a multiplicative inverse operation and returns the result.
		*
		* @return is the result of the multiplicative inverse.
		*/
		ILVectorArray2n MultiplicativeInverse() const;

		/**
		* Scalar addition - add an element to all entries.
		*
		* @param &element is the element to add entry-wise.
		* @return is the return of the addition operation.
		*/
		ILVectorArray2n Plus(const BigBinaryInteger &element) const;

		/**
		* Perform a modulus by 2 operation.  Returns the least significant bit.
		*
		* @return is the return value of the modulus by 2, also the least significant bit.
		*/
		ILVectorArray2n ModByTwo() const;

		// addition operation
		/**
		* Performs an addition operation and returns the result.
		*
		* @param &element is the element to add with.
		* @return is the result of the addition.
		*/
		ILVectorArray2n Plus(const ILVectorArray2n &element) const;

		// multiplication operation - 
		/**
		* Performs a multiplication operation and returns the result.
		*
		* @param &element is the element to multiply with.
		* @return is the result of the multiplication.
		*/
		ILVectorArray2n Times(const ILVectorArray2n &element) const;


		/**
		* Scalar multiplication - multiply all entries.
		*
		* @param &element is the element to multiply entry-wise.
		* @return is the return value of the times operation.
		*/
		ILVectorArray2n Times(const BigBinaryInteger &element) const;
		// subtraction operation
		/*
		* Performs a subtraction operation and returns the result.
		*
		* @param &element is the element to subtract with.
		* @return is the result of the subtraction.
		*/
		//		ILVectorArray2n& Minus(const ILVectorArray2n &element) const;

		// multiplication operation
		/*
		* Performs a multiplication operation and returns the result.
		*
		* @param &element is the element to multiply with.
		* @return is the result of the multiplication.
		*/
		//		ILVectorArray2n& Times(const ILVectorArray2n &element) const;

		// division operation
		/*
		* Performs a division operation and returns the result.
		*
		* @param &element is the element to divide with.
		* @return is the result of the division.
		*/
		//	ILVectorArray2n& DividedBy(const ILVectorArray2n &element) const;

		// automorphism operation
		/*
		* Performs an automorphism transform operation and returns the result.
		*
		* @param &i is the element to perform the automorphism transform with.
		* @return is the result of the automorphism transform.
		*/
		//		ILVectorArray2n& AutomorphismTransform(const BigBinaryInteger& i) const;

		// multiplicative inverse operation
		/*
		* Performs a multiplicative inverse operation and returns the result.
		*
		* @return is the result of the multiplicative inverse.
		*/
		//		ILVectorArray2n& MultiplicativeInverse() const;

		// OTHER METHODS

		// rounds polynomial to a certain integer x
		/*
		* Rounds the polynomial to an input integer.
		*
		* @param x is integer to round to.
		* @return is the result of the rounding operation.
		*/
		//		ILVectorArray2n& Round(const BigBinaryInteger& x) const;

		// scaling operation used in modulus switching; will be used for FHE
		/*
		* Scaling operation used in modulus switching
		*
		* @param newModulus the new modulus to scale to.
		* @return is the result of the scaling operation.
		*/
		//	ILVectorArray2n& Scale(const BigBinaryInteger& newModulus) const;

		// add new level - will be used for FHE
		/*
		* Add new level operation.
		*
		* @param &element is the element to add.
		* @return is the result of the add level operation.
		*/
		//		void AddLevel(const ILVector2n &element);

		// remove level - will be used for FHE
		/*
		* Remove level operation.
		*
		* @param index is the level to remove.
		* @return is the result of the remove level operation.
		*/
		//	ILVector2n& RemoveLevel(usint index);

		// multiplication operation - PREV1
		/*
		* Performs a multiplication operation and returns the result.
		*
		* @param &element is the element to multiply with.
		* @return is the result of the multiplication.
		*/
	//	ILVectorArray2n Times(const ILVectorArray2n &element) const;

		//Represent the lattice in binary format
		/**
		* Convert the lattice to be represented internally in binary format.
		*
		* @param *text the byte array to take as input.
		* @param &modulus modulus to convert from.
		*/

		// multiplicative inverse operation
		/*
		* Performs a multiplicative inverse operation and returns the result.
		* For double-crt, call multiplicative inverse on all Ilvector2ns (this is with respect to the modulus of each vector from the tower)
		* @return is the result of the multiplicative inverse.
		*/
		//ILVector2n MultiplicativeInverse() const;
		void DecodeElement(ByteArrayPlaintextEncoding *text, const BigBinaryInteger &modulus) const;
		
		/*
		Helper method for chinese remainder interpolatiom
		*/

		/**
		*This function returns the interpolated vectors
		*/

		ILVector2n InterpolateIlArrayVector2n();

		//Convert binary string to lattice format
		/**
		* Convert binary string to lattice format.
		*
		* @param &encoded the byte array to take as input.
		* @param &modulus modulus to convert to.
		*/
		void EncodeElement(const ByteArrayPlaintextEncoding &encoded, const BigBinaryInteger &modulus);
		// convert from Coefficient to CRT or vice versa; calls FFT and inverse FFT
		/**
		* Convert from Coefficient to CRT or vice versa; calls FFT and inverse FFT.
		*/
		void SwitchFormat();

		/**
		* Determines if inverse exists
		*
		* @return is the Boolean representation of the existence of multiplicative inverse.
		*/
		bool InverseExists() const;

		private:BigBinaryInteger CalculateInterpolationSum(std::vector<std::vector<BigBinaryInteger>> vectorOfvectors, usint index);

		/*
		Helper method for chinese remainder interpolatiom
		*/

		private:std::vector<std::vector<BigBinaryInteger>> BuildChineseRemainderInterpolationVector(std::vector<std::vector<BigBinaryInteger>> vectorOfvectors);

		/*
		Helper method for chinese remainder interpolatiom
		*/

		private:BigBinaryInteger CalculateChineseRemainderInterpolationCoefficient(usint i);

	    /*
		*This function is a helper function that applies a modulus to all IlVector2n's so they don't wrap their respective modulus
		*/
	
	private:void ChangeModuliOfIlVectorsToMatchDBLCRT();

	/*
	*helper function for chinese remainder interpolation
	*/
	private:std::vector<BigBinaryInteger> BuildChineseRemainderInterpolationVectorForRow(usint i);

			/*This function takes in a row and a vector of vector of BigBinaryIntegers and calculates the sum of each
			row, module the value set by the CRI formula*/
			/*This method calculates the value for CRI*/
	private:BigBinaryInteger CalculatInterpolateModulu(BigBinaryInteger value, usint index);

			/*


			// modulus factors in ciphertext modulus
			BigBinaryVector m_modulusFactors;

			// computes moduli qi
			void ComputeModuli();

			// when modulus factors are set, m_moduli are automatically computed by calling ComputeModuli()
			void SetModulusFactors(const BigBinaryVector& m_modulusFactors);

			*/

	private:
		// array of vectors used for double-CRT presentation
		std::vector<ILVector2n> m_vectors;

		// parameters for the ideal lattice: cyclotomic order and ciphertext modulus factors
		ILDCRTParams m_params;

		// 0 for coefficient and 1 for evaluation format
		Format m_format;

	};

	/**
	* Multiplication operator overload.  Performs a multiplication in the ring.
	*
	* @param &a the first parameter.
	* @param &b the first parameter.
	*
	* @return The result of multiplication in the ring.
	*/
	inline lbcrypto::ILVectorArray2n operator*(const lbcrypto::ILVectorArray2n &a, const lbcrypto::ILVectorArray2n &b) { return a.Times(b); }

	/**
	* Multiplication operator overload.  Performs a multiplication in the ring.
	*
	* @param &a the first parameter.
	* @param &b the first parameter.
	*
	* @return The result of multiplication in the ring.
	*/
	inline lbcrypto::ILVectorArray2n operator*(const lbcrypto::BigBinaryInteger &b, const lbcrypto::ILVectorArray2n &a) { return a.Times(b); }

	/**
	* Addition operator overload.  Performs an addition in the ring.
	*
	* @param &a the first parameter.
	* @param &b the first parameter.
	*
	* @return The result of addition in the ring.
	*/
	inline lbcrypto::ILVectorArray2n operator+(const lbcrypto::ILVectorArray2n &a, const lbcrypto::ILVectorArray2n &b) { return a.Plus(b); }


	/**
	* Addition operator overload.  Performs an addition in the ring.
	*
	* @param &a the first parameter.
	* @param &b the first parameter.
	*
	* @return The result of addition in the ring.
	*/
	inline lbcrypto::ILVectorArray2n operator+(const lbcrypto::ILVectorArray2n &a, const lbcrypto::BigBinaryInteger &b) { return a.Plus(b); }

} // namespace lbcrypto ends

#endif
