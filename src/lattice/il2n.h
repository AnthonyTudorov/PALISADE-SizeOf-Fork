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
#include "../lattice/ideals.h"
#include "../math/nbtheory.h"
#include "../math/transfrm.h"
#include "../encoding/ptxtencoding.h"

/**
* @namespace lbcrypto
* The namespace of lbcrypto
*/
namespace lbcrypto {

	const usint SAMPLE_SIZE = 30; //!< @brief The maximum number of samples used for random variable sampling.

								  /**
								  * @brief Ideal lattice in vector representation or a vector in the double-CRT "matrix".  This is not fully implemented and is currently only stubs.
								  */
	class ILVector2n : public ILElement
	{
	public:

		/**
		* Constructor that initializes nothing.
		*/
		ILVector2n();

		/**
		* Constructor that initializes parameters.
		*
		* @param &params element parameters.
		*/
		ILVector2n(const ElemParams &params);

		/**
		* Copy constructor.
		*
		* @param &element the copied element.
		*/
		ILVector2n(const ILVector2n &element);

		/**
		* Copy constructor.
		*
		* @param &&element the copied element.
		*/
		ILVector2n(ILVector2n &&element);

		/**
		* Assignment Operator.
		*
		* @param &rhs the copied vector.
		* @return the resulting vector.
		*/
		ILVector2n& operator=(const ILVector2n &rhs);

		/**
		* Assignment Operator.
		*
		* @param &&rhs the copied vector.
		* @return the resulting vector.
		*/
		ILVector2n& operator=(ILVector2n &&rhs);

		// construct using an array in either Coefficient (0) or CRT format (1)
		//ILVector2n (const BigBinaryVector &values, Format format, const ILParams &params):m_values(new BigBinaryVector(values)),
		//m_params(params),m_format(format){	}

		/**
		* Constructor based on full methods.
		*
		* @param &dgg the input discrete Gaussian Generator.
		* @param &params the input params.
		* @param &format the input format fixed to EVALUATION. Format is a enum type that indicates if the polynomial is in Evaluation representation or Coefficient representation. It is defined in inttypes.h.
		*/
		ILVector2n(DiscreteGaussianGenerator &dgg, const ElemParams &params, Format format = EVALUATION);

		/**
		* Destructor.
		*/
		~ILVector2n();

		//void GenerateGaussian(DiscreteGaussianGenerator &dgg);

		/**
		* Get method of the modulus.
		*
		* @return the modulus.
		*/
		const BigBinaryInteger &GetModulus() const;

		/**
		* Get method of the vector.
		*
		* @return the vector.
		*/
		const BigBinaryVector &GetValues() const;

		/**
		* Get method of the root of unity.
		*
		* @return the root of unity.
		*/
		const BigBinaryInteger &GetRootOfUnity();

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
		const ILParams &GetParams();

		/**
		* Get value of binaryvector at index i.
		*
		* @return value at index i.
		*/
		const BigBinaryInteger& GetIndexAt(usint i);

		/**
		* Get method of the length of the element.
		*
		* @return the length of the element.
		*/
		usint GetLength();

		/**
		* Set method of the values.
		*
		* @param values is the set of values of the vector.
		* @param format is the format.
		*/
		void SetValues(const BigBinaryVector& values, Format format);

		/**
		* Set method of the values.
		*
		* @param values is the set of values of the vector.
		* @param format is the format.
		*/
		void SetModulus(const BigBinaryInteger &modulus);


		// SCALAR OPERATIONS


		/**
		* Scalar addition - add an element to all entries.
		*
		* @param &element is the element to add entry-wise.
		* @return is the return of the addition operation.
		*/
		ILVector2n Plus(const BigBinaryInteger &element) const;

		/**
		* Scalar subtraction - subtract an element to all entries.
		*
		* @param &element is the element to subtract entry-wise.
		* @return is the return value of the minus operation.
		*/
		ILVector2n Minus(const BigBinaryInteger &element) const;

		/**
		* Scalar multiplication - multiply all entries.
		*
		* @param &element is the element to multiply entry-wise.
		* @return is the return value of the times operation.
		*/
		ILVector2n Times(const BigBinaryInteger &element) const;

		/**
		* Scalar division - divide an element to all entries.
		*
		* @param &element is the element to divide entry-wise.
		* @return is the return value of the division operation.
		*/
		ILVector2n DividedBy(const BigBinaryInteger &element) const;

		/**
		* Modulus - perform a modulus operation.
		*
		* @param modulus is the modulus to use.
		* @return is the return value of the modulus.
		*/
		ILVector2n Mod(const BigBinaryInteger & modulus) const;

		/**
		* Perform a modulus by 2 operation.  Returns the least significant bit.
		*
		* @return is the return value of the modulus by 2, also the least significant bit.
		*/
		BigBinaryVector ModByTwo() const;

		// VECTOR OPERATIONS

		/**
		* Determines if two vectors are equal.
		*
		* @param &element is the element to test equality with.
		* @return is the Boolean representation of equality.
		*/
		bool Equal(const ILVector2n &element) const;

		/**
		* Determines if inverse exists
		*
		* @return is the Boolean representation of the existence of multiplicative inverse.
		*/
		bool InverseExists() const;

		// addition operation - PREV1
		/**
		* Performs an addition operation and returns the result.
		*
		* @param &element is the element to add with.
		* @return is the result of the addition.
		*/
		ILVector2n Plus(const ILVector2n &element) const;

		/**
		* Performs an addition operation and returns the result.
		*
		* @param &element is the element to add with.
		* @return is the result of the addition.
		*/
		const ILVector2n& operator+=(const ILVector2n &element);

		// subtraction operation
		/**
		* Performs a subtraction operation and returns the result.
		*
		* @param &element is the element to subtract with.
		* @return is the result of the subtraction.
		*/
		ILVector2n Minus(const ILVector2n &element) const;

		// multiplication operation - PREV1
		/**
		* Performs a multiplication operation and returns the result.
		*
		* @param &element is the element to multiply with.
		* @return is the result of the multiplication.
		*/
		ILVector2n Times(const ILVector2n &element) const;

		// division operation
		/**
		* Performs a division operation and returns the result.
		*
		* @param &element is the element to divide with.
		* @return is the result of the division.
		*/
		ILVector2n DividedBy(const ILVector2n &element) const;

		// automorphism operation
		/**
		* Performs an automorphism transform operation and returns the result.
		*
		* @param &i is the element to perform the automorphism transform with.
		* @return is the result of the automorphism transform.
		*/
		ILVector2n AutomorphismTransform(const BigBinaryInteger &i) const;

		// multiplicative inverse operation
		/**
		* Performs a multiplicative inverse operation and returns the result.
		*
		* @return is the result of the multiplicative inverse.
		*/
		ILVector2n MultiplicativeInverse() const;

		// OTHER METHODS

		// rounds polynomial to a certain integer x
		/**
		* Rounds the polynomial to an input integer.
		*
		* @param x is integer to round to.
		* @return is the result of the rounding operation.
		*/
		ILVector2n Round(const BigBinaryInteger& x) const;

		// convert from Coefficient to CRT or vice versa; calls FFT and inverse FFT
		/**
		* Convert from Coefficient to CRT or vice versa; calls FFT and inverse FFT.
		*/
		void SwitchFormat();

		// get digit for a specific based - used for PRE scheme
		/**
		* Get digit for a specific base.  Gets a binary polynomial from a given polynomial.  From every coefficient, it extracts the same digit.  Used in bit decomposition/relinearization operations.
		*
		* @param index is the index to get.
		* @param base is the base the result should be in.
		* @return is the result.
		*/
		ILVector2n GetDigitAtIndexForBase(usint index, usint base) const;

		// does the vector have any coefficients
		/**
		* Returns whether the vector is all zero.
		*
		* @return returns whether the vector is all zero.
		*/
		bool IsZero() const;

		/**
		* Shift entries in the vector left a specific number of entries.
		*
		* @param n the number of entries to shift left.
		* @return is the resulting vector from shifting left.
		*/
		ILVector2n ShiftLeft(unsigned int n) const;

		/**
		* Shift entries in the vector right a specific number of entries.
		*
		* @param n the number of entries to shift right.
		* @return is the resulting vector from shifting right.
		*/
		ILVector2n ShiftRight(unsigned int n) const;

		//Represent the lattice in binary format
		/**
		* We assume the plaintext comes as an array of bits and this function converts those bits input a ByteArray.
		* This method saves the result into the output parameter text.
		*
		* @param *text the byte array output.
		* @param &modulus modulus to convert from.
		*/
		void DecodeElement(ByteArrayPlaintextEncoding *text, const BigBinaryInteger &modulus) const;

		//Convert binary string to lattice format; do p=2 first but document that we need to generalize it later
		/**
		* Convert binary string to lattice format.
		*
		* @param &encoded the byte array output.
		* @param &modulus modulus to convert to.
		*/
		void EncodeElement(const ByteArrayPlaintextEncoding &encoded, const BigBinaryInteger &modulus);

		/**
		* Print the pre-computed discrete Gaussian samples.
		*/
		static void PrintPreComputedSamples() {
			for (usint i = 0; i < SAMPLE_SIZE; i++)
				std::cout << m_dggSamples[i].GetValues() << std::endl;
		}

		// computes the samples
		/**
		* Pre computes the Dgg samples.
		*
		* @param &dgg the discrete Gaussian Generator.
		* @param &params are the relevant ring parameters.
		*/
		static void PreComputeDggSamples(DiscreteGaussianGenerator &dgg, const ILParams &params);

		/**
		* Clear the pre-computed discrete Gaussian samples.
		*/
		static void DestroyPreComputedSamples() {
			m_dggSamples.clear();
		}

	private:

		// stores either coefficient or evaluation representation
		BigBinaryVector *m_values;

		// 0 for coefficient and 1 for evaluation format
		Format m_format;

		// noise norm associated with this vector - to be defined later
		// BigBinaryInteger m_norm;

		// reference to the parameters for ideal lattices
		ILParams m_params;

		// static variable to store pre-computed samples
		static std::vector<ILVector2n> m_dggSamples;

		// static variable to store the sample size for each set of ILParams
		static const usint m_sampleSize = SAMPLE_SIZE;

		// gets a random discrete Gaussian polynomial
		const ILVector2n GetPrecomputedVector(const ILParams &params);

	};

	// overloaded operators for ILVector2n
	//PREV1

	/**
	* Addition operator overload.  Performs an addition in the ring.
	*
	* @param &a the first parameter.
	* @param &b the first parameter.
	*
	* @return The result of addition in the ring.
	*/
	inline lbcrypto::ILVector2n operator+(const lbcrypto::ILVector2n &a, const lbcrypto::BigBinaryInteger &b) { return a.Plus(b); }

	/**
	* Subtraction operator overload.  Performs a subtraction in the ring.
	*
	* @param &a the first parameter.
	* @param &b the first parameter.
	*
	* @return The result of subtraction in the ring.
	*/
	inline lbcrypto::ILVector2n operator-(const lbcrypto::ILVector2n &a, const lbcrypto::BigBinaryInteger &b) { return a.Minus(b); }
	//PREV1

	/**
	* Multiplication operator overload.  Performs a multiplication in the ring.
	*
	* @param &a the first parameter.
	* @param &b the first parameter.
	*
	* @return The result of multiplication in the ring.
	*/
	inline lbcrypto::ILVector2n operator*(const lbcrypto::BigBinaryInteger &b, const lbcrypto::ILVector2n &a) { return a.Times(b); }

	/**
	* Division operator overload.  Performs an division in the ring.
	*
	* @param &a the first parameter.
	* @param &b the first parameter.
	*
	* @return The result of division in the ring.
	*/
	inline lbcrypto::ILVector2n operator/(const lbcrypto::ILVector2n &a, const lbcrypto::BigBinaryInteger &b) { return a.DividedBy(b); }
	//PREV1

	/**
	* Addition operator overload.  Performs an addition in the ring.
	*
	* @param &a the first parameter.
	* @param &b the first parameter.
	*
	* @return The result of addition in the ring.
	*/
	inline lbcrypto::ILVector2n operator+(const lbcrypto::ILVector2n &a, const lbcrypto::ILVector2n &b) { return a.Plus(b); }

	/**
	* Subtraction operator overload.  Performs a subtraction in the ring.
	*
	* @param &a the first parameter.
	* @param &b the first parameter.
	*
	* @return The result of subtraction in the ring.
	*/
	inline lbcrypto::ILVector2n operator-(const lbcrypto::ILVector2n &a, const lbcrypto::ILVector2n &b) { return a.Minus(b); }
	//PREV1

	/**
	* Multiplication operator overload.  Performs a multiplication in the ring.
	*
	* @param &a the first parameter.
	* @param &b the first parameter.
	*
	* @return The result of multiplication in the ring.
	*/
	inline lbcrypto::ILVector2n operator*(const lbcrypto::ILVector2n &a, const lbcrypto::ILVector2n &b) { return a.Times(b); }

	/**
	* Division operator overload.  Performs an division in the ring.
	*
	* @param &a the first parameter.
	* @param &b the first parameter.
	*
	* @return The result of division in the ring.
	*/
	inline lbcrypto::ILVector2n operator/(const lbcrypto::ILVector2n &a, const lbcrypto::ILVector2n &b) { return a.DividedBy(b); }

	// ideal lattice in the double-CRT representation

	/**
	* @brief Ideal lattice in the double-CRT representation.  This is not fully implemented and is currently only stubs.
	*/
	class ILVectorArray2n : public ILElement
	{
	public:

		// CONSTRUCTORS

		// copy constructor
		/*
		* Copy constructor.
		*
		* @param &element the copied element.
		*/
		ILVectorArray2n(const ILVectorArray2n &element);

		// construct using an array in either Coefficient (0) or CRT format (1)
		/*
		* Construct using an array in either Coefficient (0) or CRT format (1).
		*
		* @param params the input parameters.
		* @param &levels the levels.
		*/
		ILVectorArray2n(const ILDCRTParams& params, std::vector<ILVector2n> &levels, Format format);
		/*
		* Construct using an array in either Coefficient (0) or CRT format (1).
		*
		* @param element the input parameter to build ILVectorArray2n from one vector for double-CRT representation.
		*/
		ILVectorArray2n(ILVector2n element, const ILDCRTParams& params, Format format);
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

		ILDCRTParams &GetParams() const;

		// Set accessors

		/**
		* Set method of the values.
		*
		* @param values is the set of values of the vector.
		*/
		void SetValues(std::vector<ILVector2n>& values);

		// SCALAR OPERATIONS

		// addition operation	
		/*
		* Scalar addition - add an element to all entries.
		*
		* @param &element is the element to add entry-wise.
		* @return is the return of the addition operation.
		*/
		//		ILVectorArray2n& Plus(const BigBinaryInteger &element) const;

		// subtraction operation
		/*
		* Scalar subtraction - subtract an element to all entries.
		*
		* @param &element is the element to subtract entry-wise.
		* @return is the return value of the minus operation.
		*/
		//		ILVectorArray2n& Minus(const BigBinaryInteger &element) const;

		

		// division operation
		/*
		* Scalar division - divide an element to all entries.
		*
		* @param &element is the element to divide entry-wise.
		* @return is the return value of the division operation.
		*/
		//		ILVectorArray2n& DividedBy(const BigBinaryInteger &element) const;

		// modulo operation
		/*
		* Modulus - perform a modulus operation.
		*
		* @param modulus is the modulus to use.
		* @return is the return value of the modulus.
		*/
		//		ILVectorArray2n& Mod(const BigBinaryInteger & modulus) const;

		// VECTOR OPERATIONS

		// equality operation
		/*
		* Determines if two vectors are equal.
		*
		* @param &element is the element to test equality with.
		* @return is the Boolean representation of equality.
		*/
		//		bool Equal(const ILVectorArray2n &element) const;

		// addition operation
		/*
		* Performs an addition operation and returns the result.
		*
		* @param &element is the element to add with.
		* @return is the result of the addition.
		*/
		//		ILVectorArray2n& Plus(const ILVectorArray2n &element) const;

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

		BigBinaryInteger CalculateInterpolationSum(std::vector<std::vector<BigBinaryInteger>> vectorOfvectors, usint index);

		/*
		Helper method for chinese remainder interpolatiom
		*/

		std::vector<std::vector<BigBinaryInteger>> BuildChineseRemainderInterpolationVector(std::vector<std::vector<BigBinaryInteger>> vectorOfvectors);

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


		/*
		Helper method for chinese remainder interpolatiom
		*/

		BigBinaryInteger CalculateChineseRemainderInterpolationModuluForIndex(usint i);

		/**
		*This function returns the interpolated vectors
		*/

	    ILVector2n InterpolateIlArrayVector2n();

	    /*
		*This function is a helper function that applies a modulus to all IlVector2n's so they don't wrap their respective modulus
		*/
	
	void ChangeModuliOfIlVectorsToMatchDBLCRT();

	/*
	*helper function for chinese remainder interpolation
	*/
	std::vector<BigBinaryInteger> BuildChineseRemainderInterpolationVectorForRow(usint i);

			/*This function takes in a row and a vector of vector of BigBinaryIntegers and calculates the sum of each
			row, module the value set by the CRI formula*/
			/*This method calculates the value for CRI*/
	BigBinaryInteger CalculatInterpolateModulu(BigBinaryInteger value, usint index);

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

	// overloaded operators for ILVectorArray2n

	/*
	* Addition operator overload.  Performs an addition in the ring.
	*
	* @param &a the first parameter.
	* @param &b the first parameter.
	*
	* @return The result of addition in the ring.
	*/
	//	inline lbcrypto::ILVectorArray2n operator+(const lbcrypto::ILVectorArray2n &a, const lbcrypto::BigBinaryInteger &b) { return a.Plus(b); }

	/*
	* Subtraction operator overload.  Performs an subtraction in the ring.
	*
	* @param &a the first parameter.
	* @param &b the first parameter.
	*
	* @return The result of subtraction in the ring.
	*/
	//	inline lbcrypto::ILVectorArray2n operator-(const lbcrypto::ILVectorArray2n &a, const lbcrypto::BigBinaryInteger &b) { return a.Minus(b); }

	/*
	* Multiplication operator overload.  Performs a multiplication in the ring.
	*
	* @param &a the first parameter.
	* @param &b the first parameter.
	*
	* @return The result of multiplication in the ring.
	*/
	//	inline lbcrypto::ILVectorArray2n operator*(const lbcrypto::ILVectorArray2n &a, const lbcrypto::BigBinaryInteger &b) { return a.Times(b); }

	/*
	* Division operator overload.  Performs a division in the ring.
	*
	* @param &a the first parameter.
	* @param &b the first parameter.
	*
	* @return The result of division in the ring.
	*/
	//	inline lbcrypto::ILVectorArray2n operator/(const lbcrypto::ILVectorArray2n &a, const lbcrypto::BigBinaryInteger &b) { return a.DividedBy(b); }

	/*
	* Addition operator overload.  Performs an addition in the ring.
	*
	* @param &a the first parameter.
	* @param &b the first parameter.
	*
	* @return The result of addition in the ring.
	*/
	//	inline lbcrypto::ILVectorArray2n operator+(const lbcrypto::ILVectorArray2n &a, const lbcrypto::ILVectorArray2n &b) { return a.Plus(b); }

	/*
	* Subtraction operator overload.  Performs a subtraction in the ring.
	*
	* @param &a the first parameter.
	* @param &b the first parameter.
	*
	* @return The result of subtraction in the ring.
	*/
	//	inline lbcrypto::ILVectorArray2n operator-(const lbcrypto::ILVectorArray2n &a, const lbcrypto::ILVectorArray2n &b) { return a.Minus(b); }

	/*
	* Multiplication operator overload.  Performs a multiplication in the ring.
	*
	* @param &a the first parameter.
	* @param &b the first parameter.
	*
	* @return The result of multiplication in the ring.
	*/
	//	inline lbcrypto::ILVectorArray2n operator*(const lbcrypto::ILVectorArray2n &a, const lbcrypto::ILVectorArray2n &b) { return a.Times(b); }

	/*
	* Division operator overload.  Performs an division in the ring.
	*
	* @param &a the first parameter.
	* @param &b the first parameter.
	*
	* @return The result of division in the ring.
	*/
	//	inline lbcrypto::ILVectorArray2n operator/(const lbcrypto::ILVectorArray2n &a, const lbcrypto::ILVectorArray2n &b) { return a.DividedBy(b); }

} // namespace lbcrypto ends

#endif
