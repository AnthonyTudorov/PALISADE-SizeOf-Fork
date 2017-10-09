/**
 * @file trapdoor.h Provides the utility for sampling trapdoor lattices as described in https://eprint.iacr.org/2017/844.pdf
 * @author  TPOC: palisade@njit.edu
 *
 * @copyright Copyright (c) 2017, New Jersey Institute of Technology (NJIT)
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
 */

#ifndef LBCRYPTO_LATTICE_TRAPDOOR_H
#define LBCRYPTO_LATTICE_TRAPDOOR_H

#include "math/matrix.h"
#include "dgsampling.h"

namespace lbcrypto {

	typedef Matrix<Poly> RingMat;

/**
* @brief Class to store a lattice trapdoor pair generated using construction 1 in section 3.2 of https://eprint.iacr.org/2013/297.pdf
* This construction is based on the hardness of Ring-LWE problem 
*/
template <class Element>
class RLWETrapdoorPair {
public:
	// matrix of noise Elementnomials
	Matrix<Element> m_r;
	// matrix 
	Matrix<Element> m_e;

	RLWETrapdoorPair();
	RLWETrapdoorPair(const Matrix<Element> &r, const Matrix<Element> &e): m_r(r), m_e(e) {};
};

/**
* @brief Static class implementing lattice trapdoor construction in Algorithm 1 of https://eprint.iacr.org/2017/844.pdf
*/
template <class Element>
class RLWETrapdoorUtility
{
public:
	/**
	* Trapdoor generation method as described in Algorithm 1 of https://eprint.iacr.org/2017/844.pdf
	*
	* @param params ring element parameters
	* @param sttdev distribution parameter used in sampling noise polynomials of the trapdoor
	* @param base base of gadget matrix
	* @param bal flag for balanced (true) versus not-balanced (false) digit representation
	* @return the trapdoor pair including the public key (matrix of rings) and trapdoor itself
	*/
	static std::pair<Matrix<Element>, RLWETrapdoorPair<Element>> TrapdoorGen(shared_ptr<typename Element::Params> params, int stddev, int32_t base = 2, bool bal = false);

	/**
	* Gaussian sampling as described in Alogorithm 2 of https://eprint.iacr.org/2017/844.pdf
	*
	* @param n ring dimension
	* @param k matrix sample dimension; k = log2(q)/log2(base) + 2
	* @param &A public key of the trapdoor pair
	* @param &T trapdoor itself
	* @param &u syndrome vector where gaussian that Gaussian sampling is centered around
	* @param &dgg discrete Gaussian generator for integers
	* @param &dggLargeSigma discrete Gaussian generator for perturbation vector sampling (only used in Peikert's method)
	* @param base base of gadget matrix
	* @return the sampled vector (matrix)
	*/
	static Matrix<Element> GaussSamp(size_t n, size_t k, const Matrix<Element>& A, 
		const RLWETrapdoorPair<Element>& T, const Element &u, 
		typename Element::DggType &dgg, typename Element::DggType &dggLargeSigma, int32_t base = 2);

	/**
	* On-line stage of pre-image sampling (includes only G-sampling)
	*
	* @param n ring dimension
	* @param k matrix sample dimension; k = log2(q)/log2(base) + 2
	* @param &A public key of the trapdoor pair
	* @param &T trapdoor itself
	* @param &u syndrome vector where gaussian that Gaussian sampling is centered around
	* @param &dgg discrete Gaussian generator for integers
	* @param &perturbationVector perturbation vector generated during the offline stage
	* @param &base base for G-lattice
	* @return the sampled vector (matrix)
	*/
	static Matrix<Element> GaussSampOnline(size_t n, size_t k, const Matrix<Element>& A,
		const RLWETrapdoorPair<Element>& T, const Element &u, typename Element::DggType &dgg,
		 const shared_ptr<Matrix<Element>> perturbationVector, int32_t base = 2);

	/**
	* Offline stage of pre-image sampling (perturbation sampling)
	*
	* @param n ring dimension
	* @param k matrix sample dimension; k = logq + 2
	* @param &T trapdoor itself
	* @param &dgg discrete Gaussian generator for integers
	* @param &dggLargeSigma discrete Gaussian generator for perturbation vector sampling
	* @param &base base for G-lattice
	* @return the sampled vector (matrix)
	*/
	static shared_ptr<Matrix<Element>> GaussSampOffline(size_t n, size_t k,
		const RLWETrapdoorPair<Element>& T,typename Element::DggType &dgg, typename Element::DggType &dggLargeSigma, 
		int32_t base = 2);

	/**
	* New method for perturbation generation as described in Algorithm 4 of https://eprint.iacr.org/2017/844.pdf
	*
	*@param n ring dimension
	*@param s parameter Gaussian distribution
	*@param sigma standard deviation
	*@param &Tprime compact trapdoor matrix
	*@param &dgg discrete Gaussian generator for error sampling
	*@param &dggLargeSigma discrete Gaussian generator for perturbation vector sampling
	*@param *perturbationVector perturbation vector;output of the function
	*/
	static void ZSampleSigmaP(size_t n, double s, double sigma,
		const RLWETrapdoorPair<Element> &Tprime,
		const typename Element::DggType& dgg, const typename Element::DggType& dggLargeSigma,
		shared_ptr<Matrix<Element>> perturbationVector);

};

} //end namespace crypto
#endif
