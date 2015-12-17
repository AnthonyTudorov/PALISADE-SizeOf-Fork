//
// Created by matt on 12/10/15.
//

#ifndef LBCRYPTO_MATH_DISCRETEGAUSSIANGENERATOR_H_
#define LBCRYPTO_MATH_DISCRETEGAUSSIANGENERATOR_H_

#include "backend.h"
#include "DiscreteDistributionGenerator.h"

namespace lbcrypto {
    /**
     * @brief The class for Discrete Gaussion Distribution generator.
     */
    class DiscreteGaussianGenerator : DiscreteDistributionGenerator {
    public:
        /**
         * @brief         Basic constructor for specifying distribution parameter and modulus.
         * @param modulus The modulus to use to generate discrete values.
         * @param std     The standard deviation for this Gaussian Distribution.
         */
        DiscreteGaussianGenerator (const BigBinaryInteger & modulus, const sint std);

        /**
         * @brief Initializes the generator.
         */
        void Initialize ();

        /**
         * @brief  Returns the standard deviation of the generator.
         * @return The analytically obtained standard deviation of the generator.
         */
        sint getStd () const;

        /**
         * @brief     Sets the standard deviation of the generator.
         * @param std The analytic standard deviation of the generator.
         */
        void setStd (const sint std);

        /**
         * @brief      Returns a generated char vector.
         * @param size The number of values to return.
         * @return     A pointer to an array of schar values generated with the distribution.
         */
        schar * GenerateCharVector (usint size) const;

        /**
         * @brief  Returns a generated integer.
         * @return A random value within this Discrete Gaussian Distribution.
         */
        BigBinaryInteger generateInteger ();

        /**
         * @brief           Generates a vector of random values within this Discrete Gaussian Distribution.
         *
         * @param  size     The number of values to return.
         * @return          The vector of values within this Discrete Gaussian Distribution.
         */
        BigBinaryVector generateVector (usint size);

        /**
         * @brief               Generates a vector of random, positive values within this Discrete Gaussian Distribution.
         * @param  vectorLength The number of values to return.
         * @param  &modValue    The number of values to return.
         * @return              The vector of positive values within this Discrete Gaussian Distribution.
         */
        static BigBinaryVector DiscreteGaussianPositiveGenerator (usint vectorLength, const BigBinaryInteger &modValue);

    private:
        usint FindInVector (const std::vector<double> &S, double search) const;

        //Gyana to add precomputation methods and data members
        //all parameters are set as int because it is assumed that they are used for generating "small" polynomials only
        double m_a;

        void InitiateVals ();

        std::vector<double> m_vals;

        /**
         * The standard deviation of the distribution.
         */
        sint m_std;
    };
}

#endif // LBCRYPTO_MATH_DISCRETEGAUSSIANGENERATOR_H_
