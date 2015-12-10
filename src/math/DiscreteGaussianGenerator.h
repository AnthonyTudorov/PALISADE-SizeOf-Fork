//
// Created by matt on 12/10/15.
//

#ifndef DISCRETE_GAUSSIAN_GENERATOR_H
#define DISCRETE_GAUSSIAN_GENERATOR_H

#include "backend.h"
#include "ModulusDistributionGenerator.h"

namespace lbcrypto {
/**
 * @brief The class for discrete Gaussion distribution generator
 */
    class DiscreteGaussianGenerator : ModulusDistributionGenerator {
    public:
        /**
         * Basic constructor.
         */
        DiscreteGaussianGenerator (); //srand(time(NULL)) is called here

        /**
         * Basic constructor for specifying distribution parameter and modulus.
         *
         * @param std is the distribution parameter.
         */
        DiscreteGaussianGenerator (sint std);

        /**
         * Destructor.
         */
        ~DiscreteGaussianGenerator ();

        /**
         * Initiate the generator
         */
        void Initialize ();

        //ACCESSORS

        //int GetMean() const;

        /**
         * Returns the standard deviation of the generator.
         *
         * @return the analytically obtained standard deviation of the generator.
         */
        sint GetStd () const;
        //int GetUpperBound() const;
        //void SetMean(int mean);

        /**
         * Sets the standard deviation of the generator.
         *
         * @param std the analytic standard deviation of the generator.
         */
        void SetStd (sint std);
        //void SetUpperBound(int upperBound);

        /*
         * Sets the modulus of the generator.
         *
         * @param &modulus the analytic standard deviation of the generator.
         */
        //void SetModulus(BigBinaryInteger &modulus);

        /**
         * Returns a generated char vector.
         *
         * @param size the number of values to return.
         * @return a pointer to an array of schar values generated with the distribution.
         */
        schar *GenerateCharVector (usint size) const;

        /**
         * Returns a generated integer.
         *
         * @return a generated integer.
         */
        BigBinaryInteger GenerateInteger (const BigBinaryInteger &modulus);

        /**
         * Returns a generated vector.
         *
         * @param size the number of values to return.
         * @param &modulus the modulus of the returned data.
         * @return vector of values generated with the distribution.
         */
        BigBinaryVector GenerateVector (usint size, const BigBinaryInteger &modulus);

        /**
         * Returns a generated vector.
         *
         * @param vectorLength the number of values to return.
         * @param &modValue the number of values to return.
         * @return vector of values generated with the distribution.
         */
        static BigBinaryVector DiscreteGaussianPositiveGenerator (usint vectorLength, const BigBinaryInteger &modValue);

    private:
        usint FindInVector (const std::vector<double> &S, double search) const;

        //Gyana to add precomputation methods and data members
        //all parameters are set as int because it is assumed that they are used for generating "small" polynomials only
//	int m_mean;
        float m_a;

        void InitiateVals ();

        std::vector<double> m_vals;
        sint m_std;
        //BigBinaryInteger m_modulus;
    };
}

#endif // DISCRETE_GAUSSIAN_GENERATOR_H
