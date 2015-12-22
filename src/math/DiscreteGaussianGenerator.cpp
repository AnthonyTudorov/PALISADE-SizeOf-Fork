//
// Created by matt on 12/10/15.
//

#include "DiscreteGaussianGenerator.h"
#include "nbtheory.h"
#include "backend.h"

namespace lbcrypto {

    DiscreteGaussianGenerator::DiscreteGaussianGenerator (const BigBinaryInteger & modulus, const sint std) : DiscreteDistributionGenerator (modulus) {
        this->std_ = std;
        InitiateVals();
    }

    void DiscreteGaussianGenerator::SetStd (const sint std) {
        this->std_ = std;
    }

    sint DiscreteGaussianGenerator::GetStd () const {
        return this->std_;
    }

    void DiscreteGaussianGenerator::Initialize () {
        InitiateVals();
    }

    void DiscreteGaussianGenerator::InitiateVals () {

        const double pi = 3.1415926;
        //weightDiscreteGaussian
        double acc = 0.00000001;

        int fin = (int)ceil(sqrt(2 * pi) * this->std_ * sqrt(-1 * log(acc) / pi));

        double cusum = 1.0;

        for (sint x = 1; x <= fin; x++) {

            cusum = cusum + 2 * exp(-pi * (x * x) / (this->std_ * this->std_ * 2 * pi));

        }

        m_a = 1 / cusum;

        fin = (int)ceil(sqrt(-2 * (this->std_ * this->std_) * log(acc)));
        double temp;

        for (sint i = 1; i <= fin; i++) {
            temp = m_a * exp(-((double) (i * i) / (2 * this->std_ * this->std_)));
            this->vals_.push_back(temp);
        }

        /*
        for(usint i=0;i<m_vals.size();i++){
            std::cout<<m_vals[i]<<std::endl;
        }
        std::cout<<std::endl<<std::endl;
        */

        // take cumulative summation
        for (usint i = 1; i < this->vals_.size(); i++) {
            this->vals_[i] += this->vals_[i - 1];
        }

        //std::cout<<m_a<<std::endl;

        /*
        for(usint i=0;i<m_vals.size();i++){
            std::cout<<m_vals[i]<<std::endl;
        }
        std::cout<<std::endl<<std::endl;
        */
    }

    schar * DiscreteGaussianGenerator::GenerateCharVector (usint size) const {

        //std::default_random_engine generator;
        //std::uniform_real_distribution<double> distribution(0.0,1.0);
        //generator.seed(time(NULL));
        double val = 0, seed;
        schar * ans = new schar[size];
        for (usint i = 0; i < size; i++) {
            //generator.seed(time(NULL));
            seed = ((double) std::rand() / (RAND_MAX)) - 0.5;
            //std::cout<<seed<<std::endl;
            //seed = distribution(generator)-0.5;
            if (std::abs(seed) <= m_a / 2) {
                val = 0;
            } else if (seed > 0) {
                val = FindInVector(this->vals_, (std::abs(seed) - m_a / 2));
            } else {
                val = - (int) FindInVector(this->vals_, (std::abs(seed) - m_a / 2));
            }
            ans[i] = val;
        }

        return ans;
    }

    usint DiscreteGaussianGenerator::FindInVector (const std::vector<double> &S, double search) const {
        for (usint i = 0; i < S.size(); i++) {
            if (S[i] >= search) {
                return i;
            }
        }
    }

    BigBinaryVector DiscreteGaussianGenerator::DiscreteGaussianPositiveGenerator(usint vectorLength, const BigBinaryInteger &modValue) {

        BigBinaryVector ans(vectorLength);
        ans.SetModulus(modValue);

        for (usint i = 0; i < vectorLength; i++) {
            ans.SetValAtIndex(i, UintToBigBinaryInteger(std::rand() % 8));
        }

        return ans;
    }

    BigBinaryInteger DiscreteGaussianGenerator::GenerateInteger() {
        return std::move(*(new BigBinaryInteger()));
    }

    BigBinaryVector DiscreteGaussianGenerator::GenerateVector(const usint size) {
        //BigBinaryVector ans(DiscreteGaussianGenerator::DiscreteGaussianPositiveGenerator(size,this->m_modulus));

        //return ans;
        schar* result_vector = GenerateCharVector(size);

        BigBinaryVector ans(size);
        ans.SetModulus(this->modulus_);

        for (usint i = 0; i < size; i++) {
            if (result_vector[i] < 0) {
                result_vector[i] *= -1;
                ans.SetValAtIndex(i, UintToBigBinaryInteger(result_vector[i]));
                ans.SetValAtIndex(i, this->modulus_ - ans.GetValAtIndex(i));
            } else {
                ans.SetValAtIndex(i, UintToBigBinaryInteger(result_vector[i]));
            }
        }

        delete []result_vector;

        return ans;


    }

} // namespace lbcrypto
