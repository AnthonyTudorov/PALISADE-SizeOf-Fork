//
// Created by matt on 12/10/15.
//

#include "DiscreteGaussianGenerator.h"
#include "nbtheory.h"
#include "backend.h"

namespace lbcrypto {

    DiscreteGaussianGenerator::DiscreteGaussianGenerator (const BigBinaryInteger & modulus, const sint std) : ModulusDistributionGenerator (modulus){
        this->m_std = std;

        InitiateVals();

        //srand (time(NULL));
        /*
        for(usint i=0;i<m_vals.size();i++)
            std::cout<<m_vals[i]<<std::endl;

        std::cout<<std::endl;
        */
    }

    void DiscreteGaussianGenerator::setStd (const sint std) {
        this->m_std = std;
    }

    sint DiscreteGaussianGenerator::getStd () const {
        return this->m_std;
    }

    void DiscreteGaussianGenerator::Initialize () {

        InitiateVals();

    }

// BigBinaryInteger DiscreteGaussianGenerator::GetModulus(){
// 	return m_modulus;
// }

//void DiscreteGaussianGenerator::SetModulus(BigBinaryInteger &modulus){
//
//	m_modulus = modulus;
//
//}

    void DiscreteGaussianGenerator::InitiateVals () {

        const double pi = 3.1415926;
        //weightDiscreteGaussian
        double acc = 0.00000001;

        int fin = ceil(sqrt(2 * pi) * m_std * sqrt(-1 * log(acc) / pi));

        double cusum = 1.0;

        for (sint x = 1; x <= fin; x++) {

            cusum = cusum + 2 * exp(-pi * (x * x) / (m_std * m_std * 2 * pi));

        }

        m_a = 1 / cusum;

        fin = ceil(sqrt(-2 * (m_std * m_std) * log(acc)));
        double temp;

        for (sint i = 1; i <= fin; i++) {
            temp = m_a * exp((double) -((double) (i * i) / (2 * m_std * m_std)));
            m_vals.push_back(temp);
        }

        /*
        for(usint i=0;i<m_vals.size();i++){
            std::cout<<m_vals[i]<<std::endl;
        }
        std::cout<<std::endl<<std::endl;
        */

        //take cumulative summation
        for (usint i = 1; i < m_vals.size(); i++) {
            m_vals[i] += m_vals[i - 1];
        }

        //std::cout<<m_a<<std::endl;

        /*
        for(usint i=0;i<m_vals.size();i++){
            std::cout<<m_vals[i]<<std::endl;
        }
        std::cout<<std::endl<<std::endl;
        */
    }

    schar *DiscreteGaussianGenerator::GenerateCharVector (usint size) const {

        //std::default_random_engine generator;
        //std::uniform_real_distribution<double> distribution(0.0,1.0);
        //generator.seed(time(NULL));
        double val = 0, seed;
        schar *ans = new schar[size];
        for (usint i = 0; i < size; i++) {
            //generator.seed(time(NULL));
            seed = ((double) std::rand() / (RAND_MAX)) - 0.5;
            //std::cout<<seed<<std::endl;
            //seed = distribution(generator)-0.5;
            if (std::abs(seed) <= m_a / 2)
                val = 0;
            else if (seed > 0)
                val = FindInVector(m_vals, (std::abs(seed) - m_a / 2));
            else
                val = -(int) FindInVector(m_vals, (std::abs(seed) - m_a / 2));

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


    BigBinaryVector DiscreteGaussianGenerator::DiscreteGaussianPositiveGenerator(usint vectorLength,const BigBinaryInteger &modValue){

        BigBinaryVector ans(vectorLength);
        ans.SetModulus(modValue);


        for(usint i=0;i<vectorLength;i++){
            ans.SetValAtIndex(i,UintToBigBinaryInteger(std::rand()%8));
        }

        return ans;
    }

    BigBinaryInteger DiscreteGaussianGenerator::GenerateInteger(const BigBinaryInteger &modulus) {

        return std::move(*(new BigBinaryInteger()));
    }

    BigBinaryVector DiscreteGaussianGenerator::GenerateVector(usint size, const BigBinaryInteger &modulus) {


        //BigBinaryVector ans(DiscreteGaussianGenerator::DiscreteGaussianPositiveGenerator(size,this->m_modulus));

        //return ans;


        schar* result_vector = GenerateCharVector(size);

        BigBinaryVector ans(size);
        ans.SetModulus(modulus);

        for(usint i=0;i<size;i++){
            if( result_vector[i]<0 ){
                result_vector[i] *= -1;
                ans.SetValAtIndex(i,UintToBigBinaryInteger(result_vector[i]));
                ans.SetValAtIndex(i, modulus-ans.GetValAtIndex(i) );
            }
            else{
                ans.SetValAtIndex(i,UintToBigBinaryInteger(result_vector[i]));
            }
        }

        delete []result_vector;

        return ans;


    }

}
