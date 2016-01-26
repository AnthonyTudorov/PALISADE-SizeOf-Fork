
#include <cstddef>

#include "benchmark/benchmark.h"

#if __cplusplus >= 201103L

//#warning C++11 or greater detected. 
void BM_empty(benchmark::State& state) {
    while (state.KeepRunning()) {
        volatile std::size_t x = state.iterations();
        ((void)x);
    }
}
BENCHMARK(BM_empty);

template <class T, class U>
void BM_template(benchmark::State& state) {
    BM_empty(state);
}
BENCHMARK_TEMPLATE(BM_template, int, long);

template <class T>
void BM_template(benchmark::State& state) {
    BM_empty(state);
}
BENCHMARK_TEMPLATE(BM_template, long);
BENCHMARK_TEMPLATE(BM_template, int);
BENCHMARK_TEMPLATE(BM_template, long, int);

BENCHMARK_MAIN()
#else
//#warning C++03 detected
void BM_empty(benchmark::State& state) {
    while (state.KeepRunning()) {
        volatile std::size_t x = state.iterations();
        ((void)x);
    }
}
BENCHMARK(BM_empty);

template <class T, class U>
void BM_template2(benchmark::State& state) {
    BM_empty(state);
}
BENCHMARK_TEMPLATE2(BM_template2, int, long);

template <class T>
void BM_template1(benchmark::State& state) {
    BM_empty(state);
}
BENCHMARK_TEMPLATE(BM_template1, long);
BENCHMARK_TEMPLATE1(BM_template1, int);

BENCHMARK_MAIN()
#endif
