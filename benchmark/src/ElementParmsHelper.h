shared_ptr<ILParams> parm_8_30( new ILParams(8, BigBinaryInteger("536871001"), BigBinaryInteger("322299632")) );
shared_ptr<ILParams> parm_8_60( new ILParams(8, BigBinaryInteger("576460752303423649"), BigBinaryInteger("168966263632512486")) );
shared_ptr<ILParams> parm_8_100( new ILParams(8, BigBinaryInteger("633825300114114700748351603497"), BigBinaryInteger("346785002350981855777149989030")) );
shared_ptr<ILParams> parm_16_30( new ILParams(16, BigBinaryInteger("536871089"), BigBinaryInteger("453444631")) );
shared_ptr<ILParams> parm_16_60( new ILParams(16, BigBinaryInteger("576460752303423649"), BigBinaryInteger("445222158767550178")) );
shared_ptr<ILParams> parm_16_100( new ILParams(16, BigBinaryInteger("633825300114114700748351603777"), BigBinaryInteger("158526154030753428971875578867")) );
shared_ptr<ILParams> parm_32_30( new ILParams(32, BigBinaryInteger("536871233"), BigBinaryInteger("270599745")) );
shared_ptr<ILParams> parm_32_60( new ILParams(32, BigBinaryInteger("576460752303423649"), BigBinaryInteger("189737790501446066")) );
shared_ptr<ILParams> parm_32_100( new ILParams(32, BigBinaryInteger("633825300114114700748351603777"), BigBinaryInteger("548092891331783023532813998227")) );
shared_ptr<ILParams> parm_64_30( new ILParams(64, BigBinaryInteger("536871233"), BigBinaryInteger("268585022")) );
shared_ptr<ILParams> parm_64_60( new ILParams(64, BigBinaryInteger("576460752303426241"), BigBinaryInteger("42065371588604318")) );
shared_ptr<ILParams> parm_64_100( new ILParams(64, BigBinaryInteger("633825300114114700748351603777"), BigBinaryInteger("112238319142051274089073361078")) );
shared_ptr<ILParams> parm_128_30( new ILParams(128, BigBinaryInteger("536872321"), BigBinaryInteger("536138614")) );
shared_ptr<ILParams> parm_128_60( new ILParams(128, BigBinaryInteger("576460752303430529"), BigBinaryInteger("285497987503397922")) );
shared_ptr<ILParams> parm_128_100( new ILParams(128, BigBinaryInteger("633825300114114700748351608961"), BigBinaryInteger("285911309737765344820779602428")) );
shared_ptr<ILParams> parm_256_30( new ILParams(256, BigBinaryInteger("536874497"), BigBinaryInteger("20558990")) );
shared_ptr<ILParams> parm_256_60( new ILParams(256, BigBinaryInteger("576460752303434497"), BigBinaryInteger("156313576129429466")) );
shared_ptr<ILParams> parm_256_100( new ILParams(256, BigBinaryInteger("633825300114114700748351611393"), BigBinaryInteger("357592901114840193907394379371")) );
shared_ptr<ILParams> parm_512_30( new ILParams(512, BigBinaryInteger("536874497"), BigBinaryInteger("2031030")) );
shared_ptr<ILParams> parm_512_60( new ILParams(512, BigBinaryInteger("576460752303436801"), BigBinaryInteger("22441747419598564")) );
shared_ptr<ILParams> parm_512_100( new ILParams(512, BigBinaryInteger("633825300114114700748351611393"), BigBinaryInteger("390541910591016109011030492388")) );
shared_ptr<ILParams> parm_1024_30( new ILParams(1024, BigBinaryInteger("536881153"), BigBinaryInteger("295184143")) );
shared_ptr<ILParams> parm_1024_60( new ILParams(1024, BigBinaryInteger("576460752303436801"), BigBinaryInteger("358469952161664325")) );
shared_ptr<ILParams> parm_1024_100( new ILParams(1024, BigBinaryInteger("633825300114114700748351634433"), BigBinaryInteger("90487631240944978775994429419")) );
shared_ptr<ILParams> parm_2048_30( new ILParams(2048, BigBinaryInteger("536881153"), BigBinaryInteger("27661536")) );
shared_ptr<ILParams> parm_2048_60( new ILParams(2048, BigBinaryInteger("576460752303439873"), BigBinaryInteger("227218586376681578")) );
shared_ptr<ILParams> parm_2048_100( new ILParams(2048, BigBinaryInteger("633825300114114700748351660033"), BigBinaryInteger("538656593806121444004599743100")) );
shared_ptr<ILParams> parm_4096_30( new ILParams(4096, BigBinaryInteger("536903681"), BigBinaryInteger("316679111")) );
shared_ptr<ILParams> parm_4096_60( new ILParams(4096, BigBinaryInteger("576460752303439873"), BigBinaryInteger("37211485026155169")) );
shared_ptr<ILParams> parm_4096_100( new ILParams(4096, BigBinaryInteger("633825300114114700748351660033"), BigBinaryInteger("136971478753003267070551058410")) );
shared_ptr<ILParams> parm_8192_30( new ILParams(8192, BigBinaryInteger("536903681"), BigBinaryInteger("242542334")) );
shared_ptr<ILParams> parm_8192_60( new ILParams(8192, BigBinaryInteger("576460752303439873"), BigBinaryInteger("478250159403020681")) );
shared_ptr<ILParams> parm_8192_100( new ILParams(8192, BigBinaryInteger("633825300114114700748351660033"), BigBinaryInteger("522089389445617342265930548090")) );

shared_ptr<ILParams> parmArray[] = {
parm_8_30,
parm_8_60,
parm_8_100,
parm_16_30,
parm_16_60,
parm_16_100,
parm_32_30,
parm_32_60,
parm_32_100,
parm_64_30,
parm_64_60,
parm_64_100,
parm_128_30,
parm_128_60,
parm_128_100,
parm_256_30,
parm_256_60,
parm_256_100,
parm_512_30,
parm_512_60,
parm_512_100,
parm_1024_30,
parm_1024_60,
parm_1024_100,
parm_2048_30,
parm_2048_60,
parm_2048_100,
parm_4096_30,
parm_4096_60,
parm_4096_100,
parm_8192_30,
parm_8192_60,
parm_8192_100,
};

#define DO_PARM_BENCHMARK(X) \
BENCHMARK(X)->Unit(benchmark::kMicrosecond)->ArgName("parm_8_30")->Arg(0); \
BENCHMARK(X)->Unit(benchmark::kMicrosecond)->ArgName("parm_8_60")->Arg(1); \
BENCHMARK(X)->Unit(benchmark::kMicrosecond)->ArgName("parm_8_100")->Arg(2); \
BENCHMARK(X)->Unit(benchmark::kMicrosecond)->ArgName("parm_16_30")->Arg(3); \
BENCHMARK(X)->Unit(benchmark::kMicrosecond)->ArgName("parm_16_60")->Arg(4); \
BENCHMARK(X)->Unit(benchmark::kMicrosecond)->ArgName("parm_16_100")->Arg(5); \
BENCHMARK(X)->Unit(benchmark::kMicrosecond)->ArgName("parm_32_30")->Arg(6); \
BENCHMARK(X)->Unit(benchmark::kMicrosecond)->ArgName("parm_32_60")->Arg(7); \
BENCHMARK(X)->Unit(benchmark::kMicrosecond)->ArgName("parm_32_100")->Arg(8); \
BENCHMARK(X)->Unit(benchmark::kMicrosecond)->ArgName("parm_64_30")->Arg(9); \
BENCHMARK(X)->Unit(benchmark::kMicrosecond)->ArgName("parm_64_60")->Arg(10); \
BENCHMARK(X)->Unit(benchmark::kMicrosecond)->ArgName("parm_64_100")->Arg(11); \
BENCHMARK(X)->Unit(benchmark::kMicrosecond)->ArgName("parm_128_30")->Arg(12); \
BENCHMARK(X)->Unit(benchmark::kMicrosecond)->ArgName("parm_128_60")->Arg(13); \
BENCHMARK(X)->Unit(benchmark::kMicrosecond)->ArgName("parm_128_100")->Arg(14); \
BENCHMARK(X)->Unit(benchmark::kMicrosecond)->ArgName("parm_256_30")->Arg(15); \
BENCHMARK(X)->Unit(benchmark::kMicrosecond)->ArgName("parm_256_60")->Arg(16); \
BENCHMARK(X)->Unit(benchmark::kMicrosecond)->ArgName("parm_256_100")->Arg(17); \
BENCHMARK(X)->Unit(benchmark::kMicrosecond)->ArgName("parm_512_30")->Arg(18); \
BENCHMARK(X)->Unit(benchmark::kMicrosecond)->ArgName("parm_512_60")->Arg(19); \
BENCHMARK(X)->Unit(benchmark::kMicrosecond)->ArgName("parm_512_100")->Arg(20); \
BENCHMARK(X)->Unit(benchmark::kMicrosecond)->ArgName("parm_1024_30")->Arg(21); \
BENCHMARK(X)->Unit(benchmark::kMicrosecond)->ArgName("parm_1024_60")->Arg(22); \
BENCHMARK(X)->Unit(benchmark::kMicrosecond)->ArgName("parm_1024_100")->Arg(23); \
BENCHMARK(X)->Unit(benchmark::kMicrosecond)->ArgName("parm_2048_30")->Arg(24); \
BENCHMARK(X)->Unit(benchmark::kMicrosecond)->ArgName("parm_2048_60")->Arg(25); \
BENCHMARK(X)->Unit(benchmark::kMicrosecond)->ArgName("parm_2048_100")->Arg(26); \
BENCHMARK(X)->Unit(benchmark::kMicrosecond)->ArgName("parm_4096_30")->Arg(27); \
BENCHMARK(X)->Unit(benchmark::kMicrosecond)->ArgName("parm_4096_60")->Arg(28); \
BENCHMARK(X)->Unit(benchmark::kMicrosecond)->ArgName("parm_4096_100")->Arg(29); \
BENCHMARK(X)->Unit(benchmark::kMicrosecond)->ArgName("parm_8192_30")->Arg(30); \
BENCHMARK(X)->Unit(benchmark::kMicrosecond)->ArgName("parm_8192_60")->Arg(31); \
BENCHMARK(X)->Unit(benchmark::kMicrosecond)->ArgName("parm_8192_100")->Arg(32); \


#define DO_PARM_BENCHMARK_TEMPLATE(X,Y) \
BENCHMARK_TEMPLATE(X,Y)->Unit(benchmark::kMicrosecond)->ArgName("parm_8_30")->Arg(0); \
BENCHMARK_TEMPLATE(X,Y)->Unit(benchmark::kMicrosecond)->ArgName("parm_8_60")->Arg(1); \
BENCHMARK_TEMPLATE(X,Y)->Unit(benchmark::kMicrosecond)->ArgName("parm_8_100")->Arg(2); \
BENCHMARK_TEMPLATE(X,Y)->Unit(benchmark::kMicrosecond)->ArgName("parm_16_30")->Arg(3); \
BENCHMARK_TEMPLATE(X,Y)->Unit(benchmark::kMicrosecond)->ArgName("parm_16_60")->Arg(4); \
BENCHMARK_TEMPLATE(X,Y)->Unit(benchmark::kMicrosecond)->ArgName("parm_16_100")->Arg(5); \
BENCHMARK_TEMPLATE(X,Y)->Unit(benchmark::kMicrosecond)->ArgName("parm_32_30")->Arg(6); \
BENCHMARK_TEMPLATE(X,Y)->Unit(benchmark::kMicrosecond)->ArgName("parm_32_60")->Arg(7); \
BENCHMARK_TEMPLATE(X,Y)->Unit(benchmark::kMicrosecond)->ArgName("parm_32_100")->Arg(8); \
BENCHMARK_TEMPLATE(X,Y)->Unit(benchmark::kMicrosecond)->ArgName("parm_64_30")->Arg(9); \
BENCHMARK_TEMPLATE(X,Y)->Unit(benchmark::kMicrosecond)->ArgName("parm_64_60")->Arg(10); \
BENCHMARK_TEMPLATE(X,Y)->Unit(benchmark::kMicrosecond)->ArgName("parm_64_100")->Arg(11); \
BENCHMARK_TEMPLATE(X,Y)->Unit(benchmark::kMicrosecond)->ArgName("parm_128_30")->Arg(12); \
BENCHMARK_TEMPLATE(X,Y)->Unit(benchmark::kMicrosecond)->ArgName("parm_128_60")->Arg(13); \
BENCHMARK_TEMPLATE(X,Y)->Unit(benchmark::kMicrosecond)->ArgName("parm_128_100")->Arg(14); \
BENCHMARK_TEMPLATE(X,Y)->Unit(benchmark::kMicrosecond)->ArgName("parm_256_30")->Arg(15); \
BENCHMARK_TEMPLATE(X,Y)->Unit(benchmark::kMicrosecond)->ArgName("parm_256_60")->Arg(16); \
BENCHMARK_TEMPLATE(X,Y)->Unit(benchmark::kMicrosecond)->ArgName("parm_256_100")->Arg(17); \
BENCHMARK_TEMPLATE(X,Y)->Unit(benchmark::kMicrosecond)->ArgName("parm_512_30")->Arg(18); \
BENCHMARK_TEMPLATE(X,Y)->Unit(benchmark::kMicrosecond)->ArgName("parm_512_60")->Arg(19); \
BENCHMARK_TEMPLATE(X,Y)->Unit(benchmark::kMicrosecond)->ArgName("parm_512_100")->Arg(20); \
BENCHMARK_TEMPLATE(X,Y)->Unit(benchmark::kMicrosecond)->ArgName("parm_1024_30")->Arg(21); \
BENCHMARK_TEMPLATE(X,Y)->Unit(benchmark::kMicrosecond)->ArgName("parm_1024_60")->Arg(22); \
BENCHMARK_TEMPLATE(X,Y)->Unit(benchmark::kMicrosecond)->ArgName("parm_1024_100")->Arg(23); \
BENCHMARK_TEMPLATE(X,Y)->Unit(benchmark::kMicrosecond)->ArgName("parm_2048_30")->Arg(24); \
BENCHMARK_TEMPLATE(X,Y)->Unit(benchmark::kMicrosecond)->ArgName("parm_2048_60")->Arg(25); \
BENCHMARK_TEMPLATE(X,Y)->Unit(benchmark::kMicrosecond)->ArgName("parm_2048_100")->Arg(26); \
BENCHMARK_TEMPLATE(X,Y)->Unit(benchmark::kMicrosecond)->ArgName("parm_4096_30")->Arg(27); \
BENCHMARK_TEMPLATE(X,Y)->Unit(benchmark::kMicrosecond)->ArgName("parm_4096_60")->Arg(28); \
BENCHMARK_TEMPLATE(X,Y)->Unit(benchmark::kMicrosecond)->ArgName("parm_4096_100")->Arg(29); \
BENCHMARK_TEMPLATE(X,Y)->Unit(benchmark::kMicrosecond)->ArgName("parm_8192_30")->Arg(30); \
BENCHMARK_TEMPLATE(X,Y)->Unit(benchmark::kMicrosecond)->ArgName("parm_8192_60")->Arg(31); \
BENCHMARK_TEMPLATE(X,Y)->Unit(benchmark::kMicrosecond)->ArgName("parm_8192_100")->Arg(32); \


