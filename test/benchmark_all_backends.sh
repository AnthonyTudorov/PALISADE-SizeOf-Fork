smallbmargs="--benchmark_report_aggregates_only=true --benchmark_format=csv"
largebmargs="--benchmark_repetitions=20 --benchmark_report_aggregates_only=true --benchmark_format=csv"

for i in 2 4 6 7
do
	(
	BINDIR=bin/backend-$i
	BMDIR=$BINDIR/benchmark

	export DYLD_LIBRARY_PATH=bin/backend-$i/lib:$LD_LIBRARY_PATH
	export LD_LIBRARY_PATH=bin/backend-$i/lib:$LD_LIBRARY_PATH
	export PATH=bin/backend-$i/lib:$LD_LIBRARY_PATH

	echo "****************************"
	echo Benchmarking MATHBACKEND $i
	echo "****************************"


	for bm in BBIMath BBVMath NbTheory Lattice 
	do
		echo $bm:
		$BMDIR/${bm}* ${smallbmargs} 
	done

	for bm in Encoding Crypto SHE
	do
		echo $bm:
		$BMDIR/${bm}* ${largebmargs} 
	done

	echo "****************************"
	echo DONE
	echo "****************************"
done
