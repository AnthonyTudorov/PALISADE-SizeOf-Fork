BMDIR=bin/benchmark
# take benchmark snapshot

###if [ $# -ne 1 ]
###then
	###echo Usage is $0 filename-to-store-snapshot
	###exit 1
###fi

###if [ -e $1 ]
###then
	###echo Sorry, that file already exists
	###exit 1
###fi

smallbmargs="--benchmark_report_aggregates_only=true --benchmark_format=csv"
largebmargs="--benchmark_repetitions=20 --benchmark_report_aggregates_only=true --benchmark_format=csv"

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

