
backends="2 4 6 7"

if [ "$1" != "" ];
then
	backends=$1
else
	make clean
fi
	
echo "****************************"
echo Building backends $1 for coverage
echo "****************************"

for i in $backends
do
	BINDIR=bin/backend-${i}-cov
	echo "****************************"
	echo Building MATHBACKEND $i
	echo "****************************"

	touch src/core/lib/math/backend.h

	make -j8  BINDIR=$BINDIR BACKEND=$i COVERAGE=yes all >/dev/null 2>&1
	if [ $? -eq 0 ];
	then
		echo "****************************"
		echo BUILT
		echo "****************************"
	else
		echo " ******** build for MATHBACKEND $i failed!!!"
	fi
done
