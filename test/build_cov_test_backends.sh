if [ "$1" = "force" ];
then
	make clean
fi

echo "****************************"
echo Building all backends
echo "****************************"

for i in 2 4 6 7
do
	BINDIR=bin/backend-${i}-cov
	echo "****************************"
	echo Building MATHBACKEND $i
	echo "****************************"
	if [ "$1" = "force" ];
	then
		touch src/core/lib/math/backend.h
	fi
	make -j8  BINDIR=$BINDIR BACKEND=$i COVERAGE=yes all #>/dev/null 2>&1
	if [ $? -eq 0 ];
	then
		echo "****************************"
		echo BUILT
		echo "****************************"
	else
		echo " ******** build for MATHBACKEND $i failed!!!"
	fi
done
