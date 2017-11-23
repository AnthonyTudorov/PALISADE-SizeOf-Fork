
backends="2 4 6 7"

if [ "$1" != "" ];
then
	backends=$1
else
	make clean
fi

echo "****************************"
echo Building backends $backends
echo "****************************"

for i in $backends
do
	echo "****************************"
	echo Building MATHBACKEND $i
	echo "****************************"

	touch src/core/lib/math/backend.h

	make -j16  BINDIR=bin/backend-$i BACKEND=$i all benchmark >/dev/null 2>&1
	if [ $? -eq 0 ];
	then
		echo "****************************"
		echo BUILT
		echo "****************************"
	else
		echo " ******** build for MATHBACKEND $i failed!!!"
	fi
done
