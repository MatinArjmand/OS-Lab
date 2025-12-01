gcc process.c -o process
if [ $? -ne 0 ]; then
    echo "compile error!"
    exit 1
fi    
echo

gcc thread.c -o thread -lpthread
if [ $? -ne 0 ]; then
    echo "compile error!"
    exit 1
fi
echo


echo "=======  Performance Test  ======="
echo

echo "results of process :"
/usr/bin/time -v ./process > /dev/null
echo "----------------------------------------------------"
echo

echo "results of thread :"
/usr/bin/time -v ./thread > /dev/null
echo "------------------------------------------------"
echo