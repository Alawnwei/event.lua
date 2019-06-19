

until [ $# -eq 0 ]
do
echo "第一个参数为: $1 参数个数为: $#"
shift
shift
done



#位置参数左移
#1 2 3 4
#2 3 4
#3 4
#4