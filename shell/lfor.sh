

#getopt
#ab:c::(-a不接参数,-b必接参数,-c可加可不加)
#--后的参数不通过getopt解析
#getopt 要用$@
#如果有混合的话要getopt -o xxx -l xxx "$@" 
#getopt 带-o或都-l时,必须用--,指定后面为解析参数
#getopt如果不带-o或-l时,--加上后面成为一整个参数,不参与解析
args=`getopt -o ab:c:: -l ab,ac:  "$@"`
echo $args

#把参数传个整个命令行参数
set -- ${args}

#等于for i in "$@"
for i
do
	echo $i
done

# #把参数传给第一个命令行参数
# set -- "${args}"




