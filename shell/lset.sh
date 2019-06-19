


#set 设置shell行为
#-v 显示shell所读取的输入值

#+<参数> 　取消某个set曾启动的参数。


# set -v

# echo "set -v"

# read num
# echo $num

# set +v

# #-x 执行指令后，会先显示该指令及所下的参数。
# #
# set -x
# echo "set -v"

# read num
# echo $num

# set +x

# #-h 　自动记录函数的所在位置。
# set -h
# for i
# do
# 	echo $i
# done

read num
set -- $num
#把$num 分别传给各个参数
echo $1
echo $2
echo $@
echo $#

read fuck
set -- "$fuck"
#把fuck的值作为一个整体参递
echo $1
echo $2
echo $@
echo $#