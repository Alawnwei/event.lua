
set -avx

echo "input number:"
read num
fuck=5
case $num in
1|4|$fuck)
echo "select 1"
;;
2)
echo "select 2"
;;
*)
echo "other"
;;
esac