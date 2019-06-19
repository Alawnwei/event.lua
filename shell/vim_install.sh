#!/bin/bash

CURPATH=`pwd`
VIMRC=${CURPATH}/.vimrc

cd ~
if [ ! -d ./vim_asset ];then
	mkdir vim_asset
fi
cd ./vim_asset

if [ ! -d ./vim ];then
	git clone https://github.com/vim/vim.git
fi

if [ ! -d ./the_silver_searcher ];then
	git clone https://github.com/ggreer/the_silver_searcher.git
	cd the_silver_searcher
	./autogen.sh && ./configure && make
	sudo make install
	cd ..
	
fi

if [ ! -d ./ctags ];then 
	git clone https://github.com/universal-ctags/ctags.git
	cd ctags
	./autogen.sh && ./configure && make
	sudo make install
	cd ..
fi

if [ ! -f ./Python-2.7.5.tgz ];then
	wget https://www.python.org/ftp/python/2.7.5/Python-2.7.5.tgz
	tar zxvf Python-2.7.5.tgz
	cd Python-2.7.5 && ./configure --enable-shared && make
	sudo make install
	cd ..
fi

cd vim
./configure  --enable-pythoninterp=yes --with-python-config-dir=/usr/lib64/python2.7/config
sudo make
sudo make install
sudo cp /usr/local/bin/vim /usr/bin/vim

if [ ! -d ~/.vim ];then
	mkdir ~/.vim
fi

if [ ! -d ~/.vim/autoload ];then
	mkdir ~/.vim/autoload
fi

cd ~/.vim/autoload

if [ ! -d ./plug.vim ];then
	wget https://raw.githubusercontent.com/junegunn/vim-plug/master/plug.vim
fi


if [ ! -f ~/.vimrc ];then
	dos2unix ${VIMRC}
	cp ${VIMRC} ~/.vimrc
fi

