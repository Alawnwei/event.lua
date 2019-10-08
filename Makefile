LUA_PATH ?= ./3rd/lua
LUA_INC ?= ./3rd/lua/src
LUA_STATIC_LIB ?= ./3rd/lua/src/liblua.a

LIBEV_PATH ?= 3rd/libev
LIBEV_INC ?= 3rd/libev
LIBEV_SHARE_LIB ?= 3rd/libev/.libs/libev.so

TC_PATH ?= 3rd/gperftools
TC_INC ?= 3rd/gperftools/src/gperftools
TC_STATIC_LIB= 3rd/gperftools/.libs/libtcmalloc_and_profiler.a

LIBCURL_PATH ?= 3rd/curl
LIBCURL_INC ?= 3rd/curl/include
LIBCURL_SHARE_LIB = 3rd/curl/lib/.libs/libcurl.so

LIBARES_PATH ?= 3rd/c-ares
LIBARES_INC ?= 3rd/c-ares
LIBARES_SHARE_LIB = 3rd/c-ares/.libs/libcares.so

EFENCE_PATH ?= ./3rd/electric-fence
EFENCE_STATIC_LIB ?= ./3rd/electric-fence/libefence.a


# $(warning $(SIGAR_LUA_SRC))
# $(shell find $(SIGAR_LUA_INC) -maxdepth 3 -type d) 
# $(foreach dir,$(SIGAR_LUA_DIR),$(wildcard $(dir)/*.c))
# find . -type f -exec dos2unix {} \;
# makefile自动找到第一个目标去执行
# .PHONY 声明变量是命令而非目标文件,在目标没有依赖，而又存在目标文件时

LUA_CLIB_PATH ?= ./.libs
LUA_CLIB_SRC ?= ./luaclib
LUA_CLIB = ev worker tp dump serialize redis bson mongo util lfs cjson http ikcp simpleaoi toweraoi linkaoi pathfinder nav protocolparser protocolcore trie filter co luasql snapshot 

CONVERT_PATH ?= ./luaclib/convert

CONVERT_SRC ?= $(wildcard $(CONVERT_PATH)/milo/*.cpp)
CONVERT_OBJ = $(patsubst %.c,%.o,$(patsubst %.cpp,%.o,$(CONVERT_SRC)))

DOUBLE_CONVERSION_SRC ?= $(wildcard $(CONVERT_PATH)/double-conversion/*.cc)
DOUBLE_CONVERSION_OBJ = $(patsubst %.cc,%.o,$(DOUBLE_CONVERSION_SRC)) 

MAIN_PATH ?= ./src
MAIN_SRC ?= $(wildcard $(MAIN_PATH)/*.c)
MAIN_SRC +=  ./luaclib/socket/socket_tcp.c ./luaclib/socket/socket_util.c ./luaclib/socket/ring_buffer.c ./luaclib/common/encrypt.c ./luaclib/common/object_container.c
MAIN_OBJ = $(patsubst %.c,%.o,$(patsubst %.cc,%.o,$(MAIN_SRC)))

TARGET ?= event

CC=gcc
CFLAGS=-g -Wall -fno-omit-frame-pointer $(DEFINE)

LDFLAGS=-lrt -lm -ldl -lpthread -lssl -lunwind -lstdc++
STATIC_LIBS=$(LUA_STATIC_LIB) $(TC_STATIC_LIB) 
DEFINE=-DUSE_TC
SHARED=-fPIC --shared

.PHONY : all clean debug libc efence

all : \
	$(LIBEV_SHARE_LIB) \
	$(LIBCURL_SHARE_LIB) \
	$(LIBARES_SHARE_LIB) \
	$(STATIC_LIBS) \
	$(TARGET) \
	$(foreach v, $(LUA_CLIB), $(LUA_CLIB_PATH)/$(v).so) 
	cp $(TARGET) $(TARGET).raw && strip $(TARGET).raw

$(LUA_STATIC_LIB) :
	cd $(LUA_PATH) && make linux

$(EFENCE_STATIC_LIB) :
	cd $(EFENCE_PATH) && make

$(TC_STATIC_LIB) :
	cd $(TC_PATH) && sh autogen.sh && ./configure && make

$(LIBEV_SHARE_LIB) :
	cd $(LIBEV_PATH) && ./configure && make

$(LIBCURL_SHARE_LIB) :
	cd $(LIBCURL_PATH) && ./configure && make

$(LIBARES_SHARE_LIB) :
	cd $(LIBARES_PATH) && ./configure && make

$(LUA_CLIB_PATH):
	mkdir $(LUA_CLIB_PATH)

$(CONVERT_PATH)/milo/%.o:$(CONVERT_PATH)/milo/%.cpp
	$(CC) $(CFLAGS) -fPIC -o $@ -c $<

$(CONVERT_PATH)/double-conversion/%.o:$(CONVERT_PATH)/double-conversion/%.cc
	$(CC) $(CFLAGS) -fPIC -o $@ -c $< -I$(CONVERT_PATH)

%.o:%.c
	$(CC) $(CFLAGS) -o $@ -c $< -I$(LUA_INC) -I$(TC_INC) -I$(LIBEV_INC) -Iluaclib

%.o:%.cc
	$(CC) $(CFLAGS) -o $@ -c $< -I$(LUA_INC) -I$(TC_INC) -I$(LIBEV_INC) -Iluaclib

debug :
	$(MAKE) $(ALL) CFLAGS="-g -Wall -Wno-unused-value -fno-omit-frame-pointer" TC_STATIC_LIB="3rd/gperftools/.libs/libtcmalloc_debug.a" LDFLAGS="-lrt -lm -ldl -lprofiler -lpthread -lssl -lstdc++"

leak :
	$(MAKE) $(ALL) CC=clang CFLAGS="-g -Wall -Wno-unused-value -fno-omit-frame-pointer -fsanitize=address -fsanitize=leak" DEFINE="" STATIC_LIBS="$(LUA_STATIC_LIB) $(LIBEVENT_STATIC_LIB)" LDFLAGS="-lrt -lm -ldl -lpthread -lssl -lstdc++"

libc :
	$(MAKE) $(ALL) DEFINE="" STATIC_LIBS="$(LUA_STATIC_LIB) $(LIBEVENT_STATIC_LIB)" LDFLAGS="-lrt -lm -ldl -lpthread -lssl -lstdc++"

efence :
	$(MAKE) $(ALL) DEFINE="" STATIC_LIBS="$(LUA_STATIC_LIB) $(LIBEVENT_STATIC_LIB) $(EFENCE_STATIC_LIB)" LDFLAGS="-lrt -lm -ldl -lpthread -lssl -lstdc++"

$(TARGET) : $(MAIN_OBJ) $(STATIC_LIBS) $(LIBEV_SHARE_LIB)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS) -I./$(LIBEV_INC) -Wl,-E

$(LUA_CLIB_PATH)/ev.so : $(LUA_CLIB_SRC)/lua-ev.c $(LUA_CLIB_SRC)/lua-gate.c $(LUA_CLIB_SRC)/common/common.c $(LUA_CLIB_SRC)/socket/gate.c $(LUA_CLIB_SRC)/common/encrypt.c $(LUA_CLIB_SRC)/socket/socket_tcp.c $(LUA_CLIB_SRC)/socket/socket_udp.c $(LUA_CLIB_SRC)/socket/socket_pipe.c $(LUA_CLIB_SRC)/socket/socket_util.c $(LUA_CLIB_SRC)/socket/socket_httpc.c $(LUA_CLIB_SRC)/socket/dns_resolver.c $(LUA_CLIB_SRC)/common/object_container.c $(LUA_CLIB_SRC)/common/string.c $(LUA_CLIB_SRC)/socket/ring_buffer.c $(LIBEV_SHARE_LIB) $(LIBCURL_SHARE_LIB) $(LIBARES_SHARE_LIB) | $(LUA_CLIB_PATH)
	$(CC) $(CFLAGS) -Wno-strict-aliasing $(SHARED) $^ -o $@ -I$(LUA_INC) -I$(LIBEV_INC) -I$(LUA_CLIB_SRC) -I$(LIBCURL_INC) -I$(LIBARES_INC) -I./3rd/klib

$(LUA_CLIB_PATH)/worker.so : $(LUA_CLIB_SRC)/lua-worker.c $(LUA_CLIB_SRC)/common/message_queue.c $(LUA_CLIB_SRC)/common/lock.c $(LUA_CLIB_SRC)/socket/socket_util.c | $(LUA_CLIB_PATH)
	$(CC) $(CFLAGS) $(SHARED) $^ -o $@ -I$(LUA_INC)

$(LUA_CLIB_PATH)/tp.so : $(LUA_CLIB_SRC)/lua-tp.c $(LUA_CLIB_SRC)/common/thread_pool.c $(LUA_CLIB_SRC)/common/lock.c $(LUA_CLIB_SRC)/socket/socket_util.c | $(LUA_CLIB_PATH)
	$(CC) $(CFLAGS) $(SHARED) $^ -o $@ -I$(LUA_INC)

$(LUA_CLIB_PATH)/dump.so : $(LUA_CLIB_SRC)/lua-dump.c ./3rd/lua-cjson/dtoa.c $(CONVERT_OBJ) | $(LUA_CLIB_PATH)
	$(CC) $(CFLAGS) -Wno-uninitialized $(SHARED) $^ -o $@ -I$(LUA_INC) -I$(CONVERT_PATH)

$(LUA_CLIB_PATH)/serialize.so : $(LUA_CLIB_SRC)/lua-serialize.c | $(LUA_CLIB_PATH)
	$(CC) $(CFLAGS) $(SHARED) $^ -o $@ -I$(LUA_INC)

$(LUA_CLIB_PATH)/redis.so : $(LUA_CLIB_SRC)/lua-redis.c $(CONVERT_OBJ) | $(LUA_CLIB_PATH)
	$(CC) $(CFLAGS) $(SHARED) $^ -o $@ -I$(LUA_INC) -I$(CONVERT_PATH)

$(LUA_CLIB_PATH)/bson.so : $(LUA_CLIB_SRC)/lua-bson.c | $(LUA_CLIB_PATH)
	$(CC) $(CFLAGS) $(SHARED) $^ -o $@ -I$(LUA_INC)

$(LUA_CLIB_PATH)/mongo.so : $(LUA_CLIB_SRC)/lua-mongo.c | $(LUA_CLIB_PATH)
	$(CC) $(CFLAGS) $(SHARED) $^ -o $@ -I$(LUA_INC)

$(LUA_CLIB_PATH)/util.so : $(LUA_CLIB_SRC)/lua-util.c ./3rd/klib/kstring.c $(LUA_CLIB_SRC)/profiler/size_of.c $(LUA_CLIB_SRC)/profiler/profiler.c $(LUA_CLIB_SRC)/profiler/hash_frame.c $(LUA_CLIB_SRC)/profiler/stack_hot.c $(LUA_CLIB_SRC)/common/common.c $(LUA_CLIB_SRC)/common/timeutil.c $(LUA_CLIB_SRC)/common/encrypt.c $(CONVERT_OBJ) $(DOUBLE_CONVERSION_OBJ) ./3rd/linenoise/linenoise.c | $(LUA_CLIB_PATH)
	$(CC) $(CFLAGS) -Wno-unused-value $(SHARED) $^ -o $@ -I$(LUA_INC) -I$(CONVERT_PATH) -I$(CONVERT_PATH)/ -I./3rd/linenoise -I./3rd/klib -I./3rd/lz4/lib -L./3rd/lz4/lib -llz4 -liconv

$(LUA_CLIB_PATH)/lfs.so : ./3rd/luafilesystem/src/lfs.c | $(LUA_CLIB_PATH)
	$(CC) $(CFLAGS) $(SHARED) $^ -o $@ -I$(LUA_INC)

$(LUA_CLIB_PATH)/cjson.so : $(filter-out ./3rd/lua-cjson/g_fmt.c ./3rd/lua-cjson/dtoa.c,$(foreach v, $(wildcard ./3rd/lua-cjson/*.c), $(v))) | $(LUA_CLIB_PATH)
	$(CC) $(CFLAGS) $(SHARED) $^ -o $@ -I$(LUA_INC)

$(LUA_CLIB_PATH)/http.so : $(LUA_CLIB_SRC)/lua-http-parser.c ./3rd/http-parser/http_parser.c $(LUA_CLIB_SRC)/common/string.c ./3rd/klib/kstring.c | $(LUA_CLIB_PATH)
	$(CC) $(CFLAGS) $(SHARED) $^ -o $@ -I$(LUA_INC) -I./3rd/http-parser -I./3rd/klib

$(LUA_CLIB_PATH)/ikcp.so : $(LUA_CLIB_SRC)/lua-ikcp.c $(LUA_CLIB_SRC)/socket/ikcp.c | $(LUA_CLIB_PATH)
	$(CC) $(CFLAGS) $(SHARED) $^ -o $@ -I$(LUA_INC)

$(LUA_CLIB_PATH)/simpleaoi.so : $(LUA_CLIB_SRC)/lua-simple-aoi.c $(LUA_CLIB_SRC)/aoi/simple/simple-aoi.c $(LUA_CLIB_SRC)/common/pool.c $(LUA_CLIB_SRC)/common/object_container.c | $(LUA_CLIB_PATH)
	$(CC) $(CFLAGS) $(SHARED) $^ -o $@ -I$(LUA_INC) -I$(LUA_CLIB_SRC)

$(LUA_CLIB_PATH)/toweraoi.so : $(LUA_CLIB_SRC)/lua-tower-aoi.c $(LUA_CLIB_SRC)/aoi/tower/tower-aoi.c $(LUA_CLIB_SRC)/aoi/tower/hash.c $(LUA_CLIB_SRC)/common/pool.c $(LUA_CLIB_SRC)/common/object_container.c | $(LUA_CLIB_PATH)
	$(CC) $(CFLAGS) $(SHARED) $^ -o $@ -I$(LUA_INC) -I$(LUA_CLIB_SRC) -I./3rd/klib

$(LUA_CLIB_PATH)/linkaoi.so : $(LUA_CLIB_SRC)/lua-link-aoi.c $(LUA_CLIB_SRC)/aoi/link/link-aoi.c $(LUA_CLIB_SRC)/aoi/link/hash_witness.c  | $(LUA_CLIB_PATH)
	$(CC) $(CFLAGS) $(SHARED) $^ -o $@ -I$(LUA_INC) -I./3rd/klib

$(LUA_CLIB_PATH)/pathfinder.so : $(LUA_CLIB_SRC)/lua-pathfinder.c $(LUA_CLIB_SRC)/pathfinder/tile/pathfinder.c $(LUA_CLIB_SRC)/common/minheap.c  | $(LUA_CLIB_PATH)
	$(CC) $(CFLAGS) $(SHARED) $^ -o $@ -I$(LUA_INC) -I$(LUA_CLIB_SRC)

$(LUA_CLIB_PATH)/nav.so : $(LUA_CLIB_SRC)/lua-nav.c $(LUA_CLIB_SRC)/pathfinder/nav/nav_loader.c $(LUA_CLIB_SRC)/pathfinder/nav/nav_finder.c $(LUA_CLIB_SRC)/pathfinder/nav/nav_tile.c $(LUA_CLIB_SRC)/common/minheap.c  | $(LUA_CLIB_PATH)
	$(CC) $(CFLAGS) $(SHARED) $^ -o $@  -I$(LUA_INC) -I$(LUA_CLIB_SRC)

$(LUA_CLIB_PATH)/protocolparser.so : $(LUA_CLIB_SRC)/lua-protocol-parser.c | $(LUA_CLIB_PATH)
	$(CC) $(CFLAGS) $(SHARED) $^ -o $@ -I$(LUA_INC)

$(LUA_CLIB_PATH)/protocolcore.so : $(LUA_CLIB_SRC)/lua-protocol.c | $(LUA_CLIB_PATH)
	$(CC) $(CFLAGS) $(SHARED) $^ -o $@ -I$(LUA_INC) -I./3rd/klib
	
$(LUA_CLIB_PATH)/trie.so : $(LUA_CLIB_SRC)/lua-trie.c | $(LUA_CLIB_PATH)
	$(CC) $(CFLAGS) $(SHARED) $^ -o $@ -I$(LUA_INC)	-I./3rd/klib

$(LUA_CLIB_PATH)/filter.so : $(LUA_CLIB_SRC)/lua-filter.c $(LUA_CLIB_SRC)/common/string.c ./3rd/klib/kstring.c | $(LUA_CLIB_PATH)
	$(CC) $(CFLAGS) $(SHARED) $^ -o $@ -I$(LUA_INC)	-I./3rd/klib

$(LUA_CLIB_PATH)/co.so : $(LUA_CLIB_SRC)/lua-co.c | $(LUA_CLIB_PATH)
	$(CC) $(CFLAGS) $(SHARED) $^ -o $@ -I$(LUA_INC)

$(LUA_CLIB_PATH)/luasql.so : ./3rd/luasql-mysql/src/luasql.c ./3rd/luasql-mysql/src/ls_mysql.c | $(LUA_CLIB_PATH)
	$(CC) $(CFLAGS) $(SHARED) $^ -o $@ -I$(LUA_INC) -I/usr/include/mysql -lmysqlclient

$(LUA_CLIB_PATH)/snapshot.so : $(LUA_CLIB_SRC)/lua-snapshot.c | $(LUA_CLIB_PATH)
	$(CC) $(CFLAGS) $(SHARED) $^ -o $@ -I$(LUA_INC)
	
clean :
	rm -rf $(TARGET) $(TARGET).raw
	rm -rf $(LUA_CLIB_PATH)
	rm -rf $(MAIN_OBJ)
	rm -rf luaclib/convert/milo/*.o
	rm -rf luaclib/convert/double-conversion/*.o

cleanall :
	make clean
	cd $(LUA_PATH) && make clean
	cd $(LIBEV_PATH) && make clean
	cd $(LIBCURL_PATH) && make clean
	cd $(LIBARES_PATH) && make clean
	# cd $(TC_PATH) && make distclean
	cd $(TC_PATH) && make clean
	cd $(EFENCE_PATH) && make clean
	
