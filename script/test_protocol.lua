local event = require "event"
local util = require "util"
local protocol = require "protocol"

-- protocol.parse("./protocol/other.protocol")
protocol.parse("./protocol/new.protocol")

-- protocol.dumpfile("./tmp/")

-- local test_protocol = {
-- 	arg1 = 1,
-- 	arglist = {1,2,3},
-- 	cmds = {{id = 1,argnum = {6,6,6},cmd = "msg"}}
-- }

-- local count = 1024 * 1024

--  local id,str =protocol.encode.c2s_command(test_protocol)
--  print(id,string.len(str))
--  local name,message = protocol.decode[id](str)
--  table.print(message,name)
 -- local now = util.time()
 -- local str
 -- for i = 1,count do
 -- 	str =protocol.encode.c2s_command(test_protocol)
 -- end
 -- print("protocol encode",util.time() - now,string.len(str))

 -- local now = util.time()
 -- for i = 1,count do
 -- 	protocol.decode.c2s_command(str)
 -- end
 -- print("protocol decode",util.time() - now,string.len(str))

-- local inner = {
-- 	file = "test.tes1t",
-- 	fields = {
-- 		[1] = {type = 0,name = "test0",array = true},
-- 		[2] = {type = 3,name = "test1",array = false},
-- 	}
-- }
-- local pto = {
-- 	file = "test.test",
-- 	fields = {
-- 		[1] = {type = 0,name = "test0",array = true},
-- 		[2] = {type = 3,name = "test1",array = false},
-- 	}
-- }

-- protocol.import("c2s_pto",pto)

-- local id,str = protocol.encode.c2s_pto({test0 = {3,1},test1 = "mrq"})
--  print(id,string.len(str))
--   local name,message = protocol.decode[id](str)
--  table.print(message,name)

-- protocol.dump()

local pos = {}

for i = 1,65536 do
	table.insert(pos,i)
	end

local info = {
	userUid = 1001,
	userName = "mrq",
	level = 100,
	pos = pos,
	created = true,
	version = 123,
	bornTime = 1.1123,
	itemInfoList = {{itemId = 101,amount = 1},{itemId = 102,amount = 2}}
}
local id,str = protocol.encode.sAgentEnter(info)
 -- print(id,string.len(str))

 local name,message = protocol.decode[id](str)
 table.print(message,name)