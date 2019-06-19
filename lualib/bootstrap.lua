
package.path = string.format("%s;%s",package.path,"./lualib/?.lua;./script/?.lua")
package.cpath = string.format("%s;%s",package.cpath,"./.libs/?.so")

require "lfs"
local event = require "event"
local util = require "util"
local dump = require "dump.core"
local serialize = require "serialize.core"
local import = require "import"
local model = require "model"
local debugger = require "debugger"
local helper = require "helper"
local worker = require "worker"
local tp = require "tp"
local protocol = require "protocol"

table.print = util.dump
table.encode = serialize.pack
table.decode = serialize.unpack
table.tostring = serialize.tostring
-- table.encode = dump.pack
-- table.decode = dump.unpack
-- table.tostring = dump.tostring

string.split = util.split
string.copy = util.clone_string

_G.MODEL_BINDER = model.registerBinder
_G.MODEL_VALUE = model.registerValue
_G.tostring = util.tostring
_G.import = import.import
_G.debugger = debugger
_G.debugger_ctx = {}

import.import "module.object"

_G.env = {}
local FILE = assert(io.open("./.env","r"))
assert(load(FILE:read("*a"),"env","text",_G.env))()

local args = {...}
local boot_type = args[1]
local name = args[2]

local func,err = loadfile(string.format("./script/%s.lua",name),"text",_G)
if not func then
	error(err)
end

local list = name:split("/")
env.path = name
env.name = list[#list]
env.tid = util.thread_id()
env.command = string.format("%s@%07d",env.name,env.serverId)

util.thread_name(env.command)

event.prepare()

if boot_type == 1 then
	local _G_protect = {}
	function _G_protect.__newindex(self,k,v)
		rawset(_G,k,v)
		print(string.format("%s:%s add to _G",k,v))
	end
	setmetatable(_G,_G_protect)

	if env.heap_profiler ~= nil then
		helper.heap.start(string.format("%s.%d",env.heap_profiler,env.tid))
	end

	if env.cpu_profiler ~= nil then
		helper.cpu.start(string.format("%s.%d",env.cpu_profiler,env.tid))
	end
elseif boot_type == 2 then
	worker.dispatch(args[#args])
elseif boot_type == 3 then
	tp.dispatch(args[#args])
end


local ok,err = xpcall(func,debug.traceback,table.unpack(args,3))
if not ok then
	error(err)
end

collectgarbage("collect")
local lua_mem = collectgarbage("count")
event.error(string.format("thread:%d start,command:%s,lua mem:%fkb,c mem:%fkb",env.tid,env.command,lua_mem,helper.allocated()/1024))

if boot_type == 1 then
	event.dispatch()

	worker.join()

	if env.heap_profiler ~= nil then
		helper.heap.dump("stop")
		helper.heap.stop()
	end

	if env.cpu_profiler ~= nil then
		helper.cpu.stop()
	end
else
	event.release()
end


