
local event = require "event"
local channel = require "channel"
local helper = require "helper"
local redis = require "redis"
local util = require "util"
local logger = require "logger"
local profiler = require "profiler"


local ctx = profiler.start(2,0)

local _M = {}

function _M.test4()
	local function test5()
		local b = 1
	local c = 2
	local d = 3
	local e = 4

	end
	local b = 1
	local c = 2
	for i = 1,10 do
		test5()
	end
	local d = 3
	local e = 4
end

function test3()
	local b = 1
	local c = 2
	_M.test4()
	local d = 3
	local e = 4
	
end

local function test2()
	local b = 1
	local c = 2
	test3()
	local d = 3
	local e = 4
end


local function test1()
	local a = 1
	local b = 2
	test2()
	local c = 3
end

event.fork(function ()
	while true do
		for i = 1,1024 do
			test1()
		end
		event.sleep(0.01)
	end
end)
event.fork(function ()
	while true do
		for i = 1,1024 do
			test1()
		end
		event.sleep(0.01)
	end
end)


event.timer(5,function (timer)
	timer:cancel()
	profiler.stop(ctx)
end)
