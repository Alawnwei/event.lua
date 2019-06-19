local event = require "event"


local _M = {}

local function createTimer(interval,freq,inst,method,...)
	local args = {...}

	local __timer = rawget(inst,"__timer")
	if not __timer then
		__timer = {}
		rawset(inst,"__timer",__timer)
	end

	local timer = event.timer(interval,function ()
		if not freq then
			timer:cancel()
			__timer[timer] = nil
		end
		event.fork(inst[method],inst,table.unpack(args))
	end)
	__timer[timer] = true 
	return timer
end

function _M.callout(interval,inst,method,...)
	return createTimer(interval,true,inst,method,...)
end

function _M.calloutAfter(interval,inst,method,...)
	return createTimer(interval,false,inst,method,...)
end

function _M.removeTimer(inst,timer)
	local __timer = rawget(inst,"__timer")
	assert(__timer ~= nil)
	assert(__timer[timer],string.format("no such timer:%s",timer))
	timer:cancel()
	__timer[timer] = nil
end

function _M.removeAll(inst)
	local __timer = rawget(inst,"__timer")
	if not __timer then
		return
	end
	for timer in pairs(__timer) do
		timer:cancel()
	end
	rawset(inst,__timer,{})
end

return _M
