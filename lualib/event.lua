local event_core = require "ev.core"
local co_core = require "co.core"

local _event

local _co_pool = {}
local _co_wait = {}

local _session = 1
local _main_co = coroutine.running()

local EV_ERROR = 0
local EV_TIMEOUT = 1
local EV_ACCEPT = 2
local EV_CONNECT = 3
local EV_DATA = 4

local _listener_ctx = setmetatable({},{__mode = "k"})
local _channel_ctx = setmetatable({},{__mode = "k"})
local _timer_ctx = setmetatable({},{__mode = "k"})
local _udp_ctx = setmetatable({},{__mode = "k"})
local _pipe_ctx = setmetatable({},{__mode = "k"})
local _gate_ctx = setmetatable({},{__mode = "k"})

local _channel_base
local _stream_base

local co_running = coroutine.running
local co_yield = coroutine.yield
local co_resume = coroutine.resume

local tinsert = table.insert
local tremove = table.remove
local tunpack = table.unpack

local ipairs = ipairs
local xpcall = xpcall
local traceback = debug.traceback
local assert = assert
local tostring = tostring

local _M = {}

local CO_STATE = {
	EXIT = 1,
	WAIT = 2	
}

local function co_create(func)
	local co = tremove(_co_pool)
	if co == nil then
		co = coroutine.create(function(...)
			func(...)
			while true do
				func = nil
				_co_pool[#_co_pool+1] = co
				func = co_yield(CO_STATE.EXIT)
				func(co_yield())
			end
		end)
	else
		co_resume(co, func)
	end
	return co
end

local function co_monitor(co,ok,state,session)
	if ok then
		if state == CO_STATE.WAIT then
			_co_wait[session] = co
		else
			assert(state == CO_STATE.EXIT)
		end
	else
		_M.error(traceback(co,tostring(state)))
	end
end

local function create_channel(channel_class,channel_buff,addr)
	local channel_obj
	if channel_class then
		channel_obj = channel_class:new(channel_buff,addr)
	else
		if not _channel_base then
			_channel_base = require "channel"
		end
		channel_obj = _channel_base:new(channel_buff,addr)
	end
	channel_obj:init()
	_channel_ctx[channel_buff] = channel_obj
	return channel_obj
end

local function resolve_addr(addr)
	local result = {}
	local start,over = addr:find("tcp://")
	if not start then
		start,over = addr:find("ipc://")
		if not start then
			return
		end
		local file = addr:sub(over+1)
		result.file = file
	else
		local ip,port = string.match(addr:sub(over+1),"(.+):(%d+)")
		result.ip = ip
		result.port = port
	end
	return result
end

function _M.listen(addr,header,callback,channel_class,multi)
	local listener
	local addr_form = resolve_addr(addr)
	if not addr_form then
		return false,string.format("error addr:%s",addr)
	end
	local listener,reason = _event:listen(header,multi or false,addr_form)

	if not listener then
		return false,reason
	end
	_listener_ctx[listener] = {callback = callback,channel_class = channel_class}
	return listener
end

function _M.connect(addr,header,sync,channel_class)
	local addr_form = resolve_addr(addr)
	if not addr_form then
		return false,string.format("error addr:%s",addr)
	end
	
	if sync then
		local channel_buff,reason = _event:connect(header,0,addr_form)
		if not channel_buff then
			return false,reason
		end
		return create_channel(channel_class,channel_buff,addr)
	end

	if co_running() == _main_co then
		error("cannot async connect in main co")
	end

	local session = _M.gen_session()

	local ok,reason  = _event:connect(header,session,addr_form)
	if not ok then
		return false,reason
	end
	local ok,channel_buff = _M.wait(session)
	if not ok then
		return ok,channel_buff
	end

	return create_channel(channel_class,channel_buff,addr)
end

function _M.bind(fd,channel_class)
	local channel_buff = _event:bind(fd)
	return create_channel(channel_class,channel_buff)
end

function _M.sleep(ti)
	local session = _M.gen_session()
	local timer = _event:timer(ti)
	_timer_ctx[timer]= session
	_M.wait(session)
end

function _M.timer(ti,callback)
	local timer = _event:timer(ti,ti)
	_timer_ctx[timer]= callback
	return timer
end

function _M.udp(size,callback,ip,port)
	local udp_session,err = _event:udp(size,callback,ip,port)
	if udp_session then
		_udp_ctx[udp_session] = true
	end
	return udp_session,err
end

function _M.pipe(func)
	local pipe,fd = _event:pipe(func)
	if pipe then
		_pipe_ctx[pipe] = fd
	end
	return pipe,fd
end

function _M.gate(max)
	local gate = _event:gate(max)
	if gate then
		_gate_ctx[gate] = true
	end
	return gate
end

function _M.dns(host,func)
	return _event:dns_resolve(host,func)
end

function _M.http_request(func)
	return _event:http_request(func)
end

function _M.run_process(cmd,line)
    local FILE = assert(io.popen(cmd))
    if not _stream_base then
    	_stream_base = require "stream"
    end
    local ch = _M.bind(FILE:fd(),_stream_base)
    local result
    if line then
    	result = ch:wait_lines()
    else
    	result = ch:wait()
    end
    FILE:close()
    return result
end

function _M.fork(func,...)
	local co = co_create(func)
	co_monitor(co,co_resume(co,...))
end

function _M.wakeup(session,...)
	local co = _co_wait[session]
	_co_wait[session] = nil
	if co then
		co_monitor(co,co_resume(co,...))
	else
		_M.error(string.format("error wakeup:session:%s not found",session))
	end
end

function _M.wait(session)
	local co = co_running()
	if co == _main_co then
		error("cannot wait in main co,wait op should run in fork")
	end
	return co_yield(CO_STATE.WAIT,session)
end

function _M.mutex()
	local current_thread
	local ref = 0
	local thread_queue = {}
	local thread_session = {}

	local function xpcall_ret(ok, ...)
		ref = ref - 1
		if ref == 0 then
			current_thread = tremove(thread_queue,1)
			if current_thread then
				local session = thread_session[current_thread]
				_M.timer(0,function (timer)
					timer:cancel()
					_M.wakeup(session)
				end)
			end
		end
		assert(ok, (...))
		return ...
	end

	return function(f, ...)
		local thread = coroutine.running()
		if current_thread and current_thread ~= thread then
			tinsert(thread_queue, thread)
			local session = _M.gen_session()
			thread_session[thread] = session
			_M.wait(session)
			assert(ref == 0)	-- current_thread == thread
		end
		current_thread = thread

		ref = ref + 1
		return xpcall_ret(xpcall(f, traceback, ...))
	end
end

function _M.gen_session()
	if _session >= math.maxinteger then
		_session = 1
	end
	local session = _session
	_session = _session + 1
	return session
end

function _M.error(...)
	print(...)
end

function _M.dispatch()
	local code = _event:dispatch()
	
	for timer in pairs(_timer_ctx) do
		if timer:alive() then
			timer:cancel()
		end
	end

	for listener in pairs(_listener_ctx) do
		if listener:alive() then
			listener:close()
		end
	end

	for channel_buff in pairs(_channel_ctx) do
		if channel_buff:alive() then
			channel_buff:close(true)
		end
	end

	for udp_session in pairs(_udp_ctx) do
		if udp_session:alive() then
			udp_session:destroy()
		end
	end

	for pipe in pairs(_pipe_ctx) do
		if pipe:alive() then
			pipe:release()
		end
	end

	for gate in pairs(_gate_ctx) do
		gate:release()
	end
	
	_M.release()
	return code
end

function _M.clean()
	_co_pool = {}
	_event:clean()
end

function _M.breakout(reason)
	print(reason)
	_event:breakout()
end

function _M.now()
	return _event:now()
end

local EV = {}

EV[EV_TIMEOUT] = function (timer)
	local info = _timer_ctx[timer]
	if type(info) == "number" then
		_timer_ctx[timer] = nil
		_M.wakeup(info)
	else
		info(timer)
	end
end

EV[EV_ACCEPT] = function (listener,channel_buff,addr)
	local info = _listener_ctx[listener]
	local channel_obj = create_channel(info.channel_class,channel_buff,addr)
	info.callback(listener,channel_obj)
end

EV[EV_CONNECT] = function (...)
	_M.wakeup(...)
end

EV[EV_DATA] = function (channel_buff,data,size)
	local channel = _channel_ctx[channel_buff]
	channel:data(data,size)
end

EV[EV_ERROR] = function (channel_buff)
	local channel = _channel_ctx[channel_buff]
	channel:disconnect()
end

local function event_dispatch(ev,...)
	local ev_func = EV[ev]
	if not ev_func then
		_M.error(string.format("no such ev:%d",ev))
		return
	end
	local ok,err = xpcall(ev_func,traceback,...)
	if not ok then
		_M.error(err)
	end
end

function _M.prepare()
	_event = event_core.new(event_dispatch)
end

function _M.release()
	_event:release()
end

return _M
