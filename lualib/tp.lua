local event = require "event"
local import = require "import"
local tp_core = require "tp.core"

local _M = {}

local _session_callback = {}

local _pipe
local _pipe_fd

local _tp_main
local _tp_child

function _M.send(file,method,args)
	_tp_main:push(0,table.tostring({file = file,method = method,args = args}))
end

function _M.call(file,method,args,func)
	local session = event.gen_session()
	_tp_main:push(session,table.tostring({file = file,method = method,args = args}))
	if func then
		_session_callback[session] = func
		return
	end
	local ok,result = event.wait(session)
	if not ok then
		error(result)
	end
	return result
end

function _M.create(count,boot_param)
	if not _pipe then
		_pipe,_pipe_fd = event.pipe(function (pipe,source,session,data,size)
			local message = table.decode(data,size)
			assert(message.ret == true)

			if _session_callback[session] then
				if message.args then
					_session_callback[session](message.args)
				end
			else
				if message.args then
					event.wakeup(session,true,message.args)
				else
					event.wakeup(session,false,message.err)
				end
			end
		end)
	end
	_tp_main = tp_core.create(_pipe_fd,count,boot_param)
	return _tp_main
end

function _M.dispatch(tp_ud)
	_tp_child = tp_ud
	_tp_child:dispatch(function (session,data,size)
		local message = table.decode(data,size)
		if message.ret then
			if _session_callback[session] then
				if message.args then
					_session_callback[session](message.args)
				end
			else
				if message.args then
					event.wakeup(session,true,message.args)
				else
					event.wakeup(session,false,message.err)
				end
			end
		else
			event.fork(function ()
				local ok,result = xpcall(import.dispatch,debug.traceback,message.file,message.method,message.args)
				if session == 0 then
					if not ok then
						event.error(result)
					end
					return
				end

				if not ok then
					_tp_child:send(session,table.tostring({ret = true,err = result}))
				else
					_tp_child:send(session,table.tostring({ret = true,args = result}))
				end
			end)
		end
	end)
end



return _M