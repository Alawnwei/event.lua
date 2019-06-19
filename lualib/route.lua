local protocol = require "protocol"
local co_core = require "co.core"

local event = require "event"
local import = require "import"

local _M = {}


function _M.dispatch(file,method,...)
	return import.dispatch(file,method,...)
end

function _M.dispatch_client(source,message_id,data,size)
	local reader = protocol.reader[message_id] 
	if not reader then
		event.error(string.format("no such id:%d proto:%s ",message_id,name))
		return
	end
	

	monitor.report_input(protocol,message_id,size)

	-- co_core.start()
	reader(data,size)
	-- local diff = co_core.stop()
	-- monitor.report_diff("protocol",message_id,diff)
end


return _M
