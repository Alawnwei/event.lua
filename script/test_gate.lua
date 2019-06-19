local event = require "event"
local helper = require "helper"
local client_countor = 0
local function client_accept(cid,addr)
	-- print("client_accept",cid,addr)
	client_countor = client_countor + 1
	if client_countor >= 1000 then
		
		-- print("client_countor",client_countor)
	end
end

local function client_close(cid)
	-- print("client_close",cid)
	client_countor = client_countor - 1
	if client_countor == 0 then
		print("client_countor",client_countor)
	end
end

local countor = 0
local function client_data(cid,message_id,data,size)
	countor = countor + 1
	-- print("client_data",cid,countor)
	-- -- table.print(table.decode(data,size))
	if countor % 100000 == 0 then
		print("client_data",cid,countor)
	end
end

event.fork(function ()
	gate = event.gate(5000)
	gate:set_callback(client_accept,client_close,client_data)
	local port,reason = gate:start("0.0.0.0",1989)
	if not port then
		event.breakout(string.format("%s %s",env.name,reason))
		os.exit(1)
	end
end)


event.fork(function ()
	event.sleep(20)
end)
