local event = require "event"
local protocol = require "protocol"
local serverMgr = import "module.server_manager"


local modf = math.modf
local xpcall = xpcall
local pairs = pairs
local ipairs = ipairs

_gate = _gate

_sendGate = _sendGate

_serverInst = _serverInst

function __init__(self)

end

local function _onClientData(cid,messageId,data,size)
	local cid = cid * 100 + env.distId
	event.fork(_serverInst.onClientData,_serverInst,cid,messageId,data,size)
end

local function _onClientAccept(cid,addr)
	local cid = cid * 100 + env.distId
	local ok,err = xpcall(_serverInst.onClientEnter,debug.traceback,_serverInst,cid,addr)
	if not ok then
		event.error(err)
	end
end

local function _onClientClose(cid,reason)
	local cid = cid * 100 + env.distId
	local ok,err = xpcall(_serverInst.onClientLeave,debug.traceback,_serverInst,cid,reason)
	if not ok then
		event.error(err)
	end
end

function start(self,ip,port,max,serverInst)
	local gate = event.gate(max or 1000)
	gate:set_callback(_onClientAccept,_onClientClose,_onClientData)
	local port,reason = gate:start(ip or "0.0.0.0",port or 0)
	if not port then
		return false,reason
	end

	_serverInst = serverInst

	_gate = gate

	_sendGate = _gate.send

	return port
end

function stop(self)
	assert(_gate ~= nil)
	return _gate:stop()
end

function close(self,cid)
	assert(_gate ~= nil)
	local cid = modf(cid / 100) 
	_gate:close(cid)
end

local _doSendClient
local _doBroadcastClient
if env.name == "login" or env.name == "agent" then
	_doSendClient = function (cid,mid,data)
		cid = modf(cid / 100) 
		_sendGate(_gate,cid,mid,data)
	end

	_doBroadcastClient = function (cids,mid,data)
		for _,cid in pairs(cids) do
			cid = modf(cid / 100) 
			_sendGate(_gate,cid,mid,data)
		end
	end
else
	local sendAgent = serverMgr.sendAgent
	_doSendClient = function (cid,mid,data)
		local agentId = cid - modf(cid / 100) * 100
		sendAgent(serverMgr,agentId,"module.client_manager","sendClient",{cid = cid,mid = mid,data = data})
	end
	_doBroadcastClient = function (cids,mid,data)
		
		local whereInfo = {}
		for cid in pairs(cids) do
			local agentId = cid - modf(cid / 100) * 100
			local info = whereInfo[agentId]
			if not info then
				info = {}
				whereInfo[agentId] = info
			end
			table.insert(info,cid)
		end

		for agentId,cids in pairs(whereInfo) do
			sendAgent(serverMgr,agentId,"module.client_manager","sendClient",{cid = cids,mid = mid,data = data})
		end
	end
end


function sendClient(self,cid,mid,data)
	if type(cid) == "number" then
		_doSendClient(cid,mid,data)
	else
		_doBroadcastClient(cid,mid,data)
	end
end


