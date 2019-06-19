local event = require "event"
local model = require "model"

local serverMgr = import "module.server_manager"
local idBuilder = import "module.id_builder"


_agentServerMgr = _agentServerMgr or {}

function __init__(self)
	serverMgr:registerEvent("SERVER_DOWN",self,"onServerDown")
end

function onServerDown(self,name,serverId)
	if name ~= "agent" then
		return
	end
	_agentServerMgr[serverId] = nil
end

function reportAgentAddr(_,args)
	_agentServerMgr[args.id] = {
		addr = args.addr,
		amount = 0
	}
end

function selectAgent(self)
	local min
	local serverId
	for agentId,agentInfo in pairs(_agentServerMgr) do
		if not min or agentInfo.amount < min then
			min = agentInfo.amount
			serverId = agentId
		end
	end
	if not serverId then
		return
	end
	return serverId,_agentServerMgr[serverId].addr
end