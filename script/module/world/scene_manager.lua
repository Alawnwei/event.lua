local event = require "event"
local model = require "model"

local serverMgr = import "module.server_manager"
local idBuilder = import "module.id_builder"

_sceneServerMgr = _sceneServerMgr or {}
_sceneInfo = _sceneInfo or {}
_sceneMgr = _sceneMgr or {}

_agentConnectMutex = _agentConnectMutex or {}
_agentConnectInfo = _agentConnectInfo or {}

function __init__(self)
	serverMgr:registerEvent("SERVER_DOWN",self,"onServerDown")
end

function createScene(self,sceneId)
	local minServer
	local minAmount
	for serverId,info in pairs(_sceneServerMgr) do
		if not minAmount or minAmount > info.amount then
			minAmount = info.amount
			minServer = serverId
		end
	end

	local sceneUid = idBuilder:allocSceneUid()
	serverMgr:sendScene(minServer,"module.scene.scene_server","createScene",{sceneId = sceneId,sceneUid = sceneUid})
	local info = _sceneMgr[sceneId]
	if not info then
		info = {}
		_sceneMgr[sceneId] = info
	end

	info[sceneUid] = {amount = 0,serverId = minServer}
	_sceneInfo[sceneUid] = {amount = 0,serverId = minServer}

	return minServer,sceneUid
end

function onServerDown(self,name,serverId)

end

function reportSceneAddr(self,args)
	_sceneServerMgr[args.serverId] = {
		addr = args.addr,
		amount = 0
	}
end

function onAgentConnectScene(self,args)

end

function agentConnectScene(self,agentServerId,sceneServerId)
	local connectInfo = _agentConnectInfo[agentServerId]
	if not connectInfo then
		connectInfo = {}
		_agentConnectInfo[agentServerId] = connectInfo
	end

	if connectInfo[sceneServerId] then
		return true
	end

	local sceneServerInfo = _sceneServerMgr[sceneServerId]
	if not sceneServerInfo then
		return false
	end

	local mutex = _agentConnectMutex[agentServerId]
	if not mutex then
		mutex = event.mutex()
		_agentConnectMutex[agentServerId] = mutex
	end

	return mutex(function ()
		if connectInfo[sceneServerId] then
			return true
		end

		local ok = serverMgr:callAgent(agentServerId,"module.agent.agent_server","connectSceneServer",{serverId = sceneServerId,addr = sceneServerInfo.addr})
		if ok then
			connectInfo[sceneServerId] = true
			return true
		else
			return false
		end
	end)
end

function enterScene(self,worldUser,sceneId,sceneUid,fighter)
	local sceneInfo = _sceneInfo[sceneUid]
	if not sceneInfo then
		return
	end

	if not self:agentConnectScene(worldUser.agentId,sceneInfo.serverId) then
		return
	end

	if fighter then
		serverMgr:callScene(sceneInfo.serverId,"module.scene.scene_server","enterScene",{userUid = worldUser.userUid,fighter = fighter})
		worldUser:onEnterScene(sceneId,sceneUid)
		return
	end

	local fighterInfo
	if fighter.sceneUid == sceneUid then
		serverMgr:callScene(sceneInfo.serverId,"module.scene.scene_server","enterScene",{userUid = userUid,fighterInfo = fighter})
		worldUser:onEnterScene(sceneId,sceneUid)
		return
	else
		local oSceneInfo = _sceneInfo[fighter.sceneUid]
		if oSceneInfo.serverId == sceneInfo.sceneId then
			serverMgr:callScene(sceneInfo.serverId,"module.scene.scene_server","transferInside",{userUid = userUid,sceneUid = sceneUid})
			worldUser:onEnterScene(sceneId,sceneUid)
			return
		else
			fighterInfo = serverMgr:callScene(sceneInfo.serverId,"module.scene.scene_server","leaveScene",{userUid = userUid})
		end
	end

	serverMgr:callScene(sceneInfo.serverId,"module.scene.scene_server","enterScene",{userUid = userUid,fighterInfo = fighterInfo})
	worldUser:onEnterScene(sceneId,sceneUid)
end

function leaveScene(self,args)
	serverMgr:callScene(sceneInfo.serverId,"module.scene.scene_server","leaveScene",{userUid = args.userUid})
end