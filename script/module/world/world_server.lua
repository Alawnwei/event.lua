local event = require "event"
local model = require "model"
local protocol = require "protocol"
local serverMgr = import "module.server_manager"
local scene_manager = import "module.world.scene_manager"
local dbObject = import "module.database_object"
local worldUser = import "module.world.world_user"


model.registerValue("dbCommon")
model.registerBinder("simpleUser","uid")

local eUSER_PHASE = {
	LOADING = 1,
	DONE = 2,
	LEAVE = 3
}

local sceneServerAddr = {}

isServerStart = isServerStart or false

function __init__(self)
	local dbCommon = dbObject.cDatabaseCommon:new(30)
	model.set_dbCommon(dbCommon)
	serverMgr:registerEvent("SERVER_DOWN",self,"onServerDown")
	serverMgr:registerEvent("SERVER_CONNECT",self,"onServerConnect")
end

function start(self)
	local dbCommon = model.get_dbCommon()
	local dbChannel = model.get_dbChannel()
	local list = dbChannel:findAll("common","simpleUser")
	for _,info in pairs(list) do
		dbCommon:init(info,"simpleUser",{userUid = info.userUid})
		model.bind_simpleUser_with_uid(info.userUid,info)
	end
	isServerStart = true
end


function onClientData(self,args)
	local user = model.fetch_worldUser_with_cid(args.cid)
	local reader = protocol.reader[args.messageId] 
	if not reader then
		event.error(string.format("no such pto id:%d",args.messageId))
		return
	end
	reader(user or args.cid,args.data)
end

function onServerDown(self,name,serverId)
	if name == "agent" then
		local all = model.fetch_world_user()
		for _,user in pairs(all) do
			if user.agentId == serverId then
				self:leave(user.userUid)
			end
		end
	elseif name == "scene" then
		sceneServerAddr[serverId] = nil
	end
end

function onServerConnect(self,name,serverId)
	
end

function isServerStart()
	return isServerStart
end

function onSceneAddr(_,args)
	sceneServerAddr[args.id] = args.addr

	local serverList = serverMgr:findServer("agent")
	for serverId in pairs(serverList) do
		serverMgr:sendAgent(serverId,"module.agent.agent_server","onSceneAddr",sceneServerAddr)
	end
end

function getSceneAddr(self)
	return sceneServerAddr
end

function enter(self,userUid,agentId)
	local user = model.fetch_world_user_with_uid(userUid)
	if user and user.phase == eUSER_PHASE.DONE then
		user:override(agentId)
	else
		user = worldUser.cWorldUser:new()
		model.bind_world_user_with_uid(userUid,user)
		user.phase = eUSER_PHASE.LOADING
		user:load()
		user:onCreate(userUid,agentId)
		if user.phase == eUSER_PHASE.LEAVE then
			user:release()
			model.unbind_world_user_with_uid(userUid)
			return
		end
		user.phase = eUSER_PHASE.DONE
		user:enter()
	end
end

function leave(self,userUid)
	local user = model.fetch_world_user_with_uid(userUid)
	if not user then
		return false
	end
	
	if user.phase == eUSER_PHASE.LOADING then
		user.phase = eUSER_PHASE.LEAVE
		return
	end

	user:leave()
	user:save()
	user:release()
	model.unbind_world_user_with_uid(userUid)
	return true
end

function serverStop(self)
	local dbCommon = model.get_dbCommon()
	dbCommon:save()
end
