local event = require "event"
local model = require "model"
local util = require "util"
local route = require "route"
local cjson = require "cjson"
local protocol = require "protocol"
local channel = require "channel"
local timer = require "timer"
local clientMgr = import "module.client_manager"
local serverMgr = import "module.server_manager"
local module_object = import "module.object"
local agentUser = import "module.agent.agent_user"
local common = import "common.common"

local kAUTH_TIME = 60

_tokenMgr = _tokenMgr or {}
_enterUserMgr = _enterUserMgr or {}
_accountMgr = _accountMgr or {}
_server_stop = _server_stop or false

function __init__(self)
	serverMgr:registerEvent("SERVER_DOWN",self,"server_down")
end

function start(self)
	timer.callout(1,self,"authTimer")

	import "handler.agent_handler"
	import "handler.cmd_handler"
end

function authTimer(self)
	local now = util.time()
	for token,info in pairs(_tokenMgr) do
		if now - info.time >= kAUTH_TIME then
			_tokenMgr[token] = nil
			event.error(string.format("%s:%d auth timeout",info.account,info.uid))
		end

	end
end

function onClientData(self,cid,messageId,data,size)
	local ptoName = protocol.name[messageId]
	local forward = common.PROTOCOL_FORWARD[ptoName]
	if forward then
		local message = {cid = cid,messageId = messageId,data = string.copy(data,size)}
		if forward == common.SERVER_TYPE.WORLD then
			serverMgr:sendWorld("module.world_server","onClientData",message)
		elseif forward == common.SERVER_TYPE.SCENE then
			local user = model.fetch_agentUser_with_cid(cid)
			if not user then
				event.error(string.format("forward scene error:no such user:%d",cid))
				return
			end

			serverMgr:sendScene(user.sceneServerId,"module.scene_server","onClientData",message)
		end
		return
	else
		local user = model.fetch_agentUser_with_cid(cid)
		local reader = protocol.reader[messageId]
		if not reader then
			event.error(string.format("no such pto id:%d",args.messageId))
			return
		end
		reader(user or cid,data,size)
	end
end


function onClientEnter(self,cid,addr)
	print(string.format("client enter:%d,%s",cid,addr))
end

function onClientLeave(self,cid)
	print(string.format("client leave:%d,%s",cid,addr))
	local user = model.fetch_agent_user_with_uid(cid)
	if not user then
		return
	end
	user.cid = nil
	user.status = eUSER_STATUS.DEAD	
	if user.hookTime then
		return
	end

	local mutex = _accountMgr[user.account]
	mutex(userLeave,self,user)
end

function userRegister(self,token,time)
	_tokenMgr[token] = time
end

function userKick(self,uid)
	local user = model.fetch_agent_user_with_uid(uid)
	if not user then
		return false
	end

	if user.cid then
		clientMgr:close(user.cid)
	end

	local mutex = _accountMgr[user.account]

	mutex(userLeave,self,user)

	return true
end

function userAuth(self,cid,token)
	if not _tokenMgr[token] then
		clientMgr:close(cid)
		return
	end

	local time = _tokenMgr[token]
	_tokenMgr[token] = nil

	local now = util.time()
	if now - time >= 60 * 100 then
		clientMgr:close(cid)
		return
	end

	local str,err = util.authcode(token,tostring(time),now,0)
	if not str then
		event.error(string.format("client:%d auth error:%s",cid,err))
		clientMgr:close(cid)
		return
	end

	local info = cjson.decode(str)

	local mutex = _accountMgr[info.account]
	if not mutex then
		_accountMgr[info.account] = event.mutex()
	end
	
	mutex(userEnter,self,cid,info.uid,info.account)
end

function userEnter(self,cid,uid,account)
	local user = agentUser.cAgentUser:new(cid,uid,account)
	model.bind_agentUser_with_uid(uid,user)
	model.bind_agentUser_with_cid(cid,user)

	user:onCreate(cid,uid,account)
	user:load()

	user:enterGame()

	local msg = {userUid = user.uid,agentId = env.distId}
	serverMgr:sendWorld("handler.world_handler","enterWorld",msg)
end

function userLeave(self,user)
	if not model.fetch_agentUser_with_uid(user.uid) then
		return
	end
	local ok,err = xpcall(user.leaveGame,debug.traceback,user)
	if not ok then
		event.error(err)
	end
	user:save()

	local dbChannel = model.get_dbChannel()
	local updater = {}
	updater["$inc"] = {version = 1}
	updater["$set"] = {time = os.time()}
	dbChannel:findAndModify("agentUser","saveVersion",{query = {uid = user.uid},update = updater,upsert = true})

	user:release()

	serverMgr:sendWorld("handler.world_handler","leaveWorld",{userUid = user.uid})
	serverMgr:sendLogin("handler.login_handler","leaveAgent",{account = user.account})

	model.unbind_agentUser_with_uid(user.uid)
	model.unbind_agentUser_with_cid(user.cid)
end

function get_all_enter_user(self)
	local result = {}
	for cid,info in pairs(_enterUserMgr) do
		local user = model.fetch_agent_user_with_uid(info.uid)
		result[user.account] = {uid = user.uid,agent_server = env.distId}
	end
	for _,info in pairs(_user_token) do
		result[info.account] = {uid = info.uid,agent_server = env.distId}
	end
	return result
end

function connectSceneServer(self,serverId,serverAddr)
	local allConnectSceneServer = serverMgr:findServer("scene")
	if allConnectSceneServer[serverId] then
		return true
	end

	local addr
	if serverAddr.file then
		addr = string.format("ipc://%s",serverAddr.file)
	else
		addr = string.format("tcp://%s:%d",serverAddr.ip,serverAddr.port)
	end

	local channel = serverMgr:connectServerWithAddr("scene",addr,false,1)
	return channel ~= nil
end

function onSceneAddr(_,args)
	connectSceneServer(nil,args.id,args.addr)
end

function server_down(self,name,id)
	if name == "scene" then
		local all = model.fetch_agent_user()
		for _,user in pairs(all) do
			if user.scene_server == id then
				user:scene_down()
			end
		end
	end
end

function server_stop()
	_server_stop = true
	clientMgr:stop()

	for cid,enter_info in pairs(_enterUserMgr) do
		clientMgr:close(cid)
		local user = model.fetch_agent_user_with_uid(enter_info.uid)
		if user then
			enter_info.mutex(user_leave,self,user)
		end
		_enterUserMgr[cid] = nil
	end

	local db_channel = model.get_dbChannel()
	
	local updater = {}
	updater["$inc"] = {version = 1}
	updater["$set"] = {time = os.time()}
	db_channel:findAndModify("common","agent_version",{query = {uid = env.distId},update = updater,upsert = true})

	local world_channel = model.get_world_channel()
	world_channel:send("handler.world_handler","server_stop",{id = env.distId})
end

function scene_server_update()

end

function connect_scene_server()
	local result = serverMgr:sendWorld("module.scene_manager","scene_server_info")
	local list = serverMgr:findServer("scene")

	for _,info in pairs(result) do
		if not list[info.id] then

		end
	end
end
