local event = require "event"
local cjson = require "cjson"
local model = require "model"

local util = require "util"
local protocol = require "protocol"

local serverMgr = import "module.server_manager"
local dbObject = import "module.database_object"
local itemContainer = import "module.agent.item.item_container"


local eUSER_STATUS = {
	ALIVE = 1,
	DEAD = 2 }

cAgentUser = dbObject.cDatabase:inherit("agentUser","uid","cid")

function __init__(self)
	self.cAgentUser:saveField("baseInfo")
	self.cAgentUser:saveField("itemMgr")
	self.cAgentUser:saveField("taskMgr")
	self.cAgentUser:saveField("fighter",true)
end


function cAgentUser:onCreate(cid,uid,account)
	self.cid = cid
	self.uid = uid
	self.status = eUSER_STATUS.ALIVE 
	self.hookTime = nil 

	self.account = account
end

function cAgentUser:onDestroy()

end

function cAgentUser:dbIndex()
	return {uid = self.uid}
end

function cAgentUser:enterGame()
	
	if not self.itemMgr then
		local itemMgr = itemContainer.cItemContainer:new()
		itemMgr:onCreate()
		self:init(itemMgr)
	end
	self.itemMgr:onEnterGame(self)

	self:fireEvent("ENTER_GAME")
	sendClient(self.cid,"sAgentEnter",{user_uid = self.uid})
	event.error(string.format("user:%d enter agent:%d",self.uid,env.distId))
end

function cAgentUser:leaveGame()
	self.itemMgr:onLeaveGame(self)
	self:fireEvent("LEAVE_GAME")
	event.error(string.format("user:%d leave agent:%d",self.uid,env.distId))
end

function cAgentUser:sendScene(file,method,args)
	local sceneInfo = self.sceneInfo
	if not sceneInfo then
		print(string.format("scene server:%d not connected",self.scene_server))
		return
	end
	serverMgr:sendScene(sceneInfo.serverId,file,method,args)
end

function cAgentUser:onEnterScene(serverId,sceneId,sceneUid)
	self.sceneInfo = {
		serverId = serverId,
		sceneId = sceneId,
		sceneUid = sceneUid
	}
end
