
local idBuilder = import "module.id_builder"
local sceneConst = import "module.scene.scene_const"
local sceneobj = import "module.scene.sceneobj"
local serverMgr = import "module.server_manager"
local clientMgr = import "module.client_manager"
local moveCtrl = import "module.scene.state_ctrl.move_ctrl"
local stateManager = import "module.scene.state_ctrl.state_manager"

cFighter = sceneobj.cSceneObj:inherit("fighter","uid","cid")

function __init__(self)
	
end

function cFighter:onCreate(uid,pos)
	
	sceneobj.cSceneObj.onCreate(self,idBuilder:allocMonsterTid(),pos,nil,5)

	self.stateMgr = stateManager.cStateMgr:new(self)
	self.moveCtrl = moveCtrl.cMoveCtrl:new(self)
end

function cFighter:onDestroy()
	sceneobj.cSceneObj.onDestroy(self)
end

function cFighter:sceneObjType()
	return sceneConst.eSCENE_OBJ_TYPE.FIGHTER
end

function cFighter:AOI_ENTITY_MASK()
	return sceneConst.eSCENE_AOI_MASK.USER
end

function cFighter:AOI_TRIGGER_MASK()
	return sceneConst.eSCENE_AOI_MASK.USER | sceneConst.eSCENE_AOI_MASK.MONSTER | sceneConst.eSCENE_AOI_MASK.PET
end

function cFighter:enterScene(scene,x,z)
	sceneobj.cSceneObj.enterScene(self,scene,x,z)
end

function cFighter:leaveScene()
	sceneobj.cSceneObj.leaveScene(self)
end

function cFighter:onEnterScene(scene)
	sceneobj.cSceneObj.onEnterScene(self,scene)

	local msg = {sceneId = scene.sceneId,sceneUid = scene.sceneUid}
	-- serverMgr:sendAgent(self.agentId,"handler.agent_handler","onEnterScene",msg)
	-- clientMgr:sendClient(self.cid,"sEnterScene",msg)
end

function cFighter:onLeaveScene()
	sceneobj.cSceneObj.onLeaveScene(self)
end

function cFighter:move(x,z)
	sceneobj.cSceneObj.move(self,x,z)
end

function cFighter:onObjEnter(sceneObjList)
	sceneobj.cSceneObj.onObjEnter(self,sceneObjList)

	local createObjInfo = {}
	local pathInfo = {}
	for _,sceneObj in pairs(sceneObjList) do
		table.insert(createObjInfo,sceneObj:getSeeInfo())
		local moveCtrl = sceneObj.moveCtrl
		if moveCtrl then
			local path = moveCtrl:getPath()
			if path then
				table.insert(pathInfo,{uid = sceneObj.uid,path = path})
			end
		end
	end


	-- sendClient(self.cid,"s_sceneObj_create",msg)
end

function cFighter:onObjLeave(sceneObjList)
	sceneobj.cSceneObj.onObjLeave(self,sceneObjList)
	local list = {}
	for _,sceneObj in pairs(sceneObjList) do
		table.insert(list,sceneObj.uid)
	end 
	-- sendClient(self.cid,"s_sceneObj_delete",list)
end

function cFighter:onUpdate(now)
	sceneobj.cSceneObj.onUpdate(self,now)
end
