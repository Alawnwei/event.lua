local sceneConst = import "module.scene.scene_const"
local sceneobj = import "module.scene.sceneobj"
local idBuilder = import "module.id_builder"

cPortalDoor = sceneobj.cSceneObj:inherit("portalDoor")

function __init__(self)
	
end

function cPortalDoor:onCreate(id,pos,face)
	sceneobj.cSceneObj.onCreate(self,idBuilder:allocMonsterTid(),pos)
	self.id = id
	self.liveTime = 300
	self.toSceneId = 10001
	self.toPos = {100,100}
	self.toFace = {1,1}
end

function cPortalDoor:onDestroy()
	sceneobj.cSceneObj.onDestroy(self)
end

function cPortalDoor:sceneObjType()
	return sceneConst.eSCENE_OBJ_TYPE.DOOR
end

function cPortalDoor:AOI_ENTITY_MASK()
	return sceneConst.eSCENE_AOI_MASK.OBJECT
end

function cPortalDoor:enter(sceneObj)

end

function cPortalDoor:onUpdate(now)
	sceneobj.cSceneObj.onUpdate(self,now)

	if self.liveTime and self.liveTime ~= 0 then
		local dt = now - self.createTime
		if dt >= self.liveTime then
			self:leaveScene()
			self:release()
		end
	end
end
