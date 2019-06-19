local util = require "util"
local event = require "event"
local sceneConst = import "module.scene.scene_const"
local sceneobj = import "module.scene.sceneobj"
local idBuilder = import "module.id_builder"
local bulletCtrl = import "module.scene.state_ctrl.bullet_ctrl"
local skillApi = import "module.scene.skill.skill_api"

cBullet = sceneobj.cSceneObj:inherit("bullet")

function __init__(self)
	
end

function cBullet:onCreate(id,pos,range,owner)
	sceneobj.cSceneObj.onCreate(self,idBuilder:allocMonsterTid(),pos,nil,3)

	self.id = id
	self.range = range
	self.master = owner
	self.speed = 20
	
	self.lockTarget = nil
	self.endPos = nil

	self.bulletCtrl = bulletCtrl.cBulletCtrl:new(self)
end

function cBullet:onDestroy()
	sceneobj.cSceneObj.onDestroy(self)
	self.bulletCtrl:release()
	idBuilder:reclaimMonsterTid(self.uid)
end

function cBullet:sceneObjType()
	return sceneConst.eSCENE_OBJ_TYPE.BULLET
end

function cBullet:onObjEnter(objList)

end

function cBullet:onObjLeave(objList)

end

function cBullet:setLockTarget(targetObj)
	self.lockTarget = targetObj
end

function cBullet:setEndPos(pos)
	self.endPos = {pos[1],pos[2]}
end

function cBullet:getEndPos()
	if self.endPos then
		return self.endPos
	end
	return self.lockTarget.pos
end

function cBullet:doCollision(from,to)
	if self.lockTarget then
		if util.capsule_intersect(from[1],from[2],to[1],to[2],self.range,self.lockTarget.pos[1],self.lockTarget.pos[2],self.lockTarget.range) then
			skillApi:onDamage(self.master,self.lockTarget)
			return true
		end
	else
		local objs = self:getObjInCapsule(from,to,self.range)
	
		for _,obj in pairs(objs) do
			skillApi:onDamage(self.master,obj)
		end
	end

	return false
end

function cBullet:onUpdate(now)
	sceneobj.cSceneObj.onUpdate(self,now)

	if self.bulletCtrl:onUpdate(now) then
		self:leaveScene()
		self:release()
	end
end
