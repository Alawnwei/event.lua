local event = require "event"
local util = require "util"
local sceneConst = import "module.scene.scene_const"
local dbObject = import "module.database_object"

local angle2dir = util.angle2dir
local dir2angle = util.dir2angle
local mathAbs = math.abs

local segmentIntersect = util.segment_intersect
local rectangleIntersect = util.rectangle_intersect
local sectorIntersect = util.sector_intersect
local capsuleIntersect = util.capsule_intersect
local sqrtDistance = util.sqrt_dot2dot

cSceneObj = dbObject.cCollection:inherit("sceneobj")

function __init__(self)
	self.cSceneObj:packField("uid")
	self.cSceneObj:packField("pos")
end

function cSceneObj:onCreate(uid,pos,face,aoiRange)
	self.uid = uid
	self.objType = self:sceneObjType()
	self.createTime = event.now()
	self.aoiRange = aoiRange
	self.pos = {pos[1],pos[2]}
	self.face = pos or {0,0}
	self.angle = 0
	self.speed = 10
	self.isDead = false
	self.hp = hp
	self.maxHp = hp

	self.witnessCtx = {}
	self.witnessDirty = true

	self.viewerCtx = {}
end

function cSceneObj:onDestroy()

end

function cSceneObj:sceneObjType()
	assert(false)
end

function cSceneObj:AOI_ENTITY_MASK()
	return sceneConst.eSCENE_AOI_MASK.OBJECT
end

function cSceneObj:AOI_TRIGGER_MASK()
	return 0xff
end

function cSceneObj:getSeeInfo()
	return {}
end

function cSceneObj:enterScene(scene,x,z)
	if self.scene == scene then
		self:flashTo(x,z)
		return
	end
	scene:enter(self,{x,z})
end

function cSceneObj:leaveScene()
	assert(self.scene ~= nil)
	self.scene:leave(self)
end

function cSceneObj:onEnterScene(scene)
	self.aoiEntityId = scene:createAoiEntity(self,self:AOI_ENTITY_MASK())
	if self.aoiRange then
		self.aoiTriggerId = scene:createAoiTrigger(self,self.aoiRange,self:AOI_TRIGGER_MASK())
	end

	self.scene = scene
end

function cSceneObj:onLeaveScene(scene)
	scene:removeAoiEntity(self)
	self.aoiEntityId = nil

	if self.aoiTriggerId then
		scene:removeAoiTrigger(self)
		self.aoiTriggerId = nil
	end

	self.scene = nil
end

function cSceneObj:move(x,z,notSyncAoi)
	local sceneInst = self.scene
	if not sceneInst then
		return false
	end

	-- local x,z = sceneInst:posAroundMovable(x,z,2)

	local dx = x - self.pos[1]
	local dz = z - self.pos[2]

	if mathAbs(dx) <= 0.1 and mathAbs(dz) <= 0.1 then
		return false
	end

	if not notSyncAoi then
		sceneInst:moveAoiEntity(self,x,z)
		if self.aoiTriggerId then
			sceneInst:moveAoiTrigger(self,x,z)
		end
	end

	self.pos[1] = x
	self.pos[2] = z
	
	self.face[1] = dx
	self.face[2] = dz

	self.angle = dir2angle(dx,dz)
end

function cSceneObj:flashTo(x,z)
	self:move(x,z)
end

function cSceneObj:onObjEnter(sceneObjList)

end

function cSceneObj:onObjLeave(sceneObjList)

end

function cSceneObj:onUpdate(now)

end

function cSceneObj:onCommonUpdate(now)

end

function cSceneObj:getViewer(findType)
	local result = {}
	local objMgr = self.scene.objMgr

	for sceneObjUid in pairs(self.viewerCtx) do
		local sceneObj = objMgr[sceneObjUid]

		if findType then
			if sceneObj.objType == findType then
				table.insert(result,sceneObj)
			end
		else
			table.insert(result,sceneObj)
		end
	end

	return result
end

function cSceneObj:getWitness()
	local sceneInst = self.scene

	if self.witnessDirty then
		self.witnessDirty = false
		self.witnessCtx = sceneInst:getWitness(self)
	end

	return self.witnessCtx
end

function cSceneObj:hasWitness()
	local witnessList = self:getWitness()
	return next(witnessList) ~= nil
end

function cSceneObj:getWitnessCid(filterFunc,...)
	local witnessList = self:getWitness()

	local objMgr = self.scene.objMgr

	local fighterType = sceneConst.eSCENE_OBJ_TYPE.FIGHTER

	local result = {}

	for _,sceneObjUid in pairs(witnessList) do
		local sceneObj = objMgr[sceneObjUid]
		if sceneObj.objType == fighterType then
			if filterFunc and filterFunc(...,sceneObj) then
				table.insert(result,sceneObj.cid)
			else
				table.insert(result,sceneObj.cid)
			end
		end
	end

	return result
end

function cSceneObj:getObjInLine(from,to,cmpFunc,...)
	local from = from or self.pos

	local result = {}

	local allObjs = self:getViewer()
	for _,obj in pairs(allObjs) do
		if segmentIntersect(from[1],from[2],to[1],to[2],obj.pos[1],obj.pos[2],obj.range) then
			if cmpFunc and cmpFunc(...,obj) then
				table.insert(result,obj)
			else
				table.insert(result,obj)
			end
		end
	end

	return result
end

function cSceneObj:getObjInRectangle(pos,dir,length,width,cmpFunc,...)
	local angle = dir2angle(dir[1],dir[2])

	local pos = pos or self.pos

	local result = {}

	local allObjs = self:getViewer()
	for _,obj in pairs(allObjs) do
		if rectangleIntersect(pos[1],pos[2],length,width,angle,obj.pos[1],obj.pos[2],obj.range) then
			if cmpFunc and cmpFunc(...,obj) then
				table.insert(result,obj)
			else
				table.insert(result,obj)
			end
		end
	end

	return result
end

function cSceneObj:getObjInCircle(pos,range,cmpFunc,...)
	local pos = pos or self.pos

	local result = {}
	local allObjs = self:getViewer()
	for _,obj in pairs(allObjs) do
		local totalRange = range + obj.range
		if sqrtDistance(pos[1],pos[2],obj.pos[1],obj.pos[2]) <= totalRange * totalRange then
			if cmpFunc and cmpFunc(...,obj) then
				table.insert(result,obj)
			else
				table.insert(result,obj)
			end
		end
	end

	return result
end

function cSceneObj:getObjInSector(pos,dir,degree,range,cmpFunc,...)
	local angle = dir2angle(dir[1],dir[2])

	local pos = pos or self.pos

	local result = {}

	local allObjs = self:getViewer()
	for _,obj in pairs(allObjs) do
		if sectorIntersect(pos[1],pos[2],angle,degree,range,obj.pos[1],obj.pos[2],obj.range) then
			if cmpFunc and cmpFunc(...,obj) then
				table.insert(result,obj)
			else
				table.insert(result,obj)
			end
		end
	end

	return result
end

function cSceneObj:getObjInCapsule(from,to,r,cmpFunc,...)
	local from = from or self.pos
	local result = {}

	local allObjs = self:getViewer()
	for _,obj in pairs(allObjs) do
		if capsuleIntersect(from[1],from[2],to[1],to[2],r,obj.pos[1],obj.pos[2],obj.range) then
			if cmpFunc and cmpFunc(...,obj) then
				table.insert(result,obj)
			else
				table.insert(result,obj)
			end
		end
	end

	return result
end

function cSceneObj:getDirFrom(sceneObj)
	return sceneObj.pos[1] - self.pos[1],sceneObj.pos[2] - self.pos[2]
end

function cSceneObj:getAngleFrom(sceneObj)
	return dir2angle(self:getDirFrom(sceneObj))
end