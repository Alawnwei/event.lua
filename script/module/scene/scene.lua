local event = require "event"
local aoiCore = require "toweraoi.core"
local navCore= require "nav.core"
local cjson = require "cjson"
local timer = require "timer"
local util = require "util"

local object = import "module.object"
local monster = import "module.scene.monster"
local sceneConst = import "module.scene.scene_const"

local randomInRectangle = util.random_in_rectangle
local randomInCircle = util.random_in_circle

cScene = object.cObject:inherit("scene")

function cScene:onCreate(sceneId,sceneUid)
	self.sceneId = sceneId
	self.sceneUid = sceneUid

	self.objMgr = {}
	self.objTypeMgr = {}
	
	self.aoi = aoiCore.create(self.sceneId,1000,1000,4)

	local nav = navCore.create(string.format("./config/%d.nav",sceneId))
	nav:load_tile(string.format("./config/%d.nav.tile",sceneId))

	self.nav = nav
	
	timer.callout(sceneConst.kUPDATE_INTERVAL,self,"update")
	timer.callout(sceneConst.kCOMMON_UPDATE_INTERVAL,self,"commonUpdate")

	self.phase = sceneConst.eSCENE_PHASE.CREATE
	self.lifeTime = 0
	self.timeoutResult = false

	self.passEvent = {}
	self.failEvent = {}

	self.areaMonster = {}

	self.areaMgr = {}
	self.areaEnter = {}
	self.areaActive = {}
end

function cScene:onDestroy()
	timer.removeAll(self)
	self:cleanSceneObj()
end

function cScene:cleanSceneObj()
	for _,sceneObj in pairs(self.objMgr) do
		sceneObj:release()
	end 
end

function cScene:getObj(uid)
	return self.objMgr[uid]
end

function cScene:getAllObjByType(sceneObjType)
	local typeMgr = self.objTypeMgr[sceneObjType]
	return typeMgr
end

function cScene:enter(sceneObj,pos)
	local pos = pos or sceneObj.pos

	assert(self.objMgr[sceneObj.uid] == nil,sceneObj.uid)
	self.objMgr[sceneObj.uid] = sceneObj

	local objType = sceneObj:sceneObjType()
	
	local typeMgr = self.objTypeMgr[objType]
	if not typeMgr then
		typeMgr = {}
		self.objTypeMgr[objType] = typeMgr
	end 
	typeMgr[sceneObj.uid] = sceneObj

	-- pos[1],pos[2] = self:posAroundMovable(pos[1],pos[2],2)

	sceneObj.pos[1] = pos[1]
	sceneObj.pos[2] = pos[2]

	sceneObj:onEnterScene(self)

	if objType == sceneConst.eSCENE_OBJ_TYPE.FIGHTER then
		self:onUserEnter(sceneObj)
	else
		self:onObjEnter(sceneObj)
	end
end

function cScene:leave(sceneObj)
	assert(self.objMgr[sceneObj.uid] ~= nil,sceneObj.uid)
	self.objMgr[sceneObj.uid] = nil

	local objType = sceneObj:sceneObjType()
	local typeMgr = self.objTypeMgr[objType]
	typeMgr[sceneObj.uid] = nil

	sceneObj:onLeaveScene(self)

	if objType == sceneConst.eSCENE_OBJ_TYPE.FIGHTER then
		self:onUserLeave(sceneObj)
	else
		self:onObjLeave(sceneobj)
	end
end

function cScene:onUserEnter(user)
	if not user.locationInfo then
		user.locationInfo = {}
	end
	local locationInfo = user.locationInfo
	locationInfo.enter = {
		sceneId = self.id,
		sceneUid = self.uid,
		face = user.face,
		pos = {user.pos[1],user.pos[2]}
	}
end

function cScene:onUserLeave(user)
	local locationInfo = user.locationInfo
	locationInfo.leave = {
		sceneId = self.id,
		sceneUid = self.uid,
		face = user.face,
		pos = {user.pos[1],user.pos[2]}
	}

	local sceneCfg = config.scene[self.id]
	if sceneCfg.type == sceneConst.eSCENE_TYPE.CITY then
		locationInfo.lastCity = location.leave
	end
end

function cScene:onObjEnter(obj)

end

function cScene:onObjLeave(obj)

end

function cScene:getSize()

end

--寻路坐标相关
function cScene:findPath(fromX,fromZ,toX,toZ)
	return self.nav:find(fromX,fromZ,toX,toZ)
end

function cScene:raycast(fromX,fromZ,toX,toZ)
	return self.nav:raycast(fromX,fromZ,toX,toZ)
end

function cScene:posMovable(x,z)
	return self.nav:movable(x,z)
end

function cScene:posAroundMovable(x,z,depth)
	return self.nav:around_movable(x,z,depth)
end

function cScene:randomInRectangle(center,length,width,angle)
	for i = 1,1000 do
		local x,z = randomInRectangle(center[1],center[2],length,width,angle)
		if self:posMovable(x,z) then
			return x,z
		end
	end
	return false
end

function cScene:randomInCircle(center,radius)
	for i = 1,1000 do
		local x,z = randomInCircle(center[1],center[2],radius)
		if self:posMovable(x,z) then
			return x,z
		end
	end
	return false
end

--aoi
function cScene:createAoiEntity(sceneObj,entityMask)
	local entityId,aoiSet = self.aoi:create_entity(sceneObj.uid,entityMask,sceneObj.pos[1],sceneObj.pos[2])

	for _,otherUid in pairs(aoiSet) do
		local other = self.objMgr[otherUid]
		sceneObj.witnessDirty = true
		other.viewerCtx[sceneObj.uid] = true

		other:onObjEnter({sceneObj})
	end

	return entityId
end

function cScene:removeAoiEntity(sceneObj)
	local aoiSet = self.aoi:remove_entity(sceneObj.aoiEntityId)

	for _,otherUid in pairs(aoiSet) do
		local other = self.objMgr[otherUid]
		sceneObj.witnessDirty = true
		other.viewerCtx[sceneObj.uid] = nil

		other:onObjLeave({sceneObj})
	end
end

function cScene:moveAoiEntity(sceneObj,x,z)
	local enterSet,LeaveSet = self.aoi:move_entity(sceneObj.aoiEntityId,x,z)

	for _,otherUid in pairs(enterSet) do
		local other = self.objMgr[otherUid]
		sceneObj.witnessDirty = true
		other.viewerCtx[sceneObj.uid] = true

		other:onObjEnter({sceneObj})
	end

	for _,otherUid in pairs(LeaveSet) do
		local other = self.objMgr[otherUid]
		sceneObj.witnessDirty = true
		other.viewerCtx[sceneObj.uid] = nil

		other:onObjLeave({sceneObj})
	end
end

function cScene:createAoiTrigger(sceneObj,triggerRange,triggerMask)
	local triggerId,aoiSet = self.aoi:create_trigger(sceneObj.uid,triggerMask,sceneObj.pos[1],sceneObj.pos[2],triggerRange or 3)

	local empty = true 
	local enterList = {}
	for _,otherUid in pairs(aoiSet) do
		empty = false
		local other = self.objMgr[otherUid]
		table.insert(enterList,other)
		sceneObj.viewerCtx[otherUid] = true
		other.witnessDirty = true
	end
	
	if not empty then
		sceneObj:onObjEnter(enterList)
	end

	return triggerId
end

function cScene:removeAoiTrigger(sceneObj)
	self.aoi:remove_trigger(sceneObj.aoiTriggerId)

	for uid in pairs(sceneObj.viewerCtx) do
		local other = self.objMgr[otherUid]
		other.witnessDirty = true
	end
end

function cScene:moveAoiTrigger(sceneObj,x,z)
	local enterSet,LeaveSet = self.aoi:move_trigger(sceneObj.aoiTriggerId,x,z)

	local list = {}
	local empty = true
	for _,otherUid in pairs(enterSet) do
		empty = false
		local other = self.objMgr[otherUid]
		table.insert(list,other)
		sceneObj.viewerCtx[otherUid] = true
		other.witnessDirty = true
	end
	
	if not empty then
		sceneObj:onObjEnter(list)
	end

	local list = {}
	local empty = true
	for _,otherUid in pairs(LeaveSet) do
		empty = false
		local other = self.objMgr[otherUid]
		table.insert(list,other)
		sceneObj.viewerCtx[otherUid] = nil
		other.witnessDirty = true
	end
	
	if not empty then
		sceneObj:onObjLeave(list)
	end
end

function cScene:getWitness(sceneObj)
	return self.aoi:get_witness(sceneObj.aoiEntityId)
end

--场景通关事件
function cScene:addPassEvent(ev,...)
	local eSCENE_PASS_EVENT = sceneConst.eSCENE_PASS_EVENT

	if ev == eSCENE_PASS_EVENT.TIMEOUT then
		local time = ...
		self.timeoutResult = true
		self.lifeTime = time
	elseif ev == eSCENE_PASS_EVENT.MONSTER_DIE then
		local monsterId = ...
		local evInfo = self.passEvent[ev]
		if not evInfo then
			evInfo = {}
			self.passEvent[ev] = evInfo
		end
		evInfo[monsterId] = true
	elseif ev == eSCENE_PASS_EVENT.MONSTER_AREA_DONE then
		local areaId = ...
		local evInfo = self.passEvent[ev]
		if not evInfo then
			evInfo = {}
			self.passEvent[ev] = evInfo
		end
		evInfo[areaId] = true
	end
end

--场景失败事件
function cScene:addFailEvent(ev,...)
	local eSCENE_FAIL_EVENT = sceneConst.eSCENE_FAIL_EVENT

	if ev == eSCENE_FAIL_EVENT.TIMEOUT then
		local time = ...
		self.timeoutResult = false
		self.lifeTime = time
	elseif ev == eSCENE_FAIL_EVENT.USER_DIE then
		self.failEvent[ev] = true
	elseif ev == eSCENE_FAIL_EVENT.USER_ACE then
		self.failEvent[ev] = true
	elseif ev == eSCENE_FAIL_EVENT.MONSTER_DIE then
		local monsterId = ...
		local evInfo = self.failEvent[ev]
		if not evInfo then
			evInfo = {}
			self.failEvent[ev] = evInfo
		end
		evInfo[monsterId] = true
	end
end

function cScene:spawnMonster(id,pos,face,...)
	local monsterObj = monster.cMonster:new()
	monsterObj:onCreate(id,pos,face,100)

	monsterObj:enterScene(self,pos[1],pos[2])

	self:onMonsterCreate(monsterObj)

	return monsterObj
end

function cScene:spawnMonsterArea(areaId)
	local areaInfo = self.areaMonster[areaId]

	for id,amount in pairs(areaInfo.monsterInfo) do
		for i = 1,amount do
			local pos = areaInfo.pos
			if areaInfo.posRandom then
				if areaInfo.region.type == sceneConst.eSCENE_MONSER_AREA_REGION.CIRCLE then
					pos = self:randomInCircle(areaInfo.pos,areaInfo.region.range)
				elseif areaInfo.region.type == sceneConst.eSCENE_MONSER_AREA_REGION.RECTANGLE then
					pos = self:randomInRectangle(areaInfo.pos,areaInfo.region.length,areaInfo.region.width,areaInfo.region.angle)
				end
			end
			self:spawnMonster(id,pos)
			areaInfo.monsterAmount = areaInfo.monsterAmount + 1
		end
	end
end

function cScene:initMonsterArea(areaId,spawnData)
	local areaInfo = {waveIndex = 0,
					  waveMax = spawnData.waveMax,
					  monsterAmount = 0,
					  miniSurvive = spawnData.miniSurvive,
					  monsterInfo = spawnData.monsterInfo,
					  pos = spawnData.pos,
					  posRandom = spawnData.posRandom,
					  region = spawnData.region}

	self.areaMonster[areaId] = areaInfo
end

function cScene:initArea(areaId,areaData)
	local areaInfo = {areaId = areaId,areaData = areaData,fired = false}
	self.areaMgr[areaId] = areaInfo
end

function cScene:enterArea(areaId)
	self.areaEnter[areaId] = true
	local areaInfo = self.areaMgr[areaId]
	if not areaInfo then
		return
	end

	if areaInfo.fired then
		return
	end
	areaInfo.fired = true

	return self:fireAreaEvent(areaId)
end

function cScene:leaveArea(areaId)
	self.areaEnter[areaId] = nil
	local areaInfo = self.areaMgr[areaId]
	if not areaInfo then
		return
	end
end

function cScene:fireAreaEvent(areaId,...)
	local areaInfo = self.areaMgr[areaId]
	local eSCENE_AREA_EVENT_NAME = sceneConst.eSCENE_AREA_EVENT_NAME
	for eventType,eventArgs in pairs(areaInfo.areaData) do
		local eventName = eSCENE_AREA_EVENT_NAME[eventType] 
		if eventName then
			local methodName = "onAreaEvent"..eventName
			if self[methodName] then
				self[methodName](self,areaId,eventArgs)
			end
		end
		
	end
end

function cScene:onAreaEventSpawnMonster(areaId,spawnData)
	local areaInfo = self.areaMonster[areaId]
	if areaInfo then
		return
	end
	self:initMonsterArea(areaId,spawnData)
	return self:spawnMonsterArea(areaId)
end

function cScene:onAreaEventActiveArea(areaId,activeData)

end

function cScene:onAreaEventCreatePortal(areaId,portalData)

end

function cScene:onMonsterAreaDone(areaId)
	if self.phase ~= sceneConst.eSCENE_PHASE.START then
		return
	end

	local eSCENE_PASS_EVENT = sceneConst.eSCENE_PASS_EVENT

	local evInfo = self.passEvent[eSCENE_PASS_EVENT.MONSTER_AREA_DONE]
	if not evInfo then
		return
	end
	if not evInfo[areaId] then
		return
	end
	self:over()
	self:onWin()
end

function cScene:onMonsterCreate(monster)

end

function cScene:onMonsterDead(monster,killer)
	if self.phase ~= sceneConst.eSCENE_PHASE.START then
		return
	end

	local evInfo = self.passEvent[sceneConst.eSCENE_PASS_EVENT.MONSTER_DIE]
	if evInfo and evInfo[monster.id] then
		self:over()
		self.onWin()
		return
	end
	
	local evInfo = self.failEvent[sceneConst.eSCENE_PASS_EVENT.MONSTER_DIE]
	if evInfo and evInfo[monster.id] then
		self:over()
		self.onFail()
		return
	end

	local areaId = monster.areaId
	if areaId then
		local areaInfo = self.areaMonster[areaId]
		if areaInfo.waveMax == 0 or areaInfo.waveIndex < areaInfo.waveMax then
			if areaInfo.monsterAmount <= areaInfo.miniSurvive then
				areaInfo.waveIndex = areaInfo.waveIndex + 1
				self:spawnMonsterArea(areaId)
			end
		end
	end
end

function cScene:onUserDead(user,killer)
	if self.phase ~= sceneConst.eSCENE_PHASE.START then
		return
	end

	local eSCENE_FAIL_EVENT = sceneConst.eSCENE_FAIL_EVENT

	if self.failEvent[eSCENE_FAIL_EVENT.USER_DIE] then
		self:over()
		self:onFail()
		return
	end

	if self.failEvent[eSCENE_FAIL_EVENT.USER_ACE] then
		local allUser = self:getAllObjByType(sceneConst.eSCENE_OBJ_TYPE.FIGHTER)
		for _,user in pairs(allUser) do
			if not user:isDead() then
				return
			end
		end
		self:over()
		self:onFail()
		return
	end
end

function cScene:start()
	self.phase = sceneConst.eSCENE_PHASE.START
	self.startTime = os.time()
	self:onStart()
end

function cScene:over()
	self.phase = sceneConst.eSCENE_PHASE.OVER
	self.overTime = os.time()
	self:onOver()
end

function cScene:onStart()

end

function cScene:onOver()

end

function cScene:onWin()

end

function cScene:onFail()

end

function cScene:kickUser(user)

end

function cScene:update()
	local now = event.now()
	for _,sceneObj in pairs(self.objMgr) do
		local ok,err = xpcall(sceneObj.onUpdate,debug.traceback,sceneObj,now)
		if not ok then
			event.error(err)
		end
	end
end

function cScene:commonUpdate()
	local now = event.now()

	for _,sceneObj in pairs(self.objMgr) do
		local ok,err = xpcall(sceneObj.onCommonUpdate,debug.traceback,sceneObj,now)
		if not ok then
			event.error(err)
		end
	end

	local phase = self.phase
	
	if phase == sceneConst.eSCENE_PHASE.START then
		if self.lifeTime ~= 0 then
			if now - self.startTime >= self.lifeTime then
				self:over()
				if self.timeoutResult then
					self:onWin()
				else
					self:onFail()
				end
			end
		end

		for areaId,areaInfo in pairs(self.areaMonster) do
			if areaInfo.waveMax == 0 or areaInfo.waveIndex < areaInfo.waveMax then
				if areaInfo.interval and now - areaInfo.time >= areaInfo.interval then
					self:spawnMonsterArea(areaId)
				end
			end
		end

	elseif phase == sceneConst.eSCENE_PHASE.OVER then
		if now - self.overTime >= sceneConst.kDESTROY_TIME then
			local allUser = self:getAllObjByType(sceneConst.eSCENE_OBJ_TYPE.FIGHTER)
			if allUser and next(allUser) then
				for _,user in pairs(allUser) do
					self:kickUser(user)
				end
			end
		end
	end
end
