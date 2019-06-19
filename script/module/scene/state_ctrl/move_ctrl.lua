local util = require "util"
local event = require "event"
local object = import "module.object"

cMoveCtrl = object.cObject:inherit("moveCtrl")

local dtDot2Dot = util.dot2dot
local moveForward = util.move_forward

function cMoveCtrl:ctor(sceneObj)
	self.ownerObj = sceneObj
end

function cMoveCtrl:onCreate()
end

function cMoveCtrl:onDestroy()
end

function cMoveCtrl:onUpdate(now)
	return self:doMove(now)
end

function cMoveCtrl:onClientMoveStart(path)
	local stateMgr = self.ownerObj.stateMgr

	if not stateMgr:canAddState("MOVE") then
		return false
	end

	return self:prepareMove(path)
end

function cMoveCtrl:onClientMoveStop(pos,angle)
	local stateMgr = self.ownerObj.stateMgr
	if stateMgr:hasState("MOVE") then
		self:doMove()
		stateMgr:delState("MOVE")
	end

	local location = self.ownerObj.pos
	local dt = dtDot2Dot(pos[1],pos[2],location[1],location[2])
	if dt <= 0.1 then
		self.ownerObj:move(pos[1],pos[2])
	else
		protocol.writer.sObjFixPos(self.ownerObj.cid,location)
	end

	local witness = self.ownerObj:getWitnessCid()
	protocol.writer.sObjMoveStop(witness,location)
end

function cMoveCtrl:onServerMoveStart(path)
	return self:prepareMove(path)
end

function cMoveCtrl:prepareMove(path)
	local stateMgr = self.ownerObj.stateMgr

	if stateMgr:hasState("MOVE") then
		self:doMove()
		stateMgr:delState("MOVE")
	end

	local pathNode = path[1]
	local pos = self.ownerObj.pos

	local dt = dtDot2Dot(pos[1],pos[2],pathNode[1],pathNode[2])
	if dt > self.ownerObj.speed / 10 then
		-- protocol.writer.sObjFixPos(self.ownerObj.cid,pos)
		return false
	else
		self.ownerObj:move(pathNode[1],pathNode[2])
	end

	self.pathIndex = 2
	self.pathIndexMax = #path
	self.pathList = path
	
	self.lastTime = event.now()

	stateMgr:addState("MOVE")

	local witness = self.ownerObj:getWitnessCid()

	-- protocol.writer.sObjMove(witness,self.pathList)

	return true
end

function cMoveCtrl:doMove(now)
	
	local now = now or event.now()

	local dtTime = (now - self.lastTime) / 1000

	local pathIndex = self.pathIndex
	local pathIndexMax = self.pathIndexMax
	local pathList = self.pathList

	local dtMove = self.ownerObj.speed * dtTime
	
	local pathNode = pathList[pathIndex]

	local nodeX = pathNode[1]
	local nodeZ = pathNode[2]

	local locationX = self.ownerObj.pos[1]
	local locationZ = self.ownerObj.pos[2]

	local dtNext = dtDot2Dot(locationX,locationZ,nodeX,nodeZ)

	while dtMove - dtNext >= 0.1 do
		self.ownerObj:move(nodeX,nodeZ)

		pathIndex = pathIndex + 1
		if pathIndex > pathIndexMax then
			break
		end

		dtMove = dtMove - dtNext
		
		locationX = self.ownerObj.pos[1]
		locationZ = self.ownerObj.pos[2]

		pathNode = pathList[pathIndex]

		nodeX = pathNode[1]
		nodeZ = pathNode[2]

		dtNext = dtDot2Dot(locationX,locationZ,nodeX,nodeZ)
	end

	self.pathIndex = pathIndex

	self.lastTime = now

	if pathIndex > pathIndexMax then
		return true
	end

	local nx,nz = moveForward(locationX,locationZ,nodeX,nodeZ,dtMove)
	self.ownerObj:move(nx,nz)
	return false
end

function cMoveCtrl:getPath()
	-- if self.pathIndex > self.pathIndexMax then
	-- 	return
	-- end

	-- local path = {}
	-- path[1] = {self.ownerObj.pos[1],self.ownerObj.pos[2]}

	-- for i = self.pathIndex,self.pathIndexMax do
	-- 	table.insert(path,self.pathList[i])
	-- end
	-- return path
end
