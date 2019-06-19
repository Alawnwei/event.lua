local util = require "util"
local event = require "event"
local object = import "module.object"

cBulletCtrl = object.cObject:inherit("bulletCtrl")

local dir2angle = util.dir2angle
local dtDot2Dot = util.dot2dot
local moveTorward = util.move_torward
local moveForward = util.move_forward

function cBulletCtrl:ctor(sceneObj)
	self.owner = sceneObj
	self.lastTime = event.now()
end

function cBulletCtrl:onCreate()
end

function cBulletCtrl:onDestroy()

end

function cBulletCtrl:onUpdate(now)
	local now = now or event.now()
	local ownerObj = self.owner

	local dtTime = (now - self.lastTime) / 1000

	local ox = ownerObj.pos[1]
	local oz = ownerObj.pos[2]

	local endPos = ownerObj:getEndPos()

	local endX = endPos[1]
	local endZ = endPos[2]

	local dx = endX - ox
	local dz = endZ - oz

	local angle = dir2angle(dx,dz)

	local dtMove = dtTime * ownerObj.speed

	local dt = dtDot2Dot(ox,oz,endX,endZ)

	local isFlyOver = false
	if dtMove >= dt then
		dtMove = dt
		isFlyOver = true
	end

	local nx,nz = moveTorward(ox,oz,angle,dtMove)

	ownerObj:move(nx,nz)

	self.lastTime = now

	local isOver = ownerObj:doCollision({ox,oz},{nx,nz})
	
	return isFlyOver or isOver
end

