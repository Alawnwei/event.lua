local aoi_core = require "simpleaoi.core"
local event = require "event"
local util = require "util"
local vector2 = util.vector2
local helper = require "helper"

local aoi = aoi_core.new(1001,1000,1000,5,5)

local object_ctx = {}
local aoi_ctx = {}

local object = {}

function object:new(id,x,z)
	local ctx = setmetatable({},{__index = self})
	ctx.x = x
	ctx.z = z
	ctx.id = id

	local enter_self,enter_other

	ctx.aoi_id,enter_self,enter_other = aoi:enter(id,x,z,2)
	for _,other_id in pairs(enter_other) do
		local other = object_ctx[other_id]
		other:enter(ctx)
	end

	for _,other_id in pairs(enter_self) do
		local other = object_ctx[other_id]
		ctx:enter(other)
	end

	object_ctx[id] = ctx

	return ctx
end

function object:move(x,z)
	self.x = x
	self.z = z

	local enter,leave = aoi:update(self.aoi_id,x,z)

	for _,id in pairs(enter) do
		local other = object_ctx[id]
		other:enter(self)
		self:enter(other)
	end

	for _,id in pairs(leave) do
		local other = object_ctx[id]
		other:leave(self)
		self:leave(other)
	end

end

function object:enter(other)
	-- print(string.format("enter:%d:[%f,%f],%d:[%f:%f],%f",self.id,self.x,self.z,other.id,other.x,other.z,util.distance(self.x,self.z,other.x,other.z)))
end

function object:leave(other)
	-- print(string.format("leave:%d:[%f,%f],%d:[%f:%f],%f",self.id,self.x,self.z,other.id,other.x,other.z,util.distance(self.x,self.z,other.x,other.z)))
end

for i = 1,5000 do
	local obj = object:new(i,math.random(0,999),math.random(0,999))
end

local move_set = {}

for i = 1,5000 do
	event.fork(function ()
		local move_obj = object_ctx[i]
		while true do
			local x,z = math.random(0,999),math.random(0,999)
			while true do
				event.sleep(0.1)
				local rx,rz = util.move_forward(move_obj.x,move_obj.z,x,z,5)
				local ox,oz = move_obj.x,move_obj.z
				move_obj:move(rx,rz)
				if util.distance(ox,oz,rx,rz) <= 1 then
					break
				end
			end
		end
	end)
end
