local BT_CONST = import "module.scene.ai.bt.bt_const"
local btTick = import "module.scene.ai.bt.core.Tick".btTick
local object = import "module.object"
local btBlackboard = import "module.scene.ai.bt.core.Blackboard".btBlackboard

local BLACKBOARD_SET = btBlackboard.set
local BLACKBOARD_GET = btBlackboard.get

cBtBaseNode = object.cObject:inherit("btBaseNode")

function cBtBaseNode:ctor(params)
	self.id = self.__objectId

	self.name = params.name
	self.title = params.title
	self.description = params.description

	if params.properties.precondition ~= "" then
		self.precondition = params.properties.precondition
	end

	if params.properties.operation ~= "" then
		self.operation = params.properties.operation
	end
end

function cBtBaseNode:_execute(tick)
	--ENTER

	self:_enter(tick)

	local status = BT_CONST.SUCCESS
	--OPEN
	if not (BLACKBOARD_GET(tick.blackboard, "isOpen", tick.tree.id, self.id)) then
		status = self:_open(tick)
	end

	if status == BT_CONST.SUCCESS then
		--TICK
		status = self:_tick(tick)

		--CLOSE
		if status ~= BT_CONST.RUNNING then
			self:_close(tick)
		end
	else
		self:_close(tick)
	end

	--EXIT
	self:_exit(tick)

	return status
end

function cBtBaseNode:_enter(tick)
	btTick.enterNode(tick,self)
	self:enter(tick)
end

function cBtBaseNode:_open(tick)
	btTick.openNode(tick,self)
	BLACKBOARD_SET(tick.blackboard, "isOpen", true, tick.tree.id, self.id)
	return self:open(tick)
end

function cBtBaseNode:_tick(tick)
	btTick.tickNode(tick,self)
	return self:tick(tick)
end

function cBtBaseNode:_close(tick)
	btTick.closeNode(tick,self)
	BLACKBOARD_SET(tick.blackboard, "isOpen", false, tick.tree.id, self.id)
	self:close(tick)
end

function cBtBaseNode:_exit(tick)
	btTick.exitNode(tick,self)
	self:exit(tick)
end

function cBtBaseNode:enter(tick)
end

function cBtBaseNode:open(tick)
	
	if self.precondition then
		local status = tick.target[self.precondition](tick.target)
		return status
	end
	return BT_CONST.SUCCESS
end

function cBtBaseNode:tick(tick)
end

function cBtBaseNode:close(tick)
end

function cBtBaseNode:exit(tick)
end

