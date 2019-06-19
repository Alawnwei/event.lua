local event = require "event"
local BT_CONST = import "module.scene.ai.bt.bt_const"
local btBlackboard = import "module.scene.ai.bt.core.Blackboard".btBlackboard

local BLACKBOARD_SET = btBlackboard.set
local BLACKBOARD_GET = btBlackboard.get

cBtRepeatUntilSuccess = import("module.scene.ai.bt.core.Decorator").cBtDecorator:inherit("btRepeatUntilSuccess")

function cBtRepeatUntilSuccess:ctor(params)
	super(cBtRepeatUntilSuccess).ctor(self,params)
	self.maxLoop = params.properties.maxLoop or -1
end

function cBtRepeatUntilSuccess:open(tick)
	BLACKBOARD_SET(tick.blackboard, "i", 0, tick.tree.id, self.id)
	return super(cBtRepeatUntilSuccess).open(self,tick)
end

function cBtRepeatUntilSuccess:tick(tick)
	if not self.child then
		return BT_CONST.ERROR
	end

	local i = BLACKBOARD_GET(tick.blackboard, "i", tick.tree.id , self.id)
	local status = BT_CONST.ERROR

	while(self.maxLoop < 0 or i < self.maxLoop)
	do
		local status = self.child:_execute(tick)

		if status == BT_CONST.FAILURE then
			i = i + 1
		else
			break
		end
	end

	BLACKBOARD_SET(tick.blackboard, "i", i, tick.tree.id, self.id)
	return status
end
