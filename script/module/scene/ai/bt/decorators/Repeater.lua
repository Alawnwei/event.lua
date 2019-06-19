local event = require "event"
local BT_CONST = import "module.scene.ai.bt.bt_const"
local btBlackboard = import "module.scene.ai.bt.core.Blackboard".btBlackboard

local BLACKBOARD_SET = btBlackboard.set
local BLACKBOARD_GET = btBlackboard.get

cBtRepeater = import("module.scene.ai.bt.core.Decorator").cBtDecorator:inherit("btRepeater")

function cBtRepeater:ctor(params)
	super(cBtRepeater).ctor(self,params)
	self.maxLoop = params.properties.maxLoop or -1
end

function cBtRepeater:open(tick)
	BLACKBOARD_SET(tick.blackboard, "i", 0, tick.tree.id, self.id)
	return super(cBtRepeater).open(self,tick)
end

function cBtRepeater:tick(tick)
	if not self.child then
		return BT_CONST.ERROR
	end

	local i = BLACKBOARD_GET(tick.blackboard, "i", tick.tree.id , self.id)
	local status = BT_CONST.SUCCESS

	while(self.maxLoop < 0 or i < self.maxLoop)
	do
		local status = self.child:_execute(tick)
		if status == BT_CONST.SUCCESS or status == BT_CONST.FAILURE then
			i = i + 1
		else
			break
		end
	end

	BLACKBOARD_SET(tick.blackboard, "i", i, tick.tree.id, self.id)
	return status
end
