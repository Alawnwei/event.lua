local BT_CONST = import "module.scene.ai.bt.bt_const"
local baseNode = import "module.scene.ai.bt.core.BaseNode"

cBtDecorator = baseNode.cBtBaseNode:inherit("btDecorator")

function cBtDecorator:ctor(params)
	super(cBtDecorator).ctor(self, params)

	self.category = BT_CONST.DECORATOR

	self.child = nil
end
