local BT_CONST = import "module.scene.ai.bt.bt_const"
local baseNode = import "module.scene.ai.bt.core.BaseNode"

cBtAction = baseNode.cBtBaseNode:inherit("btAction")

function cBtAction:ctor(params)
	super(cBtAction).ctor(self,params)
	self.category = BT_CONST.ACTION
end

