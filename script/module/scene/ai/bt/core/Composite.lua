local BT_CONST = import "module.scene.ai.bt.bt_const"
local baseNode = import "module.scene.ai.bt.core.BaseNode"

cBtComposite = baseNode.cBtBaseNode:inherit("btComposite")

function cBtComposite:ctor(params)
	super(cBtComposite).ctor(self,params)
	self.category = BT_CONST.COMPOSITE
	self.children = {}
end