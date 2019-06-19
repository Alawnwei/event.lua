local BT_CONST = import "module.scene.ai.bt.bt_const"

cBtCommonCondition = import("module.scene.ai.bt.core.Condition").cBtCondition:inherit("btCommonCondition")

function cBtCommonCondition:ctor(params)
	super(cBtCommonCondition).ctor(self,params)

	assert(params.properties.assertFunc ~= nil)

	self.assertFunc = params.properties.assertFunc
	if params.properties.assertValue ~= '' then
		self.assertValue = params.properties.assertValue
	end
end

function cBtCommonCondition:tick(tick)
	local result = tick.target[self.assertFunc](tick.target)
	if self.assertValue and result == self.assertValue then
		return BT_CONST.SUCCESS
	end
	return result
end
