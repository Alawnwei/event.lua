local BT_CONST = import "module.scene.ai.bt.bt_const"


cBtInverter = import("module.scene.ai.bt.core.Decorator").cBtDecorator:inherit("btInverter")

function cBtInverter:ctor(params)
	super(cBtInverter).ctor(self,params)
end

function cBtInverter:tick(tick)
	if not self.child then
		return BT_CONST.ERROR
	end

	local status = self.child:_execute(tick)

	if status == BT_CONST.SUCCESS then
		status = BT_CONST.FAILURE
	elseif status == BT_CONST.FAILURE then
		status = BT_CONST.SUCCESS
	end

	return status
end
