local BT_CONST = import "module.scene.ai.bt.bt_const"

cBtSequence = import("module.scene.ai.bt.core.Composite").cBtComposite:inherit("btSequence")

function cBtSequence:ctor(params)
	super(cBtSequence).ctor(self,params)
end

function cBtSequence:tick(tick)
	for _,v in pairs(self.children) do
		local status = v:_execute(tick)
		if status ~= BT_CONST.SUCCESS then
			return status
		end
	end
	return BT_CONST.SUCCESS
end
