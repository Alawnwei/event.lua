local common = import "common.common"

function __init__(self)
end

local categoryCreator = {
	[common.eITEM_CATETORY.ITEM] = import "module.agent.item.obj.item".cItem,
	[common.eITEM_CATETORY.CURRENCY] = import "module.agent.item.obj.currency".cCurrency,
	[common.eITEM_CATETORY.EQUIPMENT] = import "module.agent.item.obj.equipment".cEquipment,
	[common.eITEM_CATETORY.MATERIAL] = import "module.agent.item.obj.material".cMaterial,
	[common.eITEM_CATETORY.PROPS] = import "module.agent.item.obj.props".cProps,
	[common.eITEM_CATETORY.PET] = import "module.agent.item.obj.pet".cPet,
}


	
function createItem(self,cid,amount)
	local itemConf = config.item[cid]
	assert(itemConf ~= nil,cid)
	local creator = categoryCreator[itemConf.category]

	local result = {}

	local left = amount
	while left > 0 do
		local count
		if not itemConf.overlap or itemConf.overlap == 0 then
			left = 0
			count = amount
		else
			if left > itemConf.overlap then
				count = itemConf.overlap
				left = left - itemConf.overlap
			else
				count = left
				left = 0
			end
		end
		local item = creator:new()
		item:onCreate(cid,count)
		table.insert(result,item)
	end
	return result
end
