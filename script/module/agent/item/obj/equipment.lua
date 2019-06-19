local idBuilder = import "module.id_builder"
local item = import "module.agent.item.obj.item"


cEquipment = item.cItem:inherit("equipment")


function cEquipment:onCreate(cid,amount)
	super(cEquipment).onCreate(self,cid,amount)
end

function cEquipment:onDestroy()

end


--[[
itemAttr = {
	int key
	int value
}
itemExtraInfo = {
	itemAttr[] attrInfo
}
sItemInfo = {
	itemBaseInfo baseInfo
	itemExtraInfo extraInfo
}
]]
function cEquipment:getExtraInfo()

end
