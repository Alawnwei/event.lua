local util = require "util"
local idBuilder = import "module.id_builder"
local itemFactory = import "module.agent.item.item_factory"
local itemMgr = import "module.agent.item.item_manager"

cEquipmentMgr = itemMgr.cItemMgr:inherit("equipmentMgr")

function __init__(self)
end



function cEquipmentMgr:onCreate(...)
	super(cEquipmentMgr).onCreate(self)
end

function cEquipmentMgr:onDestroy()
	super(cEquipmentMgr).onDestroy(self)
end

function cEquipmentMgr:onEnterGame(user)
	super(cEquipmentMgr).onEnterGame(self,user)

	local equipSlot = {}
	for uid,item in pairs(self.itemSlot) do
		local part = util.decimal_bit(item.cid)
		equipSlot[part] = uid
	end

	self.equipSlot = equipSlot
end

function cEquipmentMgr:onInsertItem(item)
	local part = util.decimal_bit(item.cid)
	self.equipSlot[part] = item.uid
end

function cEquipmentMgr:onDeleteItem(item)
	local part = util.decimal_bit(item.cid)
	self.equipSlot[part] = nil
end

function cEquipmentMgr:puton(item)
	local part = util.decimal_bit(item.cid)
	if self.equipSlot[part] then
		self:takedown(part)
	end
	self:insertItem(item)
end

function cEquipmentMgr:takedown(part)
	local uid = self.equipSlot[part]
	self:deleteItemByUid(uid,1)
end

