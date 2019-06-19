local util = require "util"
local vector2 = require "common.vector2"
local object = import "module.object"

cAttrMgr = object.cObject:inherit("attrMgr")


function cAttrMgr:ctor(sceneObj)
	self.attrCtx = {}
	self.attrMgr = {}
	self.attrGroup = {}
	self.attrDirty = false
	self.counter = 1
	self.owner = sceneObj
end

function cAttrMgr:onCreate()
end

function cAttrMgr:onDestroy()

end

function cAttrMgr:getAttr(attr)

end

function cAttrMgr:addAttr(attrList)
	local attrId = self.counter
	self.counter = self.counter + 1
	
	local oAttrVar = {}
	local nAttrVar = {}
	for _,attrPair in pairs(attrList) do
		local oVar = oAttrVar[attrPair.attr]
		if not oVar then
			oVar = self.owner:getAttr(attrPair.attr)
			oAttrVar[attrPair.attr] = oVar
			nAttrVar[attrPair.attr] = oVar
		end
		nAttrVar[attrPair.attr] = nAttrVar[attrPair.attr] + attrPair.value
	end

	self.attrCtx[attrId] = attrList

	self.attrDirty = true
	return attrId
end

function cAttrMgr:delAttr(attrId)
	local attrList = self.attrCtx[attrId]
	if not attrList then
		return
	end
	attrList[attrId] = nil

	self.attrDirty = true
end

function cAttrMgr:addAttrByGroup(group,attrList)
	local attrId = self:addAttr(attrList)

	local groupInfo = self.attrGroup[group]
	if not groupInfo then
		groupInfo = {}
		self.attrGroup[group] = groupInfo
	end
	table.insert(groupInfo,attrId)
end

function cAttrMgr:delAttrByGroup(group)
	local groupInfo = self.attrGroup[group]
	if not groupInfo then
		return
	end

	for _,attrId in pairs(groupInfo) do
		self:delAttr(attrId)
	end
end

function cAttrMgr:flushAttr()

end