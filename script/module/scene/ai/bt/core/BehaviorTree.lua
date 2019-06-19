local BT_CONST = import "module.scene.ai.bt.bt_const"

local object = import "module.object"

cBtTree = object.cObject:inherit("btTree")

local eBtNode = {
	["Action"] 			= import "module.scene.ai.bt.core.Action".cBtAction,
	["Error"] 			= import "module.scene.ai.bt.actions.Error".cBtError,
	["Failer"] 			= import "module.scene.ai.bt.actions.Failer".cBtFailer,
	["Runner"] 			= import "module.scene.ai.bt.actions.Runner".cBtRunner,
	["Succeeder"] 		= import "module.scene.ai.bt.actions.Succeeder".cBtSucceeder,
	["Wait"] 			= import "module.scene.ai.bt.actions.Wait".cBtWait,
	["CommonAction"] 	= import "module.scene.ai.bt.actions.CommonAction".cBtCommonAction,
	["MemPriority"] 	= import "module.scene.ai.bt.composites.MemPriority".cBtMemPriority,
	["MemSequence"] 	= import "module.scene.ai.bt.composites.MemSequence".cBtMemSequence,
	["Priority"] 		= import "module.scene.ai.bt.composites.Priority".cBtPriority,
	["Sequence"] 		= import "module.scene.ai.bt.composites.Sequence".cBtSequence,
	["CommonCondition"] = import "module.scene.ai.bt.conditions.CommonCondition".cBtCommonCondition,
}

function cBtTree:ctor(title,description)
	self.id = self.__objectId
	self.title = title or "The behavior tree"
	self.description = description or "Default description"
	self.root = nil
end

function cBtTree:load(data)
	local nodes = {}

	for id,info in pairs(data.nodes) do
		local cls = eBtNode[info.name]
		assert(cls ~= nil,string.format("no found bt node:%s",info.name))

		nodes[id] = cls:new(info)
	end

	for id,info in pairs(data.nodes) do
		local node = nodes[id]

		if info.children and node.category == BT_CONST.COMPOSITE then
			for i = 1,#info.children do
				local cid = info.children[i]
				table.insert(node.children, nodes[cid])
			end
		elseif info.child and node.category == BT_CONST.DECORATOR then
			local cid = info.children[i]
			node.child = nodes[cid]
		end
	end

	self.root = nodes[data.root]
end


function cBtTree:onTick()
	--TICK NODE
	return self.root:_execute(self.tick)
end
