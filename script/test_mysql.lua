




local event = require "event"
local mysql_core = require "luasql.mysql"
local mysql_core = mysql_core.mysql()

local mysql,err = mysql_core:connect("test","root","2444cc818a3bbc06","127.0.0.1",3306)
print(mysql,err)

local function createUser()
	local CREATE_TABLE_USER = [[
		CREATE TABLE IF NOT EXISTS `user`(
		   `userUid` INT UNSIGNED AUTO_INCREMENT,
		   `name` VARCHAR(100) NOT NULL,
		   `level` INT UNSIGNED,
		   PRIMARY KEY ( `userUid` )
		)ENGINE=InnoDB DEFAULT CHARSET=utf8;
	]]

	print(mysql:execute(CREATE_TABLE_USER))

	for i=1,1024 * 1024 do
		local sql = string.format("insert into user (name,level) values (\"%s\",%d)","mrq@"..i,math.random(1,50))
		print(mysql:execute(sql))
	end
end

local function createItem(userUid)
	local CREATE_TABLE_ITEM = [[
		CREATE TABLE IF NOT EXISTS `item`(
		   `itemUid` INT UNSIGNED AUTO_INCREMENT,
		   `userUid` INT UNSIGNED,
		   `cfgId` INT UNSIGNED,
		   `amount` INT UNSIGNED,
		   PRIMARY KEY ( `itemUid` ),
		   KEY `userUid` (`userUid`) USING BTREE
		)ENGINE=InnoDB DEFAULT CHARSET=utf8;
	]]

	mysql:execute(CREATE_TABLE_ITEM)

	for i=1,100 do
		local sql = string.format("insert into item (userUid,cfgId,amount) values (%d,%d,%d)",userUid,math.random(1,50),math.random(1,10))
		print(mysql:execute(sql))
	end
end

-- createUser()

-- for i = 1,449334 do
-- 	createItem(i)
-- end