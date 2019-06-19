local http = require "http"
local event = require "event"
local cjson = require "cjson"
local helper = require "helper"
local count = 0

event.fork(function ()
    -- local count = 0
    -- local httpd,reason = http.listen("tcp://127.0.0.1:1989",function (channel,method,url,header,body)
    --     event.fork(function ()
    --         count = count + 1
    --         print(method,url,body,count)
    --         -- channel:close()
    --         channel:reply(200,"ok")
    --     end)

    -- end)
    -- if not httpd then
    --     event.error(string.format("world http listen:%s failed:%s",env.world_http,reason))
    --     os.exit(1)
    -- end
    -- event.error(string.format("world http listen:%s success",env.world_http))

    local get_count = 0
    local post_count = 0
    local count = 1024*10
    local ti = event.now()
    for i = 1,count do
        -- http.get("127.0.0.1:1989","/mrq/a/b/c",{},{},nil,function (code,header,content)
        --     get_count = get_count + 1
        --     if get_count == count then
        --         print("get diff",event.now() - ti)
        --     end
        -- end)

        http.post("192.168.20.50:1989","/mrq/a/b/c?a=1&&b=2",{},{a = 1,b = 2,c = 3},nil,function (code, error, header,content)
             post_count = post_count + 1
            print(code,error)
            if post_count == count then
                print("post diff",event.now() - ti)
                -- event.breakout()
            end
        end)
    end
end)


