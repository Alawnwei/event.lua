local event = require "event"
local channel = require "channel"
local http = require "http"
local handler = import "handler.web_handler"

event.fork(function ()
    local addr = "tcp://0.0.0.0:8083"
    local httpd = http.listen(addr,function (channel,method,url,header,body)
        event.fork(function ()
            channel:set_header("Content-Type","text/html; charset=utf-8")

            local ok,info = pcall(handler.dispatcher,channel,header,url,body)
            if not ok then
                print(info)
                -- channel:set_header("Refresh", "2;url='http://192.168.100.55:8083/index'");
                channel:reply(404,info)
            else
                channel:reply(200,info)
            end
        end)

    end)
    if not httpd then
        event.error(string.format("httpd listen client:%s failed",addr))
        os.exit(1)
    end
    event.error(string.format("httpd listen client:%s success",addr))
end)
