env = require('test_run')
test_run = env.new()
box.schema.user.grant('guest', 'read,write,execute', 'universe')

errinj = box.error.injection

box.schema.user.grant('guest', 'replication')
s = box.schema.space.create('test');
index = s:create_index('primary')

test_run:cmd("create server replica with rpl_master=default, script='replication/replica.lua'")
test_run:cmd("start server replica")
test_run:cmd("switch replica")

fiber = require('fiber')

s = box.space.test
test_run:cmd("setopt delimiter ';'")
function wait_repl(cnt)
    for i = 1, 20 do
        if s.index[0]:len() >= cnt then
            return true
        end
        fiber.sleep(0.01)
    end
    return false
end;
test_run:cmd("setopt delimiter ''");

test_run:cmd("switch default")
d = require('digest')

test_run:cmd("setopt delimiter ';'")
function test_f(st, tx)
    if tx then
        box.begin()
    end
    for i = st, st + 9 do
        local _ = s:insert({i, d.urandom(8192)})
    end
    if tx then
        box.commit()
    end
end;
test_run:cmd("setopt delimiter ''");

test_f(1)

errinj.set("ERRINJ_WAL_WRITE_PARTIAL", true)
test_f(11, true)

errinj.set("ERRINJ_WAL_WRITE_PARTIAL", false)

test_f(11, true)
test_f(21, true)

test_run:cmd("switch replica")
wait_repl(30)

test_run:cmd("switch default")
box.space.test.index[0]:len()

errinj.set("ERRINJ_WAL_WRITE_DISK", true)
test_f(31, true)

errinj.set("ERRINJ_WAL_WRITE_DISK", false)

test_f(31, true)
test_f(41, true)

test_run:cmd("switch replica")
wait_repl(50)

test_run:cmd("switch default")
box.space.test.index[0]:len()

box.schema.user.revoke('guest', 'read,write,execute', 'universe')
box.schema.user.revoke('guest', 'replication')
