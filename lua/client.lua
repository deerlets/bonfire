local bflua = require('bonfirelua');
local exit_flag = 0;

bf = bflua.new();
bflua.connect(bf, "tcp://127.0.0.1:52338");

print(bflua.servcall(bf, "lua://hello", "{}"));

bflua.destroy(bf);
