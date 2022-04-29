local libbf = require('bonfirelua');
local exit_flag = 0;

brk = libbf.broker_new("tcp://127.0.0.1:52338");

while exit_flag do
  libbf.broker_loop(brk, 1000);
end

libbf.broker_destroy(brk);
