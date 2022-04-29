local libbf = require('bonfirelua');
local exit_flag = 0;

bf = libbf.new();
libbf.connect(bf, "tcp://127.0.0.1:52338");

function hello(content)
  print(content);
  return "hello lua for bonfire";
end

libbf.add_service(bf, "lua://hello", hello);

while exit_flag do
  libbf.loop(bf, 1000);
end

libbf.destroy(bf);
