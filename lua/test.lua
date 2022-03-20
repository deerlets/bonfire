local bflua = require('bonfirelua');
local exit_flag = 0;

bf = bflua.new();
bflua.connect(bf, "tcp://127.0.0.1:18338");

function hello(content)
  print(content);
  return "hello";
end

bflua.add_service(bf, "bonfirelua://hello", hello);

-- servcall is synchronous
print(bflua.servcall(bf, "tag://info", "{\"__token__\":\""..arg[1].."\"}"));

bflua.subscribe(bf, "tag/update", function(content)
  print(content);
end);

while exit_flag do
  bflua.loop(bf, 1000);
end

bflua.destroy(bf);
