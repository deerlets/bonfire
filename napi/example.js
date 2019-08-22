const bonfire = require('./build/Release/bonfire').bonfire;

const bf = new bonfire("tcp://127.0.0.1:18338");

data = {
    header: 'bonfire://service/add'
};

bf.servcall("bonfire://service/info", data, (content) => {
    console.log(content);
});

bf.subscribe("point#update", (content) => {
    console.log(content);
});

var exit_flag = 0;

//process.on('SIGINT', () => {
//    console.log("Capture SIGINT");
//    exit_flag = 1;
//});

while (exit_flag === 0)
    bf.loop(1000);

bf.unsubscribe("point#update");
