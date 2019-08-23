const bonfire = require('./build/Release/bonfire').bonfire;

const bf = new bonfire("tcp://127.0.0.1:18338");

data = {
    header: 'bonfire://service/add'
};

var promise = bf.servcall("bonfire://service/info", data);
promise.then((content) => {
    console.log("1");
    console.log(content);
});

bf.subscribe("point#update", (content) => {
    console.log(content);
});

process.on('SIGINT', () => {
    console.log("Capture SIGINT");
    process.exit(1);
});

bf.loop(1000);

setInterval(() => {
    //console.log("timeout");
}, 1000);

//bf.unsubscribe("point#update");

bf.servcall("bonfire://service/info", data).then((content) => {
    console.log("2");
    console.log(content);
    return bf.servcall("bonfire://service/info", data);
}).then((content) => {
    console.log("3");
    console.log(content);
    return bf.servcall("bonfire://service/info", data);
}).then((content) => {
    console.log("4");
    console.log(content);
    return bf.servcall("bonfire://service/info", data);
}).then((content) => {
    console.log("5");
    console.log(content);
    return bf.servcall("bonfire://service/info", data);
}).then((content) => {
    console.log("6");
    console.log(content);
    return bf.servcall("bonfire://service/info", data);
}).then((content) => {
    console.log("7");
    console.log(content);
    return bf.servcall("bonfire://service/info", data);
}).then((content) => {
    console.log("8");
    console.log(content);
    return bf.servcall("bonfire://service/info", data);
});
