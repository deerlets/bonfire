const addon = require('./build/Release/bonfire').bonfire;
const EventEmitter = require('events').EventEmitter;

function Bonfire (address) {
    this.addon = new addon(address);
    this.addon.loop(1000);
}

Bonfire.prototype = new EventEmitter;

Bonfire.prototype.loop = function(timeout) {
    return this.addon.loop(timeout);
};

Bonfire.prototype.addService = function(header, callback) {
    return this.addon.addService(header, callback);
};

Bonfire.prototype.delService = function(header) {
    return this.addon.delService(header);
};

Bonfire.prototype.servsync = function(header, content) {
    return this.addon.servsync(header, content);
};

Bonfire.prototype.servcall = function(header, content) {
    return this.addon.servcall(header, content);
};

Bonfire.prototype.publish = function(topic, content) {
    return this.addon.publish(topic, content);
};

Bonfire.prototype.subscribe = function(topic) {
    return this.addon.subscribe(topic, (content) => {
        this.emit(topic, content);
    });
};

Bonfire.prototype.unsubscribe = function(topic) {
    return this.addon.unsubscribe(topic);
};

module.exports = Bonfire;
