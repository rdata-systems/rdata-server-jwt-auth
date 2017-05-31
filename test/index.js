const initJwtAuth = require('../src').init;
const merge = require('merge');
const assert = require('assert');
const jwt = require('jsonwebtoken');

var MockServer = function MockServer(){
    var self = this;
    self.controllers = {};
    self.exposed = {};
    self.exposedAnonymously = {};
    self.connections = [];
    self.options = { game: "testGame" };

    var MockConnection = function MockConnection(){
        var self = this;
        self.authorized = false;
        self.user = null;
        self.authorize = function(userId, gameVersion, userPayload, callback){
            self.authorized = true;
            self.user = {userId: userId, userPayload: userPayload};
            self.gameVersion = gameVersion;
            self.userPayload = userPayload;
            callback(null, true);
        }
    };

    self.addController = function(controller, controllerName){
        self.controllers[controllerName] = controller;
        self.exposed = merge(self.exposed, controller.exposed);
        self.exposedAnonymously = merge(self.exposedAnonymously, controller.exposedAnonymously);
    };

    self.authorize = function(params, callback){
        var connection = new MockConnection();
        self.connections.push(connection);
        self.exposedAnonymously['authorize'](connection, params, callback);
    };
};


describe('JwtAuth', function() {
    it('adds controller to the server controllers', function () {
        var server = new MockServer();
        initJwtAuth(server);
        assert(server.controllers["jwtAuth"]);
    });

    it('exposes authorize method on the server', function () {
        var server = new MockServer();
        initJwtAuth(server);
        assert(typeof server.exposedAnonymously["authorize"] === 'function');
    });

    it('authorizes using valid json web token', function (done) {
        var user = {id: "ASD123"};
        var token = jwt.sign({user: user}, process.env["JWT_SECRET"]);

        var server = new MockServer();
        initJwtAuth(server);
        assert(typeof server.exposedAnonymously["authorize"] === 'function');

        server.authorize({accessToken: token}, function(err, result){
            assert(result);
            assert(server.connections[0]);
            assert(server.connections[0].authorized);
            assert.equal(server.connections[0].user.userId, user.id);
            done();
        });
    });

    it('authorizes using valid json web token and provides selectedGroups', function (done) {
        var user = {id: "ASD123", roles: [{role:"readWriteData", game:"testGame", group:"2"},{role:"writeData", game:"testGame", group:"3"}]};
        var token = jwt.sign({user: user}, process.env["JWT_SECRET"]);

        var server = new MockServer();
        initJwtAuth(server);
        assert(typeof server.exposedAnonymously["authorize"] === 'function');

        server.authorize({accessToken: token, selectedGroups: ["2","3"]}, function(err, result){
            assert(result);
            assert(server.connections[0]);
            assert(server.connections[0].authorized);
            assert.equal(server.connections[0].user.userId, user.id);
            assert.equal(server.connections[0].userPayload.selectedGroups[0], 2);
            assert.equal(server.connections[0].userPayload.selectedGroups[1], 3);
            done();
        });
    });

    it('authorizes using valid json web token and provides incorrect selectedGroups', function (done) {
        var user = {id: "ASD123", groups: ["1","2","3"]};
        var token = jwt.sign({user: user}, process.env["JWT_SECRET"]);

        var server = new MockServer();
        initJwtAuth(server);
        assert(typeof server.exposedAnonymously["authorize"] === 'function');

        server.authorize({accessToken: token, selectedGroups: ["2","5"]}, function(err, result){
            assert(!result);
            done();
        });
    });

    it('fails to authorize with invalid token', function (done) {
        var user = {id: "ASD123"};
        var token = jwt.sign({user: user}, "INVALIDTOKEN");

        var server = new MockServer();
        initJwtAuth(server);
        assert(typeof server.exposedAnonymously["authorize"] === 'function');

        server.authorize({accessToken: token}, function(err, result){
            assert(err);
            assert(!result);
            assert(server.connections[0]);
            assert(!server.connections[0].authorized);
            done();
        });
    });

    it('fails to authorize with expired token', function (done) {
        var user = {id: "ASD123"};
        var token = jwt.sign({user: user}, process.env["JWT_SECRET"], { expiresIn: "1ms"});

        var server = new MockServer();
        initJwtAuth(server);
        assert(typeof server.exposedAnonymously["authorize"] === 'function');

        setTimeout(function(){
            server.authorize({accessToken: token}, function(err, result){
                assert(err);
                assert(!result);
                assert(server.connections[0]);
                assert(!server.connections[0].authorized);
                done();
            });
        }, 10);
    });
});

