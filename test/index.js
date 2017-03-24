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

    var MockConnection = function MockConnection(){
        var self = this;
        self.authenticated = false;
        self.user = null;
        self.authenticate = function(userId, callback){
            self.authenticated = true;
            self.user = {userId: userId};
            callback(null, true);
        }
    };

    self.addController = function(Controller, controllerName){
        var controller = new Controller();
        self.controllers[controllerName] = controller;
        self.exposed = merge(self.exposed, controller.exposed);
        self.exposedAnonymously = merge(self.exposedAnonymously, controller.exposedAnonymously);
    };

    self.authenticate = function(params, callback){
        var connection = new MockConnection();
        self.connections.push(connection);
        self.exposedAnonymously['authenticate'](connection, params, callback);
    };
};


describe('JwtAuth', function() {
    it('adds controller to the server controllers', function () {
        var server = new MockServer();
        initJwtAuth(server);
        assert(server.controllers["jwtAuth"]);
    });

    it('exposes authenticate method on the server', function () {
        var server = new MockServer();
        initJwtAuth(server);
        assert(typeof server.exposedAnonymously["authenticate"] === 'function');
    });

    it('authenticates using valid json web token', function (done) {
        var user = {id: "ASD123"};
        var token = jwt.sign({user: user}, process.env["JWT_SECRET"]);

        var server = new MockServer();
        initJwtAuth(server);
        assert(typeof server.exposedAnonymously["authenticate"] === 'function');

        server.authenticate({accessToken: token}, function(err, result){
            assert(result);
            assert(server.connections[0]);
            assert(server.connections[0].authenticated);
            assert(server.connections[0].user.userId === user.id);
            done();
        });
    });

    it('fails to authenticate with invalid token', function (done) {
        var user = {id: "ASD123"};
        var token = jwt.sign({user: user}, "INVALIDTOKEN");

        var server = new MockServer();
        initJwtAuth(server);
        assert(typeof server.exposedAnonymously["authenticate"] === 'function');

        server.authenticate({accessToken: token}, function(err, result){
            assert(err);
            assert(!result);
            assert(server.connections[0]);
            assert(!server.connections[0].authenticated);
            done();
        });
    });

    it('fails to authenticate with expired token', function (done) {
        var user = {id: "ASD123"};
        var token = jwt.sign({user: user}, process.env["JWT_SECRET"], { expiresIn: "1ms"});

        var server = new MockServer();
        initJwtAuth(server);
        assert(typeof server.exposedAnonymously["authenticate"] === 'function');

        setTimeout(function(){
            server.authenticate({accessToken: token}, function(err, result){
                assert(err);
                assert(!result);
                assert(server.connections[0]);
                assert(!server.connections[0].authenticated);
                done();
            });
        }, 10);
    });
});

