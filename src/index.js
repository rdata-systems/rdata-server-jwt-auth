const jwt = require('jsonwebtoken');

const requireProcessEnv = function requireProcessEnv(name){
    if (!process.env[name])
        throw new Error('You must set the ' + name + ' environment variable');
    return process.env[name];
};

var JwtAuthController = function JwtAuthController(server){
    if (this instanceof JwtAuthController === false) {
        return new JwtAuthController(server);
    }
    var self = this;
    self.server = server;

    self.jwtSecret = requireProcessEnv('JWT_SECRET');

    self.init = function(callback){
        callback();
        return self;
    };

    self.authorizeJwt = function(connection, params, callback){
        var accessToken = params.accessToken;
        if(!accessToken) return callback(new Error('Access token is invalid'));
        jwt.verify(accessToken, self.jwtSecret, function(err, token){
            if(err) return callback(err);
            connection.authorize(token.user.id, callback);
        });
    };

    self.exposedAnonymously = {
        'authorize': self.authorizeJwt
    };
};

module.exports.init = function InitJwtAuth(server){
    server.addController(JwtAuthController, 'jwtAuth');
};
