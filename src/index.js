const jwt = require('jsonwebtoken');
const merge = require('merge');
const User = require('./services/user');

const requireProcessEnv = function requireProcessEnv(name){
    if (!process.env[name])
        throw new Error('You must set the ' + name + ' environment variable');
    return process.env[name];
};

module.exports.init = function InitJwtAuth(server){

    var controller = function JwtAuthController(){
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
            var selectedGroups = params.selectedGroups || null;

            if(!accessToken)
                return callback(new Error('Access token is invalid'));

            jwt.verify(accessToken, self.jwtSecret, function(err, decodedToken){
                if(err) return callback(err);

                var user = new User(decodedToken.user);

                if(selectedGroups && Array.isArray(selectedGroups) && selectedGroups.length > 0){ // If groups selected
                    // Check if user can actually select these groups
                    for(var i in selectedGroups){
                        if(selectedGroups.hasOwnProperty(i)) {
                            var groupId = selectedGroups[i];
                            if (!user.can("writeData", self.server.options.game, groupId))
                                return callback(new Error('user has no access to log data to this group')); // Return an error
                        }
                    }
                }

                var userPayload = merge(true, decodedToken.user, {
                    selectedGroups: selectedGroups
                });

                connection.authorize(decodedToken.user.id, params.gameVersion, userPayload, function (err) {
                    if(err) return callback(err);
                    callback(null, true);
                });
            });
        };

        self.exposedAnonymously = {
            'authorize': self.authorizeJwt
        };
    };

    server.addController(controller, 'jwtAuth');
};
