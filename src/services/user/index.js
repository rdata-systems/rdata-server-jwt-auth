'use strict';

/**
 * Provides a service to work with user roles
 */
const ROLE_READ = "read";
const ROLE_WRITE = "write";
const ROLE_READ_WRITE = "readWrite";
const ROLE_READ_DATA = "readData";
const ROLE_WRITE_DATA = "writeData";
const ROLE_READ_WRITE_DATA = "readWriteData";

const roles = {};
roles[ROLE_READ] =              parseInt('0001', 2);
roles[ROLE_WRITE] =             parseInt('0010', 2);
roles[ROLE_READ_WRITE] =        parseInt('0011', 2);
roles[ROLE_READ_DATA] =         parseInt('0100', 2);
roles[ROLE_WRITE_DATA] =        parseInt('1000', 2);
roles[ROLE_READ_WRITE_DATA] =   parseInt('1100', 2);

function User(jwtUser){
    var self = this;

    this.id = jwtUser.id;
    this.email = jwtUser.email;
    this.username = jwtUser.username;
    this.roles = jwtUser.roles;

    this.can = function can(){
        var role, game, group; // arguments
        if(arguments.length === 0)
            throw new Error("can requires at least 1 argument");

        if(typeof arguments[0] === 'object'){
            role = arguments[0].role || null;
            game = arguments[0].game || null;
            group = arguments[0].group || null;
        }
        else
        {
            role = arguments[0];
            game = arguments.length > 0 ? arguments[1] : null;
            group = arguments.length > 1 ? arguments[2] : null;
        }

        // Check if user has any role that matches the pattern
        for(var i in this.roles){
            var userRole = this.roles[i];
            if((roles[role] & roles[userRole.role]) === roles[role] &&
                (!userRole.group || group === userRole.group) &&
                (!userRole.game || game === userRole.game))
                return true;
        }
        return false;
    }

}

module.exports = User;