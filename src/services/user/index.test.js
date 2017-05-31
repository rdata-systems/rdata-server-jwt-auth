const User = require('.');
const assert = require('assert');

describe('user service', function() {
    it('can read', function() {
        var user = new User({ id:1, email:'a@a.com', username: 'a', 'roles': [{role: "read" }] });
        assert(user.can({ role: "read"}));
        assert(user.can({ role: "read", game: "histology"}));
        assert(user.can({ role: "read", game: "embryology"}));
        assert(user.can({ role: "read", group: 123}));
        assert(user.can({ role: "read", group: 456}));
        assert(user.can({ role: "read", game: "histology", group: 123}));
        assert(user.can({ role: "read", game: "embryology", group: 456}));

        assert(!user.can({ role: "write"}));
        assert(!user.can({ role: "write", game: "histology"}));
        assert(!user.can({ role: "write", game: "embryology"}));
        assert(!user.can({ role: "write", group: 123}));
        assert(!user.can({ role: "write", group: 456}));
        assert(!user.can({ role: "write", game: "histology", group: 123}));
        assert(!user.can({ role: "write", game: "embryology", group: 456}));

        assert(!user.can({ role: "readWrite"}));
        assert(!user.can({ role: "readWrite", game: "histology"}));
        assert(!user.can({ role: "readWrite", game: "embryology"}));
        assert(!user.can({ role: "readWrite", group: 123}));
        assert(!user.can({ role: "readWrite", group: 456}));
        assert(!user.can({ role: "readWrite", game: "histology", group: 123}));
        assert(!user.can({ role: "readWrite", game: "embryology", group: 456}));
    });

    it('can write', function() {
        var user = new User({ id:1, email:'a@a.com', username: 'a', 'roles': [{role: "write" }] });
        assert(!user.can({ role: "read"}));
        assert(!user.can({ role: "read", game: "histology"}));
        assert(!user.can({ role: "read", game: "embryology"}));
        assert(!user.can({ role: "read", group: 123}));
        assert(!user.can({ role: "read", group: 456}));
        assert(!user.can({ role: "read", game: "histology", group: 123}));
        assert(!user.can({ role: "read", game: "embryology", group: 456}));

        assert(user.can({ role: "write"}));
        assert(user.can({ role: "write", game: "histology"}));
        assert(user.can({ role: "write", game: "embryology"}));
        assert(user.can({ role: "write", group: 123}));
        assert(user.can({ role: "write", group: 456}));
        assert(user.can({ role: "write", game: "histology", group: 123}));
        assert(user.can({ role: "write", game: "embryology", group: 456}));

        assert(!user.can({ role: "readWrite"}));
        assert(!user.can({ role: "readWrite", game: "histology"}));
        assert(!user.can({ role: "readWrite", game: "embryology"}));
        assert(!user.can({ role: "readWrite", group: 123}));
        assert(!user.can({ role: "readWrite", group: 456}));
        assert(!user.can({ role: "readWrite", game: "histology", group: 123}));
        assert(!user.can({ role: "readWrite", game: "embryology", group: 456}));
    });

    it('can readWrite', function() {
        var user = new User({ id:1, email:'a@a.com', username: 'a', 'roles': [{role: "readWrite" }] });
        assert(user.can({ role: "read"}));
        assert(user.can({ role: "read", game: "histology"}));
        assert(user.can({ role: "read", game: "embryology"}));
        assert(user.can({ role: "read", group: 123}));
        assert(user.can({ role: "read", group: 456}));
        assert(user.can({ role: "read", game: "histology", group: 123}));
        assert(user.can({ role: "read", game: "embryology", group: 456}));

        assert(user.can({ role: "write"}));
        assert(user.can({ role: "write", game: "histology"}));
        assert(user.can({ role: "write", game: "embryology"}));
        assert(user.can({ role: "write", group: 123}));
        assert(user.can({ role: "write", group: 456}));
        assert(user.can({ role: "write", game: "histology", group: 123}));
        assert(user.can({ role: "write", game: "embryology", group: 456}));

        assert(user.can({ role: "readWrite"}));
        assert(user.can({ role: "readWrite", game: "histology"}));
        assert(user.can({ role: "readWrite", game: "embryology"}));
        assert(user.can({ role: "readWrite", group: 123}));
        assert(user.can({ role: "readWrite", group: 456}));
        assert(user.can({ role: "readWrite", game: "histology", group: 123}));
        assert(user.can({ role: "readWrite", game: "embryology", group: 456}));
    });

    it('can readWrite with game', function() {
        var user = new User({ id:1, email:'a@a.com', username: 'a', 'roles': [{role: "readWrite", game: "histology" }] });
        assert(!user.can({ role: "read"}));
        assert(user.can({ role: "read", game: "histology"}));
        assert(!user.can({ role: "read", game: "embryology"}));
        assert(!user.can({ role: "read", group: 123}));
        assert(!user.can({ role: "read", group: 456}));
        assert(user.can({ role: "read", game: "histology", group: 123}));
        assert(!user.can({ role: "read", game: "embryology", group: 456}));

        assert(!user.can({ role: "write"}));
        assert(user.can({ role: "write", game: "histology"}));
        assert(!user.can({ role: "write", game: "embryology"}));
        assert(!user.can({ role: "write", group: 123}));
        assert(!user.can({ role: "write", group: 456}));
        assert(user.can({ role: "write", game: "histology", group: 123}));
        assert(!user.can({ role: "write", game: "embryology", group: 456}));

        assert(!user.can({ role: "readWrite"}));
        assert(user.can({ role: "readWrite", game: "histology"}));
        assert(!user.can({ role: "readWrite", game: "embryology"}));
        assert(!user.can({ role: "readWrite", group: 123}));
        assert(!user.can({ role: "readWrite", group: 456}));
        assert(user.can({ role: "readWrite", game: "histology", group: 123}));
        assert(!user.can({ role: "readWrite", game: "embryology", group: 456}));
    });

    it('can readWrite with group', function() {
        var user = new User({ id:1, email:'a@a.com', username: 'a', 'roles': [{role: "readWrite", group: 123 }] });
        assert(!user.can({ role: "read"}));
        assert(!user.can({ role: "read", game: "histology"}));
        assert(!user.can({ role: "read", game: "embryology"}));
        assert(user.can({ role: "read", group: 123}));
        assert(!user.can({ role: "read", group: 456}));
        assert(user.can({ role: "read", game: "histology", group: 123}));
        assert(!user.can({ role: "read", game: "embryology", group: 456}));

        assert(!user.can({ role: "write"}));
        assert(!user.can({ role: "write", game: "histology"}));
        assert(!user.can({ role: "write", game: "embryology"}));
        assert(user.can({ role: "write", group: 123}));
        assert(!user.can({ role: "write", group: 456}));
        assert(user.can({ role: "write", game: "histology", group: 123}));
        assert(!user.can({ role: "write", game: "embryology", group: 456}));

        assert(!user.can({ role: "readWrite"}));
        assert(!user.can({ role: "readWrite", game: "histology"}));
        assert(!user.can({ role: "readWrite", game: "embryology"}));
        assert(user.can({ role: "readWrite", group: 123}));
        assert(!user.can({ role: "readWrite", group: 456}));
        assert(user.can({ role: "readWrite", game: "histology", group: 123}));
        assert(!user.can({ role: "readWrite", game: "embryology", group: 456}));
    });

    it('can readWrite with group and game', function() {
        var user = new User({ id:1, email:'a@a.com', username: 'a', 'roles': [{role: "readWrite", game: "histology", group: 123 }] });
        assert(!user.can({ role: "read"}));
        assert(!user.can({ role: "read", game: "histology"}));
        assert(!user.can({ role: "read", game: "embryology"}));
        assert(!user.can({ role: "read", group: 123}));
        assert(!user.can({ role: "read", group: 456}));
        assert(user.can({ role: "read", game: "histology", group: 123}));
        assert(!user.can({ role: "read", game: "embryology", group: 456}));

        assert(!user.can({ role: "write"}));
        assert(!user.can({ role: "write", game: "histology"}));
        assert(!user.can({ role: "write", game: "embryology"}));
        assert(!user.can({ role: "write", group: 123}));
        assert(!user.can({ role: "write", group: 456}));
        assert(user.can({ role: "write", game: "histology", group: 123}));
        assert(!user.can({ role: "write", game: "embryology", group: 456}));

        assert(!user.can({ role: "readWrite"}));
        assert(!user.can({ role: "readWrite", game: "histology"}));
        assert(!user.can({ role: "readWrite", game: "embryology"}));
        assert(!user.can({ role: "readWrite", group: 123}));
        assert(!user.can({ role: "readWrite", group: 456}));
        assert(user.can({ role: "readWrite", game: "histology", group: 123}));
        assert(!user.can({ role: "readWrite", game: "embryology", group: 456}));
    });

    it('can readWrite with group and game - using arguments', function() {
        var user = new User({ id:1, email:'a@a.com', username: 'a', 'roles': [{role: "readWrite", game: "histology", group: 123 }] });
        assert(!user.can("read"));
        assert(!user.can("read", "histology"));
        assert(!user.can("read", "embryology"));
        assert(!user.can("read", null, 123));
        assert(!user.can("read", null, 456));
        assert(user.can("read", "histology", 123));
        assert(!user.can("read", "embryology", 456));

        assert(!user.can("write"));
        assert(!user.can("write", "histology"));
        assert(!user.can("write", "embryology"));
        assert(!user.can("write", null, 123));
        assert(!user.can("write", null, 456));
        assert(user.can("write", "histology", 123));
        assert(!user.can("write", "embryology", 456));

        assert(!user.can("readWrite"));
        assert(!user.can("readWrite", "histology"));
        assert(!user.can("readWrite", "embryology"));
        assert(!user.can("readWrite", null, 123));
        assert(!user.can("readWrite", null, 456));
        assert(user.can("readWrite", "histology", 123));
        assert(!user.can("readWrite", "embryology", 456));
    });
});