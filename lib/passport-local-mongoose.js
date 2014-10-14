var util = require('util');
var crypto = require('crypto');
var jwt = require('jwt-simple');
var LocalStrategy = require('passport-local').Strategy;
var BadRequestError = require('./badrequesterror');

module.exports = function(schema, options) {
    options = options || {};
    options.saltlen = options.saltlen || 32;
    options.iterations = options.iterations || 25000;
    options.keylen = options.keylen || 512;
    options.encoding = options.encoding || 'hex';

    options.accessTokenSecret = options.accessTokenSecret || 'ERTDG54634T%YG$%&97283FD';

    // Populate field names with defaults if not set
    options.usernameField = options.usernameField || 'username';
    
    // option to convert username to lowercase when finding
    options.usernameLowerCase = options.usernameLowerCase || false;
    
    options.hashField = options.hashField || 'hash';
    options.saltField = options.saltField || 'salt';
    options.deletedField = options.deletedField || false;

    //TODO: language support!!
    options.deletedMessage = options.deletedMessage || 'User not found';
    options.incorrectPasswordError = options.incorrectPasswordError || 'Incorrect password';
    options.incorrectUsernameError = options.incorrectUsernameError || 'Incorrect username';
    options.missingUsernameError = options.missingUsernameError || 'Field %s is not set';
    options.missingPasswordError = options.missingPasswordError || 'Password argument not set!';
    options.userExistsError = options.userExistsError || 'User already exists with name %s';
    options.noSaltValueStoredError = options.noSaltValueStoredError || 'Authentication not possible. No salt value stored in mongodb collection!';

    var schemaFields = {};
    if (!schema.path(options.usernameField)) {
    	schemaFields[options.usernameField] = String;
    }
    schemaFields[options.hashField] = String;
    schemaFields[options.saltField] = String;

    schema.add(schemaFields);

    schema.pre('save', function(next) {
        // if specified, convert the username to lowercase
        if (options.usernameLowerCase) {
            this[options.usernameField] = this[options.usernameField].toLowerCase();
        }

        next();
    });

    schema.methods.setPassword = function (password, cb) {
        if (!password) {
            return cb(new BadRequestError(options.missingPasswordError));
        }
        
        var self = this;

        crypto.randomBytes(options.saltlen, function(err, buf) {
            if (err) {
                return cb(err);
            }

            var salt = buf.toString(options.encoding);

            crypto.pbkdf2(password, salt, options.iterations, options.keylen, function(err, hashRaw) {
                if (err) {
                    return cb(err);
                }

                self.set(options.hashField, new Buffer(hashRaw, 'binary').toString(options.encoding));
                self.set(options.saltField, salt);

                cb(null, self);
            });
        });
    };

    /**
     * authenticate the user
     *
     * @param password
     * @param cb
     * @returns {*}
     */
    schema.methods.authenticate = function(password, cb) {
        var self = this;

        //check the deleted field
        if (options.deletedField !== false) {
            if(this.get(options.deletedField)) {
                return cb(null, false, { message: options.deletedMessage });
            }
        }

        if (!this.get(options.saltField)) {
            return cb(null, false, { message: options.noSaltValueStoredError });
        }

        crypto.pbkdf2(password, this.get(options.saltField), options.iterations, options.keylen, function(err, hashRaw) {
            if (err) {
                return cb(err);
            }
            
            var hash = new Buffer(hashRaw, 'binary').toString(options.encoding);

            if (hash === self.get(options.hashField)) {

                //if no accessToken is set create one
                if(!self.get('accessToken')) {
                    self.generateAccessToken(function(err,user){
                        if (err) {
                            return cb(err);
                        }
                        return cb(null, user);
                    });
                } else {
                    cb(null, self);
                }

            } else {
                return cb(null, false, { message: options.incorrectPasswordError });
            }
        });
    };

    /**
     * generate API Access Token
     * @param cb
     * @return callback
     */
    schema.methods.generateAccessToken = function(cb) {
        var self, payload;

        self = this;
        payload = {
            date: Date.now()
        };

        payload[options.usernameField] = self.get(options.usernameField);
        payload['_id'] = self.get('_id');

        self.set('accessToken',jwt.encode(payload,options.accessTokenSecret));

        self.save(function(err) {
            if (err) {
                return cb(err);
            }
            cb(null, self);
        });
    };

    /**
     * decode the access token
     * @param accessToken
     * @returns {Object}
     */
    schema.statics.decodeAccessToken = function(accessToken) {
        return jwt.decode(accessToken,options.accessTokenSecret);
    };


    schema.statics.verifyAccessToken = function (accessToken, cb) {
        var self = this;
        try {
            var decodedAccessToken = jwt.decode(accessToken, options.accessTokenSecret)

            if(!Object(decodedAccessToken).hasOwnProperty('_id')) {
                var badAccessToken = new Error('AccessToken is corrupted');
                return cb(badAccessToken, null);
            }
            
            self.findOne({"_id": decodedAccessToken._id}, function (err, user) {
                if(err) return cb(err, null);
                if(!user) return cb(null, null);

                return cb(null,user);
            })

        } catch (e) {
            return cb(e,null);
        }
    };

    schema.statics.authenticate = function() {
        var self = this;

        return function(username, password, cb) {
            self.findByUsername(username, function(err, user) {
                if (err) { return cb(err); }

                if (user) {
                    return user.authenticate(password, cb);
                } else {
                    return cb(null, false, { message: options.incorrectUsernameError })
                }
            });
        }
    };

    schema.statics.serializeUser = function() {
        return function(user, cb) {
            cb(null, user.get(options.usernameField));
        }
    };

    schema.statics.deserializeUser = function() {
        var self = this;

        return function(username, cb) {
            self.findByUsername(username, cb);
        }
    };
    
    schema.statics.register = function(user, password, cb) {
        // Create an instance of this in case user isn't already an instance
        if (!(user instanceof this)) {
            user = new this(user);
        }

        if (!user.get(options.usernameField)) {
            return cb(new BadRequestError(util.format(options.missingUsernameError, options.usernameField)));
        }

        var self = this;
        self.findByUsername(user.get(options.usernameField), function(err, existingUser) {
            if (err) { return cb(err); }
            
            if (existingUser) {
                return cb(new BadRequestError(util.format(options.userExistsError, user.get(options.usernameField))));
            }
            
            user.setPassword(password, function(err, user) {
                if (err) {
                    return cb(err);
                }

                user.save(function(err) {
                    if (err) {
                        return cb(err);
                    }

                    cb(null, user);
                });
            });
        });
    };

    schema.statics.findByUsername = function(username, cb) {
        var queryParameters = {};
        
        // if specified, convert the username to lowercase
        if (username !== undefined && options.usernameLowerCase) {
            username = username.toLowerCase();
        }
        
        queryParameters[options.usernameField] = username;
        
        var query = this.findOne(queryParameters);
        if (options.selectFields) {
            query.select(options.selectFields);
        }

        if (options.populateFields) {
            query.populate(options.populateFields);
        }

        if (cb) {
            query.exec(cb);
        } else {
            return query;
        }
    };

    schema.statics.createStrategy = function() {
        return new LocalStrategy(options, this.authenticate());
    };
};
