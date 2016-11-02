var pwdMgr = require('./managePasswords');

module.exports = function (server, db) {
    // unique index
    db.users.ensureIndex({
        email: 1
    }, {
            unique: true
        })

    server.post('/api/v1/pms/auth/register', function (req, res, next) {
        var user = req.params;
        pwdMgr.cryptPassword(user.password, function (err, hash) {
            user.password = hash;
            db.users.insert(user,
                function (err, dbUser) {
                    if (err) { // duplicate key error
                        if (err.code == 11000) /* http://www.mongodb.org/about/contributors/error-codes/*/ {
                            res.writeHead(400, {
                                'Content-Type': 'application/json; charset=utf-8'
                            });
                            res.end(JSON.stringify({
                                error: err,
                                message: "A user with this email already exists"
                            }));
                        }
                    } else {
                        res.writeHead(200, {
                            'Content-Type': 'application/json; charset=utf-8'
                        });
                        dbUser.password = "";
                        res.end(JSON.stringify(dbUser));
                        console.log(dbUser);
                    }
                });
        });
        return next();
    });

    server.post('/api/v1/pms/auth/login', function (req, res, next) {
        var user = req.params;
        if (user.email.trim().length == 0 || user.password.trim().length == 0) {
            res.writeHead(403, {
                'Content-Type': 'application/json; charset=utf-8'
            });
            res.end(JSON.stringify({
                error: "Invalid Credentials"
            }));
        }
        db.users.findOne({
            email: req.params.email
        }, function (err, dbUser) {


            pwdMgr.comparePassword(user.password, dbUser.password, function (err, isPasswordMatch) {

                if (isPasswordMatch) {
                    res.writeHead(200, {
                        'Content-Type': 'application/json; charset=utf-8'
                    });
                    // remove password hash before sending to the client
                    dbUser.password = "";
                    res.end(JSON.stringify(dbUser));
                } else {
                    res.writeHead(403, {
                        'Content-Type': 'application/json; charset=utf-8'
                    });
                    res.end(JSON.stringify({
                        error: "Invalid User"
                    }));
                }

            });
        });
        return next();
    });
    server.post('/api/v1/pms/auth/getProfile/:email', function (req, res, next) {
        var email = req.params.email;
        if (email.trim().length == 0) {
            res.writeHead(403, {
                'Content-Type': 'application/json; charset=utf-8'
            });
            res.end(JSON.stringify({
                error: "Invalid Credentials"
            }));
        }
        db.users.findOne({
            email: req.params.email
        }, function (err, dbUser) {
            res.end(JSON.stringify(dbUser));
        });
        return next();
    });
    server.post('/api/v1/pms/auth/updateProfile/:email', function (req, res, next) {
        validateRequest.validate(req, res, db, function () {
            var user = req.params;
            var existingUser = db.users.findOne({ email: req.email });
            console.log(existingUser);

        //db.users.save(user,
        //    function (err, data) {
        //        res.writeHead(200, {
        //            'Content-Type': 'application/json; charset=utf-8'
        //        });
        //        res.end(JSON.stringify(data));
        //    });
        return next();
        });
    });
};
