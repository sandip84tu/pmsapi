var restify     =   require('restify');
var mongojs     =   require('mongojs');
var morgan = require('morgan');
//var db = mongojs(' mongodb://admin:admin123@dbh36.mongolab.com:27367/bucketlistapp', ['users', 'bucketLists']);
//var db = mongojs('mongodb://sandip84tu:janaki84tu@ds049436.mlab.com:49436/pms', ['users','Pinboardtasks']);
var db = mongojs('PMS', ['users']);
var server = restify.createServer();

server.use(restify.acceptParser(server.acceptable));
server.use(restify.queryParser());
server.use(restify.bodyParser());
server.use(morgan('dev')); // LOGGER

// CORS
server.use(function(req, res, next) {
    res.header('Access-Control-Allow-Origin', "*");
    res.header('Access-Control-Allow-Methods', 'GET,PUT,POST,DELETE');
    res.header('Access-Control-Allow-Headers', 'Content-Type');
    next();
});

server.listen(process.env.PORT || 9804, function () {
    console.log("Server started @ ", process.env.PORT || 9804);
});

var manageUsers =   require('./auth/manageUser')(server, db);
var manageLists =   require('./list/manageList')(server, db);