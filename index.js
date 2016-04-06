// This is a small reference implementation for using Coinbase's
// oauth to get a user's API keys.
//
// With a user's API keys you can make API calls on the user's
// behalf. For simplisity we will use the npm module 'coinbase'
// to make our API calls.
//
// The API documentation can be found at
// https://developers.coinbase.com/api/v2


// When we request the user's API keys we need to specify the
// scope of what the API keys can do. The scope of your API
// keys will be shown to the user when they first access your
// service. The current scope allows you to verify the user's
// identity. More permissions can be found at
// https://developers.coinbase.com/docs/wallet/permissions
var OATH_SCOPES = [
    'wallet:user:email',
    'wallet:user:read'
];

// Replace this url that is used to access your service.
// Also make sure that HOST_BASE_URL + OAUTH_CALLBACK_PATH is
// added to the list of allowed callback urls in your Coinbase
// app.
var HOST_BASE_URL = 'http://localhost:8080';
var OAUTH_CALLBACK_PATH = '/oauth_callback';

// If you are using the sandbox, be sure that you
// generated your app's keys at sandbox.coinbase.com
var SANDBOX = true; 
var COINBASE_OAUTH_BASE = SANDBOX ?
    'https://sandbox.coinbase.com/oauth/authorize?response_type=code&client_id=' :
    'https://www.coinbase.com/oauth/authorize?response_type=code&client_id=';
var COINBASE_API_URL = SANDBOX ?
    'https://api.sandbox.coinbase.com/v2/' :
    'https://api.coinbase.com/v2/';
var COINBASE_TOKEN_URL = SANDBOX ?
    'https://api.sandbox.coinbase.com/oauth/token' :
    'https://api.coinbase.com/oauth/token';

// App keys are stored in a different file that is not
// tracked by source control. We don't want to accidentally
// share our keys with the world, that would be bad.
var app_keys = require('./app_keys');

// coinbase app keys
var CLIENT_ID = app_keys.CLIENT_ID;
var CLIENT_SECRET = app_keys.CLIENT_SECRET;

// used in hmac to prevent request forgery
// good practice but not required
var STATE_SECRET = app_keys.STATE_SECRET;
// used for express-session library
var SESSION_SECRET = app_keys.SESSION_SECRET;

// app dependencies
var crypto = require('crypto');
var express = require('express');
var request = require('request');
var session = require('express-session');
var Coinbase = require('coinbase');

var app = express();
app.use(session({
    secret: SESSION_SECRET
}));

// Login page, render a single link to coinbase's oauth
app.get('/login', function(req, res) {
    // Construct epoch-hmac(epoch) for state
    var hmac = crypto.createHmac('sha256', STATE_SECRET);
    var now = (new Date()).getTime() + '';
    hmac.update(now);
    var state = now + ';' + hmac.digest().toString('base64');

    // Build oauth url
    var OAUTH_URL = [
        COINBASE_OAUTH_BASE,
        encodeURIComponent(CLIENT_ID),
        '&redirect_uri=',
        encodeURIComponent(HOST_BASE_URL + OAUTH_CALLBACK_PATH),
        '&state=',
        encodeURIComponent(state),
        '&scope=',
        encodeURIComponent(OATH_SCOPES.join(','))
    ];
    res.send('<a href="' + OAUTH_URL.join('') + '">Login with Coinbase</a>');
});

app.get(OAUTH_CALLBACK_PATH, function(req, res, next) {
    // validate state parameter
    var state = (req.query.state || '').split(';');
    if (state.length !== 2) {
        return res.send('invalid state');
    }
    // make sure we generated the state parameter
    var hmac = crypto.createHmac('sha256', STATE_SECRET);
    hmac.update(state[0]);
    if (state[1] !== hmac.digest().toString('base64')) {
        return res.send('invalid state');
    }
    // make sure the parameter is not too old
    if ((new Date().getTime()) - (+state[0]) > 60 * 1000) {
        return res.send('oauth state expired');
    }

    var code = req.query.code;
    request.post(COINBASE_TOKEN_URL, { json: {
        grant_type: 'authorization_code',
        code: code,
        client_id: CLIENT_ID,
        client_secret: CLIENT_SECRET,
        redirect_uri: HOST_BASE_URL + OAUTH_CALLBACK_PATH
    }}, function(err, code, body) {
        if (err) {
            return next(err);
        }
        req.session.coinbase = {
            accessToken: body.access_token,
            refreshToken: body.refresh_token,
            baseApiUri: COINBASE_API_URL,
            tokenUri: COINBASE_TOKEN_URL
        };
        res.redirect('/');
    });
});

app.get('/', function(req, res, next) {
    var client_details = req.session.coinbase;
    if (!client_details) {
        return res.send('not logged in, go to <a href="/login">login</a>');
    }
    var client = new Coinbase.Client(client_details);
    client.getCurrentUser(function(err, user) {
        if (err) {
            return next(err);
        }
        res.send('email: ' + user.email + ' <a href="/logout">logout</a>');
    });
});

app.get('/logout', function(req, res, next) {
    var client_details = req.session.coinbase;
    if (!client_details) {
        return res.send('not logged in, go to <a href="/login">login</a>');
    }
    req.session.destroy();
    res.send('you have been logged out <a href="/">home</a>');
});

app.listen(8080);
