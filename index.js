const express = require('express');
const bodyParser = require('body-parser');
const path = require('path');
const auth0 = require('auth0');
require('dotenv').config();
const jwt = require('jsonwebtoken');
const {auth} = require('express-oauth2-jwt-bearer');
const port = 3000;

const app = express();
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({extended: true}));

const SESSION_KEY = 'Authorization';

const AuthenticationClient = new auth0.AuthenticationClient(
    {
        domain: 'kpi.eu.auth0.com',
        clientId: 'JIvCO5c2IBHlAe2patn6l6q5H35qxti0',
        clientSecret: process.env.CLIENT_SECRET
    }
);

const ManagementClient = new auth0.ManagementClient(
    {
        domain: 'kpi.eu.auth0.com',
        clientId: 'JIvCO5c2IBHlAe2patn6l6q5H35qxti0',
        clientSecret: process.env.CLIENT_SECRET
    }
)

app.use(async (req, res, next) => {
    let authorization = req.get(SESSION_KEY);
    console.log(authorization)
    let refresh = req.get('Refresh');

    if (authorization) {
        let tokens = authorization.split(';');
        if (tokens.length === 3) {
            req.access_token = tokens[0];
            req.refresh_token = tokens[1];
            //req.id_token = tokens[2];
        }
        try {
            jwt.verify(req.access_token,  process.env.CLIENT_SECRET, async function(err, decoded) {
                if (err) {
                    console.log('expired');

                    let refreshRequest = await AuthenticationClient.refreshToken(
                        {
                            refresh_token: req.refresh_token
                        }
                    );

                    req.access_token = refreshRequest.access_token;

                    console.log("Token was refreshed", refreshRequest);
                }
            });
        } catch (err) {
            res.status(401).send();
            return;
        }
        res.headers = {Authorization: `${req.access_token};${req.refresh_token}`}
    }
    next();
});

app.get('/', (req, res) => {
    if (req.access_token) {
        let payload = jwt.decode(req.access_token);

        return res.json({
            username: payload.sub,
            logout: 'http://localhost:3000/logout'
        })
    }
    res.sendFile(path.join(__dirname + '/index.html'));
})

app.get('/logout', (req, res) => {
    sessionStorage.clear()

    res.redirect('/');
});

app.post('/api/login', async (req, res) => {
    const {login, password} = req.body;

    let loginResult = {};

    try {
        loginResult = await auth0Login(login, password);
    } catch (err) {
        res.status(401).send();
        console.log(err);
        return;
    }
    console.log(loginResult);

    res.json({
        access_token: loginResult.access_token,
        refresh_token: loginResult.refresh_token
    });
});

const checkJwt = auth({
    audience: 'https://kpi.eu.auth0.com/api/v2/',
    issuerBaseURL: `https://kpi.eu.auth0.com`,
});

app.get('/api/check', checkJwt, (req, res) => {
    res.json({
        message: 'Authentication is successful'
    })
})


app.post('/api/register', async (req, res) => {
    const {email, password} = req.body;
    let createResult = {}

    try {
        createResult = await ManagementClient.createUser(
            {
                email: email,
                password: password,
                connection: 'Username-Password-Authentication'
            }
        );

        if (createResult instanceof Error) {
            throw createResult;
        }
    } catch (err) {
        res.status(400).send();
        console.log(err);
        return;
    }
    console.log(createResult)
    res.status(200).send();
});

async function auth0Login(login, password) {
    const data = {
        audience: 'https://kpi.eu.auth0.com/api/v2/',
        client_id: 'JIvCO5c2IBHlAe2patn6l6q5H35qxti0',
        username: login,
        password: password,
        realm: 'Username-Password-Authentication',
        scope: 'offline_access'
    };

    return AuthenticationClient.passwordGrant(data);
}

app.listen(port, () => {
    console.log(`Example app listening on port ${port}`)
})