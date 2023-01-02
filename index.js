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
const domain = 'software-security.us.auth0.com';
const client_id = 'hOYc3fRqBS51QGejxeLSlw7vbGU2NQnA';

const AuthenticationClient = new auth0.AuthenticationClient(
    {
        domain: domain,
        clientId: client_id,
        clientSecret: process.env.CLIENT_SECRET
    }
);

const ManagementClient = new auth0.ManagementClient(
    {
        domain: domain,
        clientId: client_id,
        clientSecret: process.env.CLIENT_SECRET
    }
)

app.use(async (req, res, next) => {
    let authorization = req.get(SESSION_KEY);
    console.log(authorization)
    let refresh = req.get('Refresh');

    if (authorization) {
        req.access_token = authorization.split(' ')[1];
        req.refresh_token = refresh;
        try {
            let payload = jwt.decode(req.access_token);
            console.log(payload)

            if (Date.now() >= payload.exp * 1000) {
                console.log('Token expired', payload.exp);

                let refreshRequest = await AuthenticationClient.refreshToken(
                    {
                        refresh_token: req.refresh_token
                    }
                );

                req.access_token = refreshRequest.access_token;

                console.log("Token was refreshed", refreshRequest);
            }
        } catch (err) {
            console.log(err)
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

    const uri = new URL(`https://${domain}/authorize`);

    uri.searchParams.append('client_id', client_id);
    uri.searchParams.append('redirect_uri', 'http://localhost:3000/callback');
    uri.searchParams.append('response_type', 'code');
    uri.searchParams.append('response_mode', 'query');

    res.redirect(uri.toString());
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

app.get('/callback', (req, res) => {
    const code = req.query.code;
    console.log(code);

    res.status(200).send()
});

const checkJwt = auth({
    audience: `https://${domain}/api/v2/`,
    issuerBaseURL: `https://${domain}`,
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
});


async function auth0Login(login, password) {
    const data = {
        audience: `https://${domain}/api/v2/`,
        client_id: client_id,
        username: login,
        password: password,
        realm: 'Username-Password-Authentication',
        scope: 'offline_access'
    };
    return AuthenticationClient.passwordGrant(data);
}

app.listen(port, () => {
    console.log(`Example app listening on port ${port}`)
});