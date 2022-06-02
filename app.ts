import * as express from 'express';
import RateLimit from 'express-rate-limit';
import {User, UserCreateException} from './user';
import * as admin from 'firebase-admin';
import * as fs from 'fs';

import * as dotenv from 'dotenv';
import { Message } from './message';
dotenv.config();

const app = express();
const limiter = RateLimit({
    windowMs: 60000, // 1 minute
    max: 60
});

app.use(limiter);
app.use(express.json());

const serviceAccount = JSON.parse(fs.readFileSync('firebaseCredentials.json').toString());
admin.initializeApp({
    credential: admin.credential.cert(serviceAccount),
    databaseURL: 'https://aeacus-default-rtdb.firebaseio.com'
});

app.post('/login', async (req, res) => {
    const username = req.body.uname;
    const password = req.body.pword;

    if (!username || !password) {
        res.json({ status: 'error', message: 'Missing arguments!' }).end();
        return;
    }

    const user = await User.verifyLogin(username, password);
    if (!user) {
        res.json({ status: 'error', message: 'Incorrect username or password!'});
        return;
    }

    const token = await user.createToken(password);
    res.json({ status: 'ok', message: 'Login successfull', token, key: user.getPublicKeyEncoded() }).end();
});

app.post('/register', async (req, res) => {
    const username = req.body.uname;
    const password = req.body.pword;

    if (!username || !password) {
        res.json({ status: 'error', message: 'Missing arguments!' }).end();
        return;
    }

    try {
        const user = await User.createUser(username, password);
        res.json({ status: 'ok', message: 'User registered', user }).end();
    } catch (e) {
        const json = { status: 'error', message: 'An unknown error occurred!' };

        if (e instanceof UserCreateException)
            json.message = 'User already exists!';

        res.json(json).end();
    }
});

app.post('/getNewMessages', async (req, res) => {
    const username = req.body.uname;
    const token = req.body.token;

    if (!username || !token) {
        res.json({ status: 'error', message: 'Missing arguments!' }).end();
        return;
    }

    const user = await User.fromUsername(username);
    if (!user.verifyToken(token)) {
        res.json({ status: 'error', message: 'Invalid token!' }).end();
        return;
    }

    const pkg = await user.getNewMessages();
    res.json({
        status: 'ok',
        message: `Retrieved command package of length ${pkg.messages.length}. ` +
            `Last acknowledged: ${pkg.lastAcknowledgedTimestamp}`,
        messagePackage: pkg
    });
});

app.post('/pushMessage', async (req, res) => {
    const message: Message = req.body.message;
    const token: string = req.body.token;

    if (!message || !token || !message.user) {
        res.json({ status: 'error', message: 'Missing arguments!' }).end();
        return;
    }

    const user = await User.fromUsername(message.user);
    if (!user) {
        res.json({ status: 'error', message: 'Invalid user!' }).end();
        return;
    }

    if (!user.verifyToken(token)) {
        res.json({ status: 'error', message: 'Invalid token!' }).end();
        return;
    }

    const success = await Message.pushMessage(message);
    if (!success) {
        res.json({status: 'error', message: 'Invalid message!'});
        return;
    }

    res.json({ status: 'ok', message: 'Message pushed' }).end();
});

app.post('/acknowledgeMessages', async (req, res) => {
    const username: string = req.body.uname;
    const token: string = req.body.token;
    const timestamps: Array<number> = req.body.timestamps;

    if (!token || !timestamps || !username) {
        res.json({ status: 'error', message: 'Missing arguments!' }).end();
        return;
    }

    const user = await User.fromUsername(username);
    if (!user) {
        res.json({ status: 'error', message: 'Invalid user!' }).end();
        return;
    }

    if (!user.verifyToken(token)) {
        res.json({ status: 'error', message: 'Invalid token!' }).end();
        return;
    }

    try {
        await user.acknowledgeMessages(timestamps);
        res.json({ status: 'ok', message: `${timestamps.length} timestamps acknowledged` }).end();
    } catch (e) {
        console.error(e);
        res.json({status: 'error', message: 'An unknown error occurred!'}).end();
    }
});

const PORT = process.env.PORT || 8080;
app.listen(PORT, () => {
    console.log(`Server listening on ${PORT}...`);
});