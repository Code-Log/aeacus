import * as express from 'express';
import RateLimit from 'express-rate-limit';
import {User, UserCreateException} from './user';
import * as admin from 'firebase-admin';
import * as fs from 'fs';
import * as dotenv from 'dotenv';
import { Message } from './message';
import * as crypto from 'crypto';

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

const { publicKey, privateKey } = crypto.generateKeyPairSync('ec', {
    namedCurve: 'secp128r2',
    publicKeyEncoding: {
        type: 'spki',
        format: 'der'
    },
    privateKeyEncoding: {
        type: 'pkcs8',
        format: 'der',
        cipher: 'aes-256-cbc',
        passphrase: 'Yo'
    }
});

const sign = crypto.createSign('SHA256');
sign.update('Hello World!');
const signature = sign.sign(publicKey, 'hex');
console.log(`Signature: ${signature}`);

console.log(`pk: ${publicKey.toString('hex')}`);
console.log(`sk: ${privateKey.toString('hex')}`);

// 0x7F89De2d83d5af1582b1952669c4fA3e361d068B

app.post('/getUser', async (req, res) => {
    const username = req.body.uname;
    const authKey = req.body.authKey;

    if (!username || !authKey) {
        res.json({ status: 'error', message: 'Missing arguments!' }).end();
        return;
    }

    const user = await User.fromUsername(username);
    if (!user) {
        res.json({ status: 'error', message: 'No such user!'});
        return;
    }

    if (!await user.verifyAuthKey(authKey)) {
        res.json({ status: 'error', message: 'Invalid auth key!' });
        return;
    }

    res.json({ status: 'ok', message: 'Login successfull', user }).end();
});

app.post('/register', async (req, res) => {
    const username = req.body.uname;
    const authKey = req.body.authKey;
    const publicKey: string = req.body.publicKey;
    const secretKey = req.body.secretKey;
    const salt = req.body.salt;
    const challengeSignature = req.body.challengeSignature;
    const hmac = req.body.hmac;

    if (!username || !authKey || !publicKey || !secretKey || !salt || !challengeSignature || !hmac) {
        res.json({ status: 'error', message: 'Missing arguments!' }).end();
        return;
    }

    const challenge = {
        authKey,
        username
    };

    const verify = crypto.createVerify('RSA-SHA256');
    verify.update(JSON.stringify(challenge));

    const pk = crypto.createPublicKey({
        key: publicKey,
        format: 'pem',
        type: 'spki'
    });

    if (!verify.verify(pk, challengeSignature, 'hex')) {
        res.json({ status: 'error', message: 'Signing challenge failed! (We think you\'re an imposter)' });
        return;
    }

    try {
        const user = await User.createUser(username, authKey, publicKey, secretKey, salt, hmac);
        res.json({ status: 'ok', message: 'User registered', user }).end();
    } catch (e) {
        const json = { status: 'error', message: 'An unknown error occurred!' };

        if (e instanceof UserCreateException)
            json.message = 'User already exists!';

        res.json(json).end();
    }
});

app.post('/getSalt', async (req, res) => {
    const username = req.body.uname;

    if (!username) {
        res.json({ status: 'error', message: 'Missing arguments!' }).end();
        return;
    }

    const user = await User.fromUsername(username);
    if (!user) {
        res.json({ status: 'error', message: 'No such user exists!' });
        return;
    }
    
    res.json({ status: 'ok', message: '', salt: user.salt }).end();
});

app.post('/getNewMessages', async (req, res) => {
    const username = req.body.uname;
    const token = req.body.token;
    const signature = req.body.signature;

    if (!username || !token || !signature) {
        res.json({ status: 'error', message: 'Missing arguments!' }).end();
        return;
    }

    const user = await User.fromUsername(username);
    if (!user.verifyToken(token, signature)) {
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
    const signature = req.body.signature;

    if (!message || !token || !message.user || !signature) {
        res.json({ status: 'error', message: 'Missing arguments!' }).end();
        return;
    }

    const user = await User.fromUsername(message.user);
    if (!user) {
        res.json({ status: 'error', message: 'Invalid user!' }).end();
        return;
    }

    if (!user.verifyToken(token, signature)) {
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
    const bad: number[] = req.body.bad;
    const signature = req.body.signature;

    if (!token || !timestamps || !username || !signature) {
        res.json({ status: 'error', message: 'Missing arguments!' }).end();
        return;
    }

    const user = await User.fromUsername(username);
    if (!user) {
        res.json({ status: 'error', message: 'Invalid user!' }).end();
        return;
    }

    if (!user.verifyToken(token, signature)) {
        res.json({ status: 'error', message: 'Invalid token!' }).end();
        return;
    }

    try {
        await user.acknowledgeMessages(timestamps, (!bad) ? [] : bad);
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