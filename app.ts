import * as express from 'express';
import RateLimit from 'express-rate-limit';
import {User, UserCreateException} from './user';
import * as admin from 'firebase-admin';
import * as fs from 'fs';
import * as dotenv from 'dotenv';
import {Message, MessageAck, MessageContext} from './message';
import * as crypto from 'crypto';
import {Certificate} from './certificate';
import {WebSocket} from 'ws';
import {auth} from 'firebase-admin';

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

app.post('/publishCertificate', async (req, res) => {
    const cert: Certificate = req.body.certificate;

    if (!cert) {
        res.json({ status: 'error', message: 'Missing arguments!' }).end();
        return;
    }

    if (!Certificate.prototype.isValid.call(cert)) {
        res.json({ status: 'error', message: 'Invalid certificate!' }).end();
        return;
    }

    try {
        await Certificate.publish(cert);
    } catch (e) {
        console.error(e);
        res.json({ status: 'error', message: 'Certificate could not be published' }).end();
    }
});

const PORT = process.env.PORT || 8080;
app.listen(PORT, () => {
    console.log(`Server listening on ${PORT}...`);
});

const SOCKET_PORT = process.env.SOCKET_PORT || 8081;
const server = new WebSocket.Server({
    port: SOCKET_PORT as number
});

let sockets: AuthenticatedSocket[] = [];

MessageContext.addListener((msg: Message): void => {
    for (const socket of sockets) {
        if (socket.user === msg.user)
            socket.socket.send(JSON.stringify({ type: 'message', payload: msg }));
    }
});

interface SocketMessage {
    type: string;
    payload;
}

interface AuthenticatedSocket {
    socket: WebSocket;
    user: string;
}

server.on('connection', (socket) => {
    console.log('Connection opened!');

    let username;

    socket.on('message', async (data) => {
        try {
            const object = JSON.parse(data.toString());
            if (!object.type || !object.payload) {
                await socket.send(JSON.stringify({ type: 'error', payload: 'Missing required parameters!' }));
                await socket.send(JSON.stringify({ type: 'authAck', payload: false }));
                socket.close();
            }

            const sm: SocketMessage = { type: object.type, payload: object.payload };

            if (sm.type === 'auth') {
                const token = sm.payload.token;
                const sig = sm.payload.signature;
                const uname = sm.payload.uname;

                if (!token || !sig || !uname) {
                    await socket.send(JSON.stringify({ type: 'error', payload: 'Missing required parameters!' }));
                    await socket.send(JSON.stringify({ type: 'authAck', payload: false }));
                    socket.close();
                }

                const user = await User.fromUsername(uname);

                if (user.verifyToken(token, sig)) {
                    username = user.getUsername();
                    sockets.push({ socket, user: username });
                    socket.send(JSON.stringify({ type: 'authAck', payload: true }));
                } else {
                    socket.send(JSON.stringify({ type: 'authAck', payload: false }));
                }
            } else {
                socket.send(JSON.stringify({ type: 'error', payload: 'Invalid socket message type' }));
                socket.close();
            }
        } catch (e) {
            console.error(e);
            socket.close();
        }
    });

    socket.on('close', () => {
        console.log('Connection closed!');

        if (username)
            sockets = sockets.filter(s => s.user !== username);
    });
});