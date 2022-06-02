import * as crypto from 'crypto';
import * as admin from 'firebase-admin';
import {argon2id, argon2Verify} from 'hash-wasm';
import {Message, MessagePackage} from './message';

export class UserCreateException {
    message: string;
    constructor(message: string) {
        this.message = message;
    }
}

export class User {
    private signatures: Array<string>;
    private readonly hash: string;
    private readonly username: string;
    private readonly publicKey: string;
    private readonly secretKey: string;
    private lastAcknowledgedTimestamp: number;

    constructor(username: string, signatures: Array<string>, hash: string, publicKey: string, secretKey: string, lastAcknowledgedTimestamp: number) {
        this.signatures = signatures;
        this.username = username;
        this.hash = hash;
        this.publicKey = publicKey;
        this.secretKey = secretKey;
        if (!lastAcknowledgedTimestamp)
            this.lastAcknowledgedTimestamp = 0;
        else
            this.lastAcknowledgedTimestamp = lastAcknowledgedTimestamp;
    }

    getPublicKey(): crypto.KeyObject {
        return crypto.createPublicKey({
            key: Buffer.from(this.publicKey, 'base64'),
            format: 'der',
            type: 'pkcs1'
        });
    }

    getPublicKeyEncoded(): string {
        return this.publicKey;
    }

    getSecretKeyDecrypted(password: string): crypto.KeyObject {
        return crypto.createPrivateKey({
            key: Buffer.from(this.secretKey, 'base64'),
            format: 'der',
            type: 'pkcs8',
            passphrase: password
        });
    }

    getUsername(): string {
        return this.username;
    }

    getHash(): string {
        return this.hash;
    }

    async createToken(password: string): Promise<string> {
        if (!this.signatures)
            this.signatures = new Array<string>();

        const token = crypto.randomBytes(64).toString('base64');
        const sig = crypto.createSign('RSA-SHA256');
        sig.write(token);
        const keyObject = this.getSecretKeyDecrypted(password);
        const sigString = sig.sign(keyObject, 'hex').toString();
        this.signatures.push(sigString);

        const db = admin.database();
        await db.ref(`users/${this.username}`).set(this);

        return token;
    }

    static async verifyLogin(username: string, password: string): Promise<User> {
        const db = admin.database();
        const userSnapshot = await db.ref(`users/${username}`).get();
        const userObject: User = userSnapshot.val();
        const user = new User(
            userObject.username,
            userObject.signatures,
            userObject.hash,
            userObject.publicKey,
            userObject.secretKey,
            (!userObject.lastAcknowledgedTimestamp) ? 0 : userObject.lastAcknowledgedTimestamp
        );

        const isValid = await argon2Verify({
            password,
            hash: user.hash
        });

        return (isValid) ? user : null;
    }

    verifyToken(token: string): boolean {
        if (!this.signatures)
            return false;

        let valid = false;
        for (const sig of this.signatures) {
            const verify = crypto.createVerify('RSA-SHA256');
            verify.write(token);
            const keyObject = this.getPublicKey();
            valid = valid || verify.verify(keyObject, sig, 'hex');
        }
        return valid;
    }

    static async createUser(username: string, password: string): Promise<User> {
        const db = admin.database();
        const ref = await db.ref(`users/${username}`).get();
        if (ref.val() != null)
            throw new UserCreateException('User already exists!');

        const salt = crypto.randomBytes(64);
        const hash = await argon2id({
            password,
            salt,
            parallelism: 1,
            iterations: 256,
            memorySize: 512,
            hashLength: 64,
            outputType: 'encoded'
        });

        const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
            modulusLength: 4096,
            publicKeyEncoding: {
                type: 'pkcs1',
                format: 'der'
            },
            privateKeyEncoding: {
                type: 'pkcs8',
                format: 'der',
                cipher: 'aes-256-cbc',
                passphrase: password
            }
        });

        const user = new User(
            username,
            [],
            hash,
            publicKey.toString('base64'),
            privateKey.toString('base64'),
            0);
        try {
            await db.ref(`users/${username}`).set(user);
        } catch (e) {
            console.error('An error occurred: ', e);
            return null;
        }
        return user;
    }

    getSecretKey(): string {
        return this.secretKey;
    }

    async getNewMessages(): Promise<MessagePackage> {
        const db = admin.database();
        const messagesRef = await db.ref('messages').get();
        let messages: Message[] = messagesRef.val();

        if (!messages)
            messages = [];

        const ourMessages: Message[] = [];
        for (const m of messages) {
            if (m.user === this.username)
                ourMessages.push(m);
        }

        return new MessagePackage(ourMessages, this.lastAcknowledgedTimestamp);
    }

    static async fromUsername(username: string): Promise<User> {
        const db = admin.database();
        const usersRef = await db.ref('users').get();
        const users = usersRef.val();

        for (const name of Object.keys(users)) {
            const user: User = users[name];
            if (user.username === username) {
                return new User(
                    user.username,
                    user.signatures,
                    user.hash,
                    user.publicKey,
                    user.secretKey,
                    user.lastAcknowledgedTimestamp
                );
            }
        }

        return null;
    }

    async acknowledgeMessages(timestamps: number[]) {
        const db = admin.database();
        let serverMessages: Message[] = (await db.ref('messages').get()).val();

        if (!serverMessages)
            serverMessages = [];

        const newMessages = [];
        let changed = false;
        for (const message of serverMessages) {
            for (const timestamp of timestamps) {
                if (message.user === this.username && message.payload.timestamp === timestamp) {
                    this.lastAcknowledgedTimestamp = timestamp;
                    changed = true;
                    continue;
                }
                newMessages.push(message);
            }
        }

        if (changed) {
            await db.ref(`users/${this.username}/lastAcknowledgedTimestamp`).set(this.lastAcknowledgedTimestamp);
        }

        await db.ref('messages').set(newMessages);
    }
}