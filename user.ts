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
    private readonly authHash: string;
    private readonly username: string;
    private readonly publicKey: string;
    private readonly secretKey: string;
    readonly salt: string;
    private lastAcknowledgedTimestamp: number;
    private hmac: string;

    constructor(username: string, hash: string, publicKey: string, secretKey: string, lastAcknowledgedTimestamp: number, salt: string, hmac: string) {
        this.username = username;
        this.authHash = hash;
        this.publicKey = publicKey;
        this.secretKey = secretKey;
        this.salt = salt;
        this.hmac = hmac;
        if (!lastAcknowledgedTimestamp)
            this.lastAcknowledgedTimestamp = 0;
        else
            this.lastAcknowledgedTimestamp = lastAcknowledgedTimestamp;
    }

    getPublicKey(): crypto.KeyObject {
        return crypto.createPublicKey({
            key: this.publicKey,
            format: 'pem',
            type: 'spki'
        });
    }

    getPublicKeyEncoded(): string {
        return this.publicKey;
    }

    getUsername(): string {
        return this.username;
    }

    getHash(): string {
        return this.authHash;
    }

    static async verifyLogin(username: string, authKey: string): Promise<User> {
        const db = admin.database();
        const userSnapshot = await db.ref(`users/${username}`).get();
        const userObject: User = userSnapshot.val();
        const user = new User(
            userObject.username,
            userObject.authHash,
            userObject.publicKey,
            userObject.secretKey,
            (!userObject.lastAcknowledgedTimestamp) ? 0 : userObject.lastAcknowledgedTimestamp,
            userObject.salt,
            userObject.hmac
        );

        const isValid = await argon2Verify({
            password: authKey,
            hash: user.authHash
        });

        return (isValid) ? user : null;
    }

    static async createUser(username: string, authKey: string, publicKey: string, secretKey: string, salt: string, hmac: string): Promise<User> {
        const db = admin.database();
        const ref = await db.ref(`users/${username}`).get();
        if (ref.val() != null)
            throw new UserCreateException('User already exists!');

        const authKeySalt = crypto.randomBytes(64);
        const authHash = await argon2id({
            password: authKey,
            salt: authKeySalt,
            parallelism: 1,
            iterations: 256,
            memorySize: 512,
            hashLength: 64,
            outputType: 'encoded'
        });

        const user = new User(
            username,
            authHash,
            publicKey,
            secretKey,
            0,
            salt,
            hmac
        );
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

    verifyToken(token: string, signature: string): boolean {
        const verify = crypto.createVerify('RSA-SHA256');
        verify.write(token);
        return verify.verify(this.getPublicKey(), signature, 'hex');
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

        ourMessages.sort((a, b) => a.payload.timestamp - b.payload.timestamp);

        return new MessagePackage(ourMessages, this.lastAcknowledgedTimestamp);
    }

    async verifyAuthKey(authKey: string): Promise<boolean> {
        return await argon2Verify({
            password: authKey,
            hash: this.authHash
        });
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
                    user.authHash,
                    user.publicKey,
                    user.secretKey,
                    user.lastAcknowledgedTimestamp,
                    user.salt,
                    user.hmac
                );
            }
        }

        return null;
    }

    async acknowledgeMessages(timestamps: number[], bad: number[]) {
        const db = admin.database();
        let serverMessages: Message[] = (await db.ref('messages').get()).val();

        if (!serverMessages)
            serverMessages = [];

        const newMessages: Message[] = [];
        let changed = false;
        for (const message of serverMessages) {
            if (message.user === this.username && timestamps.indexOf(message.payload.timestamp) != -1) {
                if (message.payload.timestamp > this.lastAcknowledgedTimestamp)
                    this.lastAcknowledgedTimestamp = message.payload.timestamp;
                changed = true;
            } else {
                newMessages.push(message);
            }
        }

        const goodMessages: Message[] = [];
        for (let i = newMessages.length - 1; i >= 0; i--) {
            if (bad.indexOf(newMessages[i].payload.timestamp) == -1)
                goodMessages.push(newMessages[i]);
        }

        if (changed) {
            await db.ref(`users/${this.username}/lastAcknowledgedTimestamp`).set(this.lastAcknowledgedTimestamp);
        }

        await db.ref('messages').remove();
        await db.ref('messages').set(goodMessages);
        console.log(goodMessages);
    }
}