import * as admin from 'firebase-admin';

export interface Payload {
    readonly target: number;
    readonly timestamp: number;
    readonly type: string;
}

export class CommandPayload implements Payload {
    readonly target: number;
    readonly timestamp: number;
    readonly type: string;

    constructor(timestamp: number, target: number, ) {
        this.target = target;
        this.timestamp = timestamp;
        this.type = 'command';
    }
}

export class Message {
    readonly payload: Payload;
    readonly signature: string;
    readonly user: string;

    constructor(payload: Payload, signature: string, user: string) {
        this.payload = payload;
        this.signature = signature;
        this.user = user;
    }

    static async pushMessage(message: Message): Promise<boolean> {
        if  (!message || !message.payload || !message.signature || !message.user || !message.payload.timestamp)
            return false;

        const db = admin.database();
        let currentMessages: Array<Message> = (await db.ref('messages').get()).val();
        if (!currentMessages)
            currentMessages = [];

        currentMessages.push(message);
        await db.ref('messages').set(currentMessages);

        return true;
    }
}

export class MessagePackage {
    readonly messages: Array<Message>;
    readonly lastAcknowledgedTimestamp: number;

    constructor(messages: Array<Message>, lastAcknowledgedTimestamp: number) {
        this.messages = messages;
        this.lastAcknowledgedTimestamp = lastAcknowledgedTimestamp;
    }
}