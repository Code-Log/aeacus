import * as crypto from 'crypto';

export function publicKeyFromString(input: string): crypto.KeyObject | null {
    try {
        return crypto.createPublicKey({
            key: input,
            type: 'spki',
            format: 'pem'
        });
    } catch (e) {
        console.error(`Parsing of public key ${input} failed!`);
        console.error(e);
        return null;
    }
}
