import * as crypto from 'crypto';
import { publicKeyFromString } from './util';
import * as admin from 'firebase-admin';

export class CertificateInformation {
    readonly issuerIdentity: string;
    readonly issuerName: string;
    readonly ownerIdentity;
    readonly ownerName: string;
    readonly timestamp: number;

    constructor(timestamp: number, issuerIdentity: string, issuerName: string, ownerName: string, ownerIdentity) {
        this.issuerIdentity = issuerIdentity;
        this.issuerName = issuerName;
        this.ownerIdentity = ownerIdentity;
        this.ownerName = ownerName;
        this.timestamp = timestamp;
    }
}

export class Certificate {
    readonly info: CertificateInformation;
    readonly signature: string;

    constructor(info: CertificateInformation, signature: string) {
        this.info = info;
        this.signature = signature;
    }

    isValid(): boolean {
        if (
            !this.info || !this.signature || !this.info.issuerIdentity || !this.info.issuerName ||
            !this.info.ownerIdentity || !this.info.ownerName || !this.info.timestamp
        ) {
            return false;
        }

        const pk = publicKeyFromString(this.info.issuerIdentity);
        if (pk === null)
            return false;
        
        const verifier = crypto.createVerify('RSA-SHA256');
        verifier.update(JSON.stringify(this.info));

        return verifier.verify(pk, this.signature, 'hex');
    }

    static async publish(cert: Certificate) {
        const db = admin.database();
        let certificates: Certificate[] | null = (await db.ref('certificates').get()).val();
        if (!certificates)
            certificates = [];

        certificates.push(cert);
        await db.ref('certificates').set(certificates);
    }
}