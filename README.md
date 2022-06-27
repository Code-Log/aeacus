# Aeacus

## Description
Aeacus is an api for secure automation of tasks across devices. Messages are signed by the
sending device using the user's private key and are then pushed to a server, where they wait to be acknowledged
by a device in possesion of the user's private key. Once acknowledged they are permanently deleted from the database.

## Usage

Deployment is fairly simple. Right now, the server is using firebase for storage of the username, password hash,
public key, encrypted private key, any signatures for login tokens, and temporary message objects which are purged
once acknowledged.

First, you must create a firebase project and app with a realtime database. Next, you'll need to set up a 
service account for the admin SDK. This process should yield a javascript object of the credentials you require.
You'll want to export that object as a file named `firebaseCredentials.json`.

In your realtime database, you need to set up a ruleset that only allows data to be written by a service account.
Example:
```json5
{
  "rules": {
    "some_path": {
      "$uid": {
        // Allow only server to access and change data
        ".read": "auth != null && auth.uid == 'webapp'",
        ".write": "auth != null && auth.uid == 'webapp'"
      }
    }
  }
}
```

Currently, the `.env` file doesn't contain anything, however, I'll have it contain server variables in future.
When it does come into use, You will have to copy `.env.template` to `.env` and change the relevant variables in the
new file for the required configuration.

That is about it. To compile the code into JavaScript, run `npm run gcp-build`. This needs to be done every time code
is changed as well as before first start. The server can be started using `npm run start`.

## Protocol

Messages are sent from device to device using a standard JSON format.
Each message must contain a username, signature and payload.
The payload must contain at least the following information: a timestamp, type and target.

Here is a sample message object.

```json
{
  "payload": {
    "target": 1,
    "timestamp": 16342201,
    "type": "command"
  },
  "signature": "<signature in hex format>",
  "user": "joe"
}
```

The user must verify the payload object against the signature using the public key of the user specified in
the message object. It's important to note that although the JSON of two messages may be equivalent, they may not hash to the same
SHA-256 digest, so by convention, whenever an object needs to be signed, we will first order all of the keys within the object
according to alphabetical order.

All objects are signed using the RSA-SHA256 digital signature algorithm. The resulting signature is then hex encoded and attached
to the relevant message.

## Server-side credential storage
Aeacus, by design, utilizes server-side storage for the public and private keys. This presents a problem for
user security, as the server is able to pull off a man-in-the-middle attack. To combat this, we derive a secret from the user's
password as follows.

Firstly, a salt is generated. This salt is then used together with the string `username + password` to produce
a secret vault key using pbkdf2 with sha256 and 310000 iterations.
The same algorithm is then applied to `vaultkey + password` to create an authentication key. The authentication
key is then used to prove to the server that we know the password, without ever providing the server with said password.

The vault key is used to encrypt the private key, as well as any locally-stored sensitive information.

We then store the user's public key, private key and salt on the server, together with a sha256 hmac of all three components
appended together. The key used for the Hmac is also the user's vault key.
The server should never store the auth key in plaintext, although even if it does, we're still safe.
To maximize security, the authkey is further hashed with argon2id server-side and then stored.

Whenever authentication is required and the user does not have access to a signing key, we will use the auth key to authenticate.
For all other authentication, we generate a one-time token of length 128 bits and sign it. The server then verifies the signature
against the token and stores it. If the server ever encounters a token it's seen before, authentication automatically fails.

## Client-side verification of messages

When a client receives a message, it is very important that they follow the following verification procedure to ensure the
validity of a message.
c
Since we are usually going to fetch a package of messages, the server MUST order the messages by timestamp and
if all the messages can't be sent at once, it must send only the oldest messages.

First, the client must verify that all messages follow the minimum requirements for being correctly structured without
doing signature verification and timestamp checking.

The client must sort the message package by timestamp again after receiving it.
The client then iterates through all the messages, going from oldest timestamp to newest, and verify two things:

1. The client must verify that the timestamp is strictly larger than the last seen timestamp.
2. The client must verify that the signature attached to the message matches the payload.

If any of these checks fails, the client must add the erroneous messages to a 'bad messages' list.
The client then sends the timestamps of the 'good' and 'bad' messages back to the server.
The server then updates it's version of the last acknowledged timestamp accordingly and discards all messages in the 'bad'
pile without updating the last ack.