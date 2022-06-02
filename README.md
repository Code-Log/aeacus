# Aeacus

## Description
Aeacus is an api for secure automation of tasks across devices. Messages are signed by the
sending device using the user's private key and are then pushed to a server, where they wait to be acknowledged
by a device in possesion of the user's private key. Once acknowledged they are permanently deleted from the database.

**NOTE**: Currently, the user's private key is stored in encrypted DER form on the server (using PKCS#8 with AES-256-GCM).
This means that in theory, someone could be pulling of a man-in-the-middle attack here. I aim to fix the problem in future, but
for now I would just like to get a rough protocol in place that anyone can implement.

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