const express = require('express');
const bodyParser = require('body-parser');
const { generateRegistrationOptions, generateAuthenticationOptions, verifyRegistrationResponse, verifyAuthenticationResponse } = require('@simplewebauthn/server');
const { isoUint8Array } = require('@simplewebauthn/server/helpers');
const crypto = require('crypto');

const cors = require('cors');

const app = express();
app.use(bodyParser.json());
app.use(cors({ origin: 'https://cred-front.onrender.com' }));
const users = new Map(); // Store user credentials temporarily in memory

// Hardcoded user info for demo
const userEmail = "natsceo@gmail.com";
const userID = "user-id"; // Replace with any unique ID you want

app.post('/generate-registration-options', async (req, res) => {
    const options = await generateRegistrationOptions({
        rpName: "WebAuthDemo",
        rpID: "cred-front.onrender.com", // Change to your actual domain
        userID: isoUint8Array.fromUTF8String(userID),
        userName: userEmail,
        userDisplayName: "Nats CEO",
        attestationType: 'direct',
        pubKeyCredParams: [
            { type: 'public-key', alg: -7 }, // ECDSA with SHA-256
        ],
    });

    // Store the challenge with the user record
    users.set(userID, { 
        email: userEmail, 
        credential: null, 
        challenge: options.challenge // Store the challenge here
    }); 
    console.log(options);
    console.log(users);
    return res.json(options);
});

app.post('/register', async (req, res) => {
    const { response } = req.body;
    const user = users.get(userID); // Get the user by userID

    if (!user) {
        return res.status(404).json({ error: "User not found" });
    }

    console.log("in register");
    console.log(response);
    console.log("in try");

    try {
        const verification = await verifyRegistrationResponse({
            response,
            expectedChallenge: user.challenge, // Use the stored challenge
            expectedOrigin: "https://cred-front.onrender.com", // Change to your actual domain
            expectedRPID: "cred-front.onrender.com", // Change to your actual domain
        });

        console.log("verification");
        console.log(verification);

        user.credential = verification; // Save the credential
        console.log("user");
        console.log(user);
        return res.json({ status: "Registration successful", credential: user.credential });
    } catch (error) {
        return res.status(400).json({ error: "Registration failed", details: error.message });
    }
});
app.post('/generate-authentication-options', async (req, res) => {
    const user = users.get(userID);

    if (!user || !user.credential) {
        return res.status(400).send('User credentials not found');
    }

    const options = await generateAuthenticationOptions({
        rpID: 'cred-front.onrender.com',
        allowCredentials: [
            {
                id: user.credential.credentialID,
                type: 'public-key',
                transports: ['usb', 'ble', 'nfc'],
            },
        ],
        userVerification: 'preferred',
    });

    // Store the challenge with the user record
    users.set(userID, { ...user, challenge: options.challenge });

    return res.json(options);
});

app.post('/authenticate', async (req, res) => {
    const { id, rawId, response, type } = req.body;
    const user = users.get(userID);

    if (!user || !user.credential) {
        return res.status(400).send('User credentials not found');
    }

    try {
        const verification = await verifyAuthenticationResponse({
            credential: {
                id,
                rawId: isoUint8Array.fromBase64(rawId),
                response: {
                    authenticatorData: isoUint8Array.fromBase64(response.authenticatorData),
                    clientDataJSON: isoUint8Array.fromBase64(response.clientDataJSON),
                    signature: isoUint8Array.fromBase64(response.signature),
                    userHandle: response.userHandle ? isoUint8Array.fromBase64(response.userHandle) : undefined,
                },
                type,
            },
            expectedChallenge: user.challenge,
            expectedOrigin: 'https://cred-front.onrender.com',
            expectedRPID: 'cred-front.onrender.com',
            authenticator: user.credential,
        });

        if (verification.verified) {
            return res.json({ verified: true });
        } else {
            return res.status(400).json({ verified: false });
        }
    } catch (error) {
        console.error(error);
        return res.status(500).send('Authentication verification failed');
    }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}`);
});
