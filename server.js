const express = require('express');
const bodyParser = require('body-parser');
const { generateRegistrationOptions, generateAuthenticationOptions, verifyRegistrationResponse, verifyAuthenticationResponse } = require('@simplewebauthn/server');
const { isoUint8Array } = require( '@simplewebauthn/server/helpers');

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

    users.set(userID, { email: userEmail, credential: null }); // Initialize user record
    console.log(options)
    console.log(users)
    return res.json(options);
});

app.post('/register', async (req, res) => {
    const { response } = req.body;
    const user = users.get(userID); // Get the user by userID

    if (!user) {
        return res.status(404).json({ error: "User not found" });
    }
    console.log("in register")
    console.log(response)
    console.log("in try")
    try {
        const verification = await verifyRegistrationResponse({
            response,
            expectedChallenge: response.challenge,
            expectedOrigin: "https://cred-front.onrender.com/", // Change to your actual domain
            expectedRPID: "cred-front.onrender.com/", // Change to your actual domain
        });

        console.log("verification")
        console.log(verification)

        user.credential = verification; // Save the credential
        console.log("user")
        console.log(user)
        return res.json({ status: "Registration successful", credential: user.credential });
    } catch (error) {
        return res.status(400).json({ error: "Registration failed", details: error.message });
    }
});

app.post('/generate-authentication-options', async (req, res) => {
    const user = users.get(userID); // Get the user by userID

    if (!user || !user.credential) {
        return res.status(404).json({ error: "User not found or not registered" });
    }

    const options = await generateAuthenticationOptions({
        allowCredentials: [user.credential], // Allow only registered credentials
        challenge: "randomChallengeString", // Use a secure random challenge in production
    });

    return res.json(options);
});

app.post('/authenticate', async (req, res) => {
    const { response } = req.body;
    const user = users.get(userID); // Get the user by userID

    if (!user || !user.credential) {
        return res.status(404).json({ error: "User not found or not registered" });
    }

    try {
        const verification = await verifyAuthenticationResponse({
            response,
            expectedChallenge: "randomChallengeString", // Must match the challenge used in generate-authentication-options
            expectedOrigin: "https://cred-front.onrender.com/", // Change to your actual domain
            expectedRPID: "cred-front.onrender.com/", // Change to your actual domain
            authenticator: user.credential,
        });

        return res.json({ status: "Authentication successful", user: userEmail });
    } catch (error) {
        return res.status(400).json({ error: "Authentication failed", details: error.message });
    }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}`);
});
