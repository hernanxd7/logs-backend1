const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const admin = require('firebase-admin');

const router = express.Router();
const db = admin.firestore();

const JWT_SECRET = process.env.JWT_SECRET || 'uteq';




console.debug('Using JWT secret: ' + JWT_SECRET);

// User Registration
router.post('/register', async (req, res) => {
    // console.debug('Register on backend:', req.body);
    const { email, username, password } = req.body;
    
    if (!email || !password || !username) {
        return res.status(400).json({ message: 'Missing fields' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    await db.collection('users').add({
        username,
        email,
        password: hashedPassword
    });

    // console.log('Previous log to send to Firebase');
    res.status(201).json({ message: 'User registered' });
});

module.exports = router;
