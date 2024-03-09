require('dotenv').config();
const express = require('express');
const cors = require('cors');
const fs = require('fs'); 
const path = require('path');  
const session = require('express-session'); 
const bcrypt = require('bcrypt'); 
const validator = require('validator');  
const cookieParser = require('cookie-parser'); 
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy; 
const { google } = require('googleapis');

const app = express();
const port = 3000;

// Basic data store 
const dbFile = 'db.json';
let db = { users: [] }; 

// Load existing data (if the file exists)
if (fs.existsSync(dbFile)) {
    db = JSON.parse(fs.readFileSync(dbFile));
}

// Configure middleware
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public'))); 
app.use(cookieParser()); // Include cookie-parser 
app.use(session({ 
    secret: 'your_strong_secret_key', 
    resave: false,
    saveUninitialized: false,  
}));

// OAuth Setup (Passport.js)
const config = require('./config'); // Import your config file

passport.use(new GoogleStrategy({
    clientID: config.google.clientId,
    clientSecret: config.google.clientSecret,
    callbackURL: 'http://localhost:3000/auth/callback' 
  },
  (accessToken, refreshToken, profile, done) => {
    console.log('Access Token:', accessToken);
    return done(null, { profile, accessToken }); // Pass accessToken along for later use
  }
));

passport.serializeUser((user, done) => done(null, user));
passport.deserializeUser((user, done) => done(null, user)); 

app.use(passport.initialize());
app.use(passport.session());

// Authentication Routes
app.get('/auth/google', 
  passport.authenticate('google', { scope: ['https://www.googleapis.com/auth/analytics.readonly'] })
);

app.get('/auth/callback', 
    passport.authenticate('google', { failureRedirect: '/' }), // Adjust redirect URLs as needed
    (req, res) => {
        res.redirect('/dashboard'); // Replace '/dashboard' with correct dashboard route
    }
);

// Simulated login endpoint
app.post('/login', async (req, res) => {
    const username = validator.escape(req.body.username); // Sanitization
    const password = validator.escape(req.body.password); // Sanitization 

    console.log('Login attempt with username:', username); 

    const user = db.users.find(user => user.username === username);

    if (user && await bcrypt.compare(password, user.password)) { 
        // Successful login
        const sessionId = generateSecureSessionId(); 
        res.cookie('sessionId', sessionId, { 
            httpOnly: true,  
            secure: true,   
            maxAge: 3600000 // Example: 1 hour 
        });  
        res.send('Login successful!'); 
    } else {
        res.status(401).send('Invalid credentials'); 
    }
});

// Logout endpoint
app.post('/logout', (req, res) => {
    req.session.destroy(); 
    res.clearCookie('sessionId'); // Clear the session cookie
    res.send('Logout successful!'); 
});

// Registration endpoint (NEW)
app.post('/register', async (req, res) => {
    // ... (Your existing register endpoint code)
});

// Middleware for checking sessions (Illustrative)
app.use((req, res, next) => {
    // ... (Your existing middleware code)
});

// A Simple Route to Test API Access
app.get('/test-api', passport.authenticate('google'), async (req, res) => {
   // ... (Google Analytics API fetching code)
});

// Save data to file on server shutdown
process.on('SIGINT', saveData);
process.on('SIGTERM', saveData);

// ... (Rest of your server.js code)

app.listen(port, () => {
  console.log(`Server listening on port ${port}`);
});
