require('dotenv').config();
const express = require('express');
const cors = require('cors');
const fs = require('fs'); 
const path = require('path');  
const session = require('express-session'); 
const bcrypt = require('bcrypt'); 
const validator = require('validator');  
const cookieParser = require('cookie-parser'); 

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
    const username = validator.escape(req.body.username); // Sanitization
    const password = validator.escape(req.body.password); // Sanitization

    // Password Validation
    const minPasswordLength = 8;
    if (password.length < minPasswordLength) {
        res.status(400).send(`Password must be at least ${minPasswordLength} characters long`);
        return; 
    }

    // Hash the password
    const saltRounds = 10; 
    const hashedPassword = await bcrypt.hash(password, saltRounds);

    if (db.users.find(user => user.username === username)) {
        res.status(400).send('Username already exists');
    } else {
        const newUser = { id: Date.now(), username, password: hashedPassword }; 
        db.users.push(newUser);
        saveData(); 
        res.send('Registration successful!');
    }
});

// Middleware for checking sessions (Illustrative)
app.use((req, res, next) => {
    const sessionId = req.cookies.sessionId;
    if (sessionId && db.users.find(user => user.id === sessionId)) {
      req.userId = sessionId;
    } 
    next(); 
});

// Save data to file on server shutdown
process.on('SIGINT', saveData);
process.on('SIGTERM', saveData);

function saveData() {
    fs.writeFileSync(dbFile, JSON.stringify(db));
    console.log('Data saved to db.json');
}

// Helper function to generate secure session IDs (Example)
function generateSecureSessionId() {
    // For production, use a more robust session ID generation library
    return Date.now().toString(); 
}


app.listen(port, () => {
  console.log(`Server listening on port ${port}`);
});
