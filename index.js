const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { check, validationResult } = require('express-validator');
const { underline } = require('colors');

const auth = require('./middleware/auth');


const app = express();
const port = process.env.PORT || 3000;

app.use(express.json({ extended: false }));
app.listen(port, () => console.log(`Listening on PORT: ${port}`.cyan.bold));


const connectDB = async () => {
    try {
        const conn = await mongoose.connect('DB Connection details goes here',{
            useNewUrlParser: true,
            useUnifiedTopology: true,
            useCreateIndex: true,
            useFindAndModify: false,
        });
        console.log(`Connected to MongoDB: ${conn.connection.host}`.yellow.bold);
    } catch (err) {
        console.log(`Error ${err}`.red.bold);
        process.exit(1);
    }
}
connectDB();

// schema 
const UserSchema = new mongoose.Schema({
    name: {
        type: String,
        required: true,
        minlength: 2,
        maxlength: 50
    },
    email: { 
        type: String,
        required: true,
        unique: true,
        minlength: 2,
        maxlength: 50
    },
    password: {
        type: String,
        required: true,
        minlength: 2,
        maxlength: 250
    }
})

// model
const User = mongoose.model('user', UserSchema);



// @route   POST /api/users
// @desc    Register user
// @access  Public
app.post('/api/users', [
    check('name', 'Name is required').not().isEmpty(),
    check('email', 'Please include a valid email').isEmail(),
    check('password', 'Please enter a password with 6 or more characters').isLength({ min: 6})
], async (req, res) => {
    
    const errors = validationResult(req);
    if(!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }
    const { name, email, password } = req.body;
    
    try {
        // see if user exists. if yes => error
        let user = await User.findOne({ email });
        if(user) {
            return res.status(400).json({ errors: [{msg: 'User already exists' }] });
        }
        // encrypt pasword using bcrypt
        user = new User({
            name,
            email,
            password
        });
        const salt = await bcrypt.genSalt(10);
        user.password = await bcrypt.hash(password, salt);
        await user.save();
        // return jsonwebtoken
        const payload = {
            user:{
                id: user.id
            }
        }
        jwt.sign(
            payload, 
            "mysecrettoken", 
            {expiresIn: 360000000000},
            (err, token) =>{
                if(err) throw err;
                res.json({ token });
            })
                //jwt secret should be set in a separate config file (good option) or as an environment variable (best option)
                //expiresIn is in seconds...should have a lower value in prod like 2-3hours.
    } catch (err) {
        res.status(500).send(err.message);
    }
})


// @route   GET /api/auth 
// @desc    Authentication for users -- test for jwt token
// @access  Public
app.get('/api/auth', auth, async (req, res) => {
    try {
        const user = await User.findById(req.user.id).select('-password');
        res.json(user);
    } catch (err) {
        res.status(500).send(err.message);
    }
})


// @route   POST /api/auth
// @desc    Authentication Loign for users -- using email and password
// @access  Public
app.post('/api/auth', [
    check('email', 'Please include a valid email').isEmail(),
    check('password', 'Password is required').exists()
], async (req, res) => {
    
    const errors = validationResult(req);
    if(!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }
    const { email, password } = req.body;
    
    try {
        // see if user exists. if yes => error
        let user = await User.findOne({ email });
        if(!user) {
            return res.status(400).json({ errors: [{msg: 'Invalid credentials' }] });
        }
        const isMatch = await bcrypt.compare(password, user.password);
        if(!isMatch){
            return res.status(400).json({ errors: [{msg: 'Invalid credentials' }] });
        }
        // return jsonwebtoken
        const payload = {
            user:{
                id: user.id
            }
        }
        jwt.sign(
            payload, 
            "mysecrettoken", 
            {expiresIn: 360000000000},
            (err, token) =>{
                if(err) throw err;
                res.json({ token });
            })
    } catch (err) {
        res.status(500).send(err.message);
    }
})
