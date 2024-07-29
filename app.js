require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const User = require('./model/User');

const app = express();

app.use(express.json());

app.get('/', (req, res) => {
    res.status(200).json({'msg': 'Welcome to the API!'});
});

app.get('/user/:id', checkToken, async (req, res) => {
    const id = req.params.id;
    try {
        const user = await User.findById(id, '-password');
        if (!user) {
            return res.status(404).json({msg: "User not found!"});
        }
        res.status(200).json({ user });
    } catch (error) {
        console.error(error);
        res.status(500).json({msg: "Server error!"});
    }
});

function checkToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({msg: 'Access denied!'});
    }

    try {
        const secret = process.env.SECRET;
        jwt.verify(token, secret);
        next();
    } catch (error) {
        console.error(error);
        res.status(401).json({msg: 'Invalid token!'});
    }
}

app.post('/auth/register', async (req, res) => {
    const { name, email, password, confirmpassword } = req.body;

    if (!name) {
        return res.status(422).json({'msg': 'The name is required!'});
    }

    if (!email) {
        return res.status(422).json({'msg': 'The email is required!'});
    }

    if (!password) {
        return res.status(422).json({'msg': 'The password is required!'});
    }

    if (password !== confirmpassword) {
        return res.status(422).json({'msg': 'The passwords do not match!'});
    }

    try {
        const userExists = await User.findOne({email: email});
        if (userExists) {
            return res.status(422).json({'msg': 'Email already registered!'});
        }

        const salt = await bcrypt.genSalt(12);
        const passwordHash = await bcrypt.hash(password, salt);

        const user = new User({ name, email, password: passwordHash });

        await user.save();
        res.status(201).json({msg: "User created successfully!"});
    } catch (error) {
        console.error(error);
        res.status(500).json({msg: "Server error!"});
    }
});

app.post('/auth/login', async (req, res) => {
    const { email, password } = req.body;

    if (!email) {
        return res.status(422).json({'msg': 'The email is required!'});
    }

    if (!password) {
        return res.status(422).json({'msg': 'The password is required!'});
    }

    try {
        const user = await User.findOne({email: email});
        if (!user) {
            return res.status(404).json({msg: "User not found!"});
        }

        const checkPassword = bcrypt.compare(password, user.password);
        if (!checkPassword) {
            return res.status(422).json({msg: "Invalid password!"});
        }

        const secret = process.env.SECRET;
        const token = jwt.sign({id: user._id}, secret);
        res.status(200).json({msg: 'Authentication successful!', token});
    } catch (error) {
        console.error(error);
        res.status(500).json({msg: "Server error!"});
    }
});

const PORT = process.env.PORT || 3000;

mongoose.connect(process.env.MONGO_URI)
    .then(() => {
        app.listen(PORT, () => {
            console.log(`Server running on port ${PORT}`);
        });
    })
    .catch(err => console.error(err));
