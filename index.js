const express = require('express')
const bodyParser = require('body-parser')
const path = require('path')
const mongoose = require('mongoose')
const bcrypt = require('bcryptjs')
const jwt = require('jsonwebtoken')
require('dotenv').config()

const app = express()


// body parser
app.use(bodyParser.json())
app.use(bodyParser.urlencoded({ extended: false }))

app.use('/', express.static(path.join(__dirname + '/static')))

// setup mongodb
const URI = "mongodb+srv://arun:1234@cluster0.t3qon.mongodb.net/JWT"

mongoose.connect(URI, { useNewUrlParser: true, useUnifiedTopology: true })
    .then(() => console.log('Database is connected'))
    .catch(err => console.log(err))


// model for store data
const user = new mongoose.Schema({
    password: { type: String, require: true },
    email: { type: String, require: true, unique: true }
})
const User = mongoose.model('User', user)


// register API
app.post('/register', async (req, res) => {
    const { pass: plainText, email } = req.body;

    // check all value is not empty
    if (!plainText || typeof plainText !== 'string') {
        return res.json({ status: 'error', error: 'Invalid Password' })
    }
    if (!email || typeof email !== 'string') {
        return res.json({ status: 'error', error: 'Invalid email' })
    }

    const password = await bcrypt.hash(plainText, 10)

    try {
        const response = await User.create({
            password,
            email
        })
        console.log(response)
    } catch (error) {
        // if email is already exist
        if (error.code === 11000) {
            return res.json({ status: 'error', error: 'Username in use' })
        } else {
            // if error in mongos
            throw error
        }
    }
    res.json({ status: 'ok' })
})

app.post('/login', async (req, res) => {
    const { email, pass } = req.body;
    const user = await User.findOne({ email }).lean()

    if (!user) {
        return res.json({ status: 'error', error: 'Invalid username/password' })
    }
    if (await bcrypt.compare(pass, user.password)) {
        const token = jwt.sign(
            {
                id: user._id,
                email: user.email
            },
            process.env.JWT_SECRET
        )
        return res.json({ status: 'ok', data: token })
    }
    res.json({ status: 'error', error: 'invalid username/password' })
})


app.post('/change', async (req, res) => {
    const { token, newpass } = req.body
    try {
        const user = jwt.verify(token, JWT_SECRET)
        const _id = user.id
        const hashpass = await bcrypt.hash(newpass, 10)
        await User.updateOne({ _id }, {
            $set: { pass: hashpass }
        })
        res.json({ status: 'ok' })
    } catch (error) {
        return res.json({ status: 'error', error: 'Signature error' })
    }
})



app.delete('/:id', (req, res) => {
    const { id } = req.params
    User.deleteOne({ _id: id })
        .then(() => {
            res.send(id + 'Deleted')
        })
        .catch(e => console.log(e))
})

app.delete('/', (req, res) => {
    User.remove({})
        .then(() => res.json({ message: 'all data erase' }))
        .catch(e => console.log(e))
})




const port = process.env.PORT || 3000
app.listen(port, console.log(`Server is up on port:${port}`))