const express = require('express')
const User = require('../models/user')
const auth = require('../middleware/auth')
const router = new express.Router()
const cryptoRandom = require('crypto-random-string')

router.post('/users', async (req, res) => {
    const user = new User(req.body)
    const verificationToken = cryptoRandom({length: 16})
    user.verificationToken = verificationToken
    
    try {
        await user.save()
        
        //Do not give token after successful registration, user must confirm the registration first!
        //const token = await user.generateAuthToken()
        
        res.status(201).send({ user, verificationToken })
    } catch (e) {
        res.status(400).send(e)
    }
})

router.post('/users/login', async(req, res) => {
    if (!process.env.JWT_SECRET || process.env.JWT_SECRET == ""){
        res.status(400).send("Fatal Error, please contact the developer.")
    } else {
        try {
            const user = await User.findByCredentials(req.body.email, req.body.password)
            const token = await user.generateAuthToken()
            res.send({ user, token })
        } catch(e) {
            res.status(400).send(e.toString())
        }
    }
})

router.patch('/users/password', auth, async (req, res) => {
    try {
        const user = await User.findByCredentials(req.user.email, req.body.passwordold)
        if (!user){
            res.status(400).send()
        }
        const password = await User.encryptPassword(req.body.passwordnew)
        const query = {_id: req.user._id}
        await User.findOneAndUpdate(query, {password: password})

        res.send()
    } catch(e) {
        res.status(500).send(e.toString())
    }
})

router.post('/users/logout', auth, async (req, res) => {
    try {
        req.user.tokens = req.user.tokens.filter((token) => {
            return token.token !== req.token
        })
        await req.user.save()

        res.send()
    } catch(e) {
        res.status(500).send()
    }
})

router.post('/users/logoutAll', auth, async (req, res) => {
    try {
        req.user.tokens = []
        await req.user.save()

        res.send()
    } catch(e) {
        res.status(500).send()
    }
})

router.get('/users/me', auth, async (req, res) => {
    res.send(req.user)
})

router.patch('/users/me', auth, async (req, res) => {
    const updates = Object.keys(req.body)
    const allowedUpdates = ['name', 'email', 'password']    
    const isValidOperation = updates.every((update) => allowedUpdates.includes(update))

    if (!isValidOperation){
        return res.status(400).send({error: "Invalid updates!"})
    }

    try {
        updates.forEach((update) => req.user[update] = req.body[update])
        await req.user.save()
        res.send(req.user)
    } catch(e) {
        res.status(400).send(e)
    } 
})

router.delete('/users/me', auth, async (req, res) => {
    try {        
        await req.user.remove()
        res.send(req.user)
    } catch(e) {
        res.status(500).send(e)
    }
})

router.patch('/users/verifyRegistration/:token', async (req, res) => {
    try {
        const user = await User.findOneAndUpdate({ verificationToken: req.params.token, status: 2 }, { status: 1 })

        if (!user){
            return res.status(404).send()
        }

        res.send(user)
    } catch(e) {
        res.status(500).send(e)
    }  
})

module.exports = router