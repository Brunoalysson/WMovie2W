/*Impoorts*/
require('dotenv').config()
const express = require('express')
const mongoose = require('mongoose')
const bcrypt = require('bcrypt')
const jwt = require('jsonwebtoken')

const app = express()

//Config JSON response
app.use(express.json())

//Models
const User = require('./models/User')

//Open Route - Public Route
app.get('/', (req, res) => {
    res.status(200).json({ msg: 'Bem-vindo a nossa API!' })
})

//Private Route
app.get('/user/:id', checkToken, async(req, res) => {

    const id = req.params.id

    //Check if user exists
    const user = await User.findById(id, '-password') //Exclui a senha do usuário do retorno

    if (!user) {
        return res.status(404).json({ msg: "Usuário não encontrado" })
    }

    res.status(200).json({ user }) //Retorna os dados do usuário
})

function checkToken(req, res, next) {

    const authHeader = req.headers['authorization']
    const token = authHeader && authHeader.split(" ")[1]

    if (!token) {
        return res.status(401).json({ msg: "Acesso negado" })
    }

    try {

        const secret = process.env.SECRET

        jwt.verify(token, secret)

        next()

    } catch (error) {
        res.status(400).json({ msg: "Token Inválido" })

    }
}

//Register User
app.post('/auth/register', async(req, res) => {
    const { name, email, password, confirmpassword } = req.body

    //Validations
    if (!name) {
        return res.status(422).json({ msg: "O nome é obrigatório" })
    }

    if (!email) {
        return res.status(422).json({ msg: "O email é obrigatório" })
    }

    if (!password) {
        return res.status(422).json({ msg: "A senha é obrigatória" })
    }

    if (password != confirmpassword) {
        return res.status(422).json({ msg: "As senhas não são iguais" })
    }

    //Check if user exists
    const userExists = await User.findOne({ email: email }) //Tipo uma cláusula WHERE no SQL

    if (userExists) {
        return res.status(422).json({ msg: "Utilize outro email" })
    }

    //Create password
    const salt = await bcrypt.genSalt(12) // Segurança pra ninguém Hackear
    const passwordhash = await bcrypt.hash(password, salt) //O salt dificulta a senha

    //Create User
    const user = new User({
        name,
        email,
        password: passwordhash,
    })

    try {
        await user.save()

        res.status(201).json({ msg: 'Usuário criado com sucesso' })

    } catch (error) {

        console.log(error)

        res.status(500).json({ msg: 'Ocorreu um erro no servidor, tente novamento mais tarde' })
    }
})

//Login User
app.post('/auth/login', async(req, res) => {
    const { name, email, password, confirmpassword } = req.body

    //Validations
    if (!email) {
        return res.status(422).json({ msg: "O email é obrigatório" })
    }

    if (!password) {
        return res.status(422).json({ msg: "A senha é obrigatória" })
    }

    //Check if user exists
    const user = await User.findOne({ email: email }) //Tipo uma cláusula WHERE no SQL

    if (!user) {
        return res.status(404).json({ msg: "Usuário não encontrado" })
    }

    //Check if password match
    const checkPassword = await bcrypt.compare(password, user.password)

    if (!checkPassword) {
        return res.status(422).json({ msg: "Senha inválida" })
    }

    try {
        const secret = process.env.SECRET

        const token = jwt.sign({
                id: user._id,
            },
            secret,
        )

        res.status(200).json({ msg: 'Autenticação realizada com sucesso', token })
    } catch (err) {
        console.log(error)

        res.status(500).json({ msg: 'Ocorreu um erro no servidor, tente novamento mais tarde' })
    }

})

//Credencials
const dbUser = process.env.DB_USER
const dbPassword = process.env.DB_PASS


mongoose.connect(`mongodb+srv://${dbUser}:${dbPassword}@cluster0.l1etuov.mongodb.net/`, ).then(() => {
    app.listen(3000)
    console.log("Conectou ao banco")
}).catch((err) => console.log(err))