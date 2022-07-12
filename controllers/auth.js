const User = require('../models/User')
const { StatusCodes } = require('http-status-codes')
const { BadRequestError, UnauthenticatedError } = require('../errors')
const bcrypt = require('bcryptjs')
const jwt = require('jsonwebtoken')


const register = async(req, res) => {

    const { name, email, password } = req.body;
    // if (!name || !email || !password) {
    //     throw new BadRequestError("Please provide name, email, and password")
    // }

    // hashing of password
    const salt = await bcrypt.genSalt(10)
    const hashPassword = await bcrypt.hash(password, salt)
    const tempUser = { name, email, password: hashPassword }

    const user = await User.create({...tempUser })
    const token = jwt.sign({ userId: user._id, name: user.name }, process.env.JWT_SECRET, { expiresIn: process.env.JWT_LIFETIME, })
    res.status(StatusCodes.CREATED).json({ user: { name: user.name }, token })
        // res.status(StatusCodes.CREATED).json({ user: { name: user.getName() }, token })
        // const token = user.createJWT()


}

const login = async(req, res) => {
    // accept input from body in POSTMAN
    const { email, password } = req.body

    // Check if the email, and password exist
    if (!email || !password) {
        throw new BadRequestError("Please provide email, and password")
    }

    // check if the email exist
    const user = await User.findOne({ email })
        // check if email exists
    if (!user) {
        throw new UnauthenticatedError('User Invalid Credentials')
    }

    // compare password
    // const isPasswordCorrect = bcrypt.compare(password, user.password)
    // if (!isPasswordCorrect) {
    //     throw new UnauthenticatedError('Password Invalid Credentials')
    // }
    const isPasswordCorrect = user.comparePassword(password)
    if (!isPasswordCorrect) {
        throw new UnauthenticatedError('Password Invalid Credentials')
    }


    const token = user.createJWT();
    res.status(StatusCodes.OK).json({ user: { name: user.name }, token })
        // console.log(token, user);

}


// const register = async(req, res) => {
//     const user = await User.create({...req.body })
//     const token = user.createJWT()
//     res.status(StatusCodes.CREATED).json({ user: { name: user.name }, token })
// }

// const login = async(req, res) => {
//     const { email, password } = req.body

//     if (!email || !password) {
//         throw new BadRequestError('Please provide email and password')
//     }
//     const user = await User.findOne({ email })
//     if (!user) {
//         throw new UnauthenticatedError('User Invalid Credentials')
//     }
//     const isPasswordCorrect = await user.comparePassword(password)
//     if (!isPasswordCorrect) {
//         throw new UnauthenticatedError('Password Invalid Credentials')
//     }
//     // compare password
//     const token = user.createJWT()
//     res.status(StatusCodes.OK).json({ user: { name: user.name }, token })
// }

module.exports = {
    login,
    register
}