const { Schema, model } = require('mongoose');

const schema = new Schema({
    email: {type: String, required: true, unique: true},
    password: {type: String, required: true},
    sourceId: {type: String, unique: true}
})

module.exports = model('User', schema);