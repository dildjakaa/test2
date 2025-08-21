const mongoose = require('mongoose');

const UserSchema = new mongoose.Schema(
	{
		username: { type: String, required: true },
		usernameLower: { type: String, required: true, unique: true },
		passwordHash: { type: String, required: true },
	},
	{ timestamps: { createdAt: 'createdAt', updatedAt: 'updatedAt' } }
);

UserSchema.index({ usernameLower: 1 }, { unique: true });

module.exports = mongoose.model('User', UserSchema);



