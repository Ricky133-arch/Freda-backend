const jwt = require('jsonwebtoken');

function authenticateToken(req, res, next) {
	const authHeader = req.headers['authorization'] || req.headers['Authorization'];
	const token = authHeader && authHeader.split(' ')[1];
	if (!token) return res.status(401).json({ message: 'Access denied' });

	try {
		const decoded = jwt.verify(token, process.env.JWT_SECRET);
		// Normalize payload to always provide userId
		req.user = {};
		req.user.userId = decoded.userId || decoded.id || decoded._id || decoded.sub || null;
		if (!req.user.userId) return res.status(403).json({ message: 'Invalid token payload' });
		next();
	} catch (err) {
		return res.status(403).json({ message: 'Invalid token' });
	}
}

module.exports = authenticateToken;
