const jwt = require("jsonwebtoken");

const authMiddleware = (req, res, next) => {
  const token = req.headers.authorization?.split(" ")[1];
  
  if (!token) {
    return res.status(401).json({ 
      success: false,
      message: "Login karo pehle!" 
    });
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.userId = decoded.id;
    next();
  } catch (error) {
    res.status(401).json({ 
      success: false,
      message: "Token invalid hai, dobara login karo!" 
    });
  }
};

module.exports = authMiddleware;
