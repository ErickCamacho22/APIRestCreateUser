const jwt = require("jsonwebtoken");

if (process.env.NODE_ENV !== "production") {
  require("dotenv/config");
}

const { KEY } = process.env;

const verifyToken = (req, res, next) => {
  const token = req.headers["x-access-token"];

  if (!token) {
    return res.status(403).send("No se a enviado el token de autenticación");
  }
  try {
    const decode = jwt.verify(token, KEY);
    req.user = decode;
  } catch (err) {
    return res.status(401).send("Token invalido");
  }
  return next();
};

module.exports = verifyToken;
