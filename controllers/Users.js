const UserData = require("../dataModels/Users.js");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

if (process.env.NODE_ENV !== "production") {
  require("dotenv/config");
}

const { KEY } = process.env;
let newUser = {};
let users = [];

const register = async (req, res) => {
  try {
    /**se valida si no hay nada en el cuerpo del requerimiento */
    if (!req.body) {
      res.status(400).send("Debes indicar nombre, email password");
    }

    /**Se valida que se coloco todo el contenido de mi cuerpo */
    const { name, email, password } = req.body;

    if (!(email && name && password)) {
      res.status(400).send("Debes indicar nombre, email password");
    }
    /**Se valida que el usuario no exista */
    const userExist = users.find((user) => user.email === email);

    if (userExist) {
      res
        .status(400)
        .send(
          "El usuario existe, por favor inicia sesión con tus credenciales"
        );
    }

    /**Encriptar el password */
    const encryptedPassword = await bcrypt.hash(password, 10);

    /**Creamos el usuario */
    newUser = UserData.User(name, email, encryptedPassword);

    /**Agregamos el usuario a la base de datos */
    users = [...users, newUser];
  } catch (err) {
    console.log("Ha ocurrido un error", err);
  }

  return res.status(201).json(newUser);
};

const login = async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!(email && password)) {
      res.status(400).send("indica el usuario y contraseña");
    }

    /**Validar si el usuario existe */
    const user = users.find((us) => us.email === email);

    /**Validar la contraseña que colocas en el Body vs la contraseña guardada en la base de datos con bcrypt */

    if (user && (await bcrypt.compare(password, user.password))) {
      const token = jwt.sign({ email }, KEY, { expiresIn: "2h" });
      user.token = token;
      res.status(200).json(user);
    } else {
      res.status(403).send("Credenciales invalidas");
    }
  } catch (err) {
    console.log("Ha ocurrido un error", err);
  }
};

module.exports = { register, login };
