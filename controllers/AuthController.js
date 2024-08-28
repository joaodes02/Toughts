const User = require("../models/User");

const bcrypt = require("bcryptjs");

module.exports = class AuthController {
  static login(req, res) {
    res.render("auth/login");
  }

  static async loginPost(req, res) {
    const { email, password } = req.body;

    //find user
    const user = await User.findOne({ where: { email: email } });

    if (!user) {
      req.flash("message", "Usuario não encontrado! ");
      res.render("auth/login");

      return;
    }

    //check if passwords match

    const passwordMatch = bcrypt.compareSync(password, user.password);

    if (!passwordMatch) {
      req.flash("message", "Senha inválida! Tente novamente.");
      res.render("auth/login");

      return;
    }

    //initialize session
    req.session.userid = user.id;

    req.flash("message", "Autenticação realizada com sucesso!");

    req.session.save(() => {
      res.redirect("/");
    });
  }

  static register(req, res) {
    res.render("auth/register");
  }

  static async registerPost(req, res) {
    const { name, email, password, confirmpassword } = req.body;

    // password validation

    if (password != confirmpassword) {
      req.flash("message", "As senhas não conferem, tente novamente.");
      res.render("auth/register");

      return;
    }

    //check if user exist
    const checkIfUserExist = await User.findOne({ where: { email: email } });

    if (checkIfUserExist) {
      req.flash("message", "Esse e-mail já está vinculado a uma conta.");
      res.render("auth/register");

      return;
    }

    //create a password

    const salt = bcrypt.genSaltSync(10);
    const hashedPassword = bcrypt.hashSync(password, salt);

    const user = {
      name,
      email,
      password: hashedPassword,
    };

    try {
      const createdUser = await User.create(user);

      req.flash("message", "Cadastrado com sucesso!");

      req.session.userid = createdUser.id;

      req.session.save(() => {
        res.redirect("/");
      });
    } catch (err) {
      console.log(err);
    }
  }
  static logout(req, res) {
    req.session.destroy();
    res.redirect("/login");
  }
};
