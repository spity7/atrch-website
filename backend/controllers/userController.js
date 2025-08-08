const User = require("../models/userModel.js");
const generateTokenAndSetCookie = require("../utils/helpers/generateTokenAndSetCookie.js");
const isPasswordComplex = require("../utils/helpers/isPasswordComplex.js");
const sendVerificationEmail = require("../utils/helpers/sendVerificationEmail.js");
const { Parser } = require("json2csv");
const moment = require("moment");
const logger = require("../config/logger.js");

exports.signupUser = async (req, res) => {
  try {
    const { firstname, lastname, email, username, password, role } = req.body;

    // Validate password complexity
    if (!isPasswordComplex(password)) {
      logger.debug(`Password isn't complex enough`);
      return res.status(400).json({
        error: "Password does not meet the complexity requirements",
        errorCode: "PASSWORD_COMPLEXITY_ERROR",
      });
    }

    // Search for the email in the database
    const userEmail = await User.findOne({ email });
    if (userEmail) {
      return res.status(400).json({ error: "Email already taken" });
    }

    // Search for the username in the database
    const userUsername = await User.findOne({ username });
    if (userUsername) {
      return res.status(400).json({ error: "Username already taken" });
    }

    // Create a new user
    const newUser = new User({
      firstname,
      lastname,
      email,
      username,
      password,
      role,
    });

    // Save the new user
    await newUser.save();

    await sendVerificationEmail(newUser);

    res.status(201).json({
      message:
        "Signup successful! Please check your email to verify your account.",
    });
  } catch (err) {
    logger.error("Error in signupUser: ", err.message);
    res.status(500).json({ error: err.message });
  }
};

exports.loginUser = async (req, res) => {
  try {
    const { emailOrUsername, password } = req.body;

    // search for user via username or email
    const user = await User.findOne({
      $or: [{ email: emailOrUsername }, { username: emailOrUsername }],
    });

    // user not found
    if (!user) {
      return res.status(400).json({
        error: "Invalid credentials. Try again!",
        errorcode: "USER_NOT_FOUND",
      });
    }

    // check password
    const isPasswordCorrect = await user.comparePassword(password);

    // password not correct
    if (!isPasswordCorrect) {
      return res.status(400).json({
        error: "Invalid credentials. Try again!",
        errorcode: "PASSWORD_NOT_CORRECT",
      });
    }

    // check if user is verified
    if (!user.isVerified) {
      return res
        .status(400)
        .json({ error: "Please verify your email before logging in." });
    }

    // generate and set JWT token
    generateTokenAndSetCookie(user._id, res);

    // successfully logged in
    logger.debug(`User ${emailOrUsername} logged in successfully.`);

    // Return the user data
    res.status(200).json({
      _id: user._id,
      firstname: user.firstname,
      lastname: user.lastname,
      email: user.email,
      username: user.username,
      role: user.role,
      isVerified: user.isVerified,
    });
  } catch (error) {
    logger.error("Error in loginUser: ", error.message);
    res.status(500).json({ error: "An error occurred. Please try again." });
  }
};

exports.logoutUser = (req, res) => {
  try {
    res.clearCookie("jwt"); // Clear the JWT cookie
    res.status(200).json({ message: "User logged out successfully" });
  } catch (err) {
    logger.error("Error in logoutUser: ", err.message);
    res.status(500).json({ error: "An error occurred. Please try again." });
  }
};
