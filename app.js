require("dotenv").config();
require("./config/database").connect();
const express = require("express");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const QR = require("qrcode");

const app = express();

app.use(express.json());
const User = require("./user");
const qrCode = require("./config/model/qrcode");
app.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!(email && password)) {
      res.status(400).send("All input is required");
    }

    const user = await User.findOne({ email });

    if (user && (await bcrypt.compare(password, user.password))) {
      const token = jwt.sign(
        { user_id: user._id, email },
        process.env.TOKEN_KEY,
        {
          expiresIn: "2h",
        }
      );

      user.token = token;

      return res.status(200).json({ token });
    }
    return res.status(400).send("Invalid Credentials");
  } catch (err) {
    console.log(err);
  }
});

app.post("/register", async (req, res) => {
  try {
    const { first_name, last_name, email, password } = req.body;

    if (!(email && password && first_name && last_name)) {
      res.status(400).send("All input is required");
    }

    const oldUser = await User.findOne({ email });

    if (oldUser) {
      return res.status(409).send("User Already Exist. Please Login");
    }

    encryptedPassword = await bcrypt.hash(password, 10);

    const user = await User.create({
      first_name,
      last_name,
      email: email.toLowerCase(),
      password: encryptedPassword,
    });

    const token = jwt.sign(
      { user_id: user._id, email },
      process.env.TOKEN_KEY,
      {
        expiresIn: "2h",
      }
    );

    res.status(201).json({ token });
  } catch (err) {
    console.log(err);
  }
});

app.post("/qr/generate", async (req, res) => {
  try {
    const { userId } = req.body;

    if (!userId) {
      res.status(400).send("User Id is required");
    }

    const user = await User.findById(userId);

    if (!user) {
      res.status(400).send("User not found");
    }

    const qrExist = await qrCode.findOne({ userId });

    if (!qrExist) {
      await qrCode.create({ userId });
    } else {
      await qrCode.findOneAndUpdate({ userId }, { $set: { disabled: true } });
      await qrCode.create({ userId });
    }
    const encryptedData = jwt.sign(
      { userId: user._id },
      process.env.TOKEN_KEY,
      {
        expiresIn: "1d",
      }
    );

    const dataImage = await QR.toDataURL(encryptedData);

    return res.status(200).json({ dataImage });
  } catch (err) {
    console.log(err);
  }
});

app.post("/qr/scan", async (req, res) => {
  try {
    const { token, deviceInformation } = req.body;

    if (!token && !deviceInformation) {
      res.status(400).send("Token and deviceInformation is required");
    }

    const decoded = jwt.verify(token, process.env.TOKEN_KEY);

    const qrCode = await QRCode.findOne({
      userId: decoded.userId,
      disabled: false,
    });

    if (!qrCode) {
      res.status(400).send("QR Code not found");
    }

    const connectedDeviceData = {
      userId: decoded.userId,
      qrCodeId: qrCode._id,
      deviceName: deviceInformation.deviceName,
      deviceModel: deviceInformation.deviceModel,
      deviceOS: deviceInformation.deviceOS,
      deviceVersion: deviceInformation.deviceVersion,
    };

    const connectedDevice = await ConnectedDevice.create(connectedDeviceData);

    await QRCode.findOneAndUpdate(
      { _id: qrCode._id },
      {
        isActive: true,
        connectedDeviceId: connectedDevice._id,
        lastUsedDate: new Date(),
      }
    );

    const user = await User.findById(decoded.userId);

    const authToken = jwt.sign({ user_id: user._id }, process.env.TOKEN_KEY, {
      expiresIn: "2h",
    });

    return res.status(200).json({ token: authToken });
  } catch (err) {
    console.log(err);
  }
});

module.exports = app;
