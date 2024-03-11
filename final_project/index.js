const express = require('express');
const jwt = require('jsonwebtoken');
const session = require('express-session');
const customer_routes = require('./router/auth_users.js').authenticated;
const genl_routes = require('./router/general.js').general;

const app = express();

app.use(express.json());

app.use("/customer", session({ secret: "fingerprint_customer", resave: true, saveUninitialized: true }));

app.use("/customer/auth/*", function auth(req, res, next) {
  // Get the access token from the request headers
  const accessToken = req.headers.authorization && req.headers.authorization.split(' ')[1];

  // Check if the access token exists
  if (!accessToken) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  // Verify the access token
  jwt.verify(accessToken, 'your_secret_key', (err, user) => {
    if (err) {
      return res.status(401).json({ error: 'Unauthorized' });
    }

    // Set user information in the session
    req.session.user = user;

    // Continue to the next middleware or route handler
    next();
  });
});

const PORT = 5000;

app.use("/customer", customer_routes);
app.use("/", genl_routes);

app.listen(PORT, () => console.log("Server is running"));
