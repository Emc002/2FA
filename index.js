const express = require('express');
const speakeasy = require('speakeasy');
const uuid = require('uuid');
const { JsonDB, Config } = require('node-json-db');

const app = express();
app.use(express.json());
const db = new JsonDB(new Config('myDatabase', true, false, '/'))
const PORT = process.env.PORT || 5000;

app.get('/api', (req, res) => res.json({ message: `Welcome to 2FA Example`}) )

// Register User and Create Temp Secret
app.post('/api/register', (req, res) => {
  const id = uuid.v4()
  const { username } = req.body;
  try{
    const path = `/user/${id}`;
    const temp_secret = speakeasy.generateSecret()
    db.push(path, { id, username, temp_secret })
    res.json({ id, username, secret: temp_secret.base32})
  } catch (e) {
    console.log(e)
    res.status(500).json({message: 'Error generating secret'})
  }
})

// Verify token and make secret permanent
app.post('/api/verify', async (req, res) => {
  const {token, userID} = req.body

  try{
    const path = `/user/${userID}`;
    const user = await db.getData(path);
    const { base32:secret } = user.temp_secret;

    const verified = speakeasy.totp.verify({ secret,
      encoding: 'base32',
      token });
    
      if (verified) {
        db.push(path, {id: userID, username:user.username, secret: user.temp_secret})
        res.json({ verify: true });
      } else {
        res.json({ verify: false })
      }

  } catch (e) {
    console.log(e)
    res.status(500).json({ message: `Error Finding user`})
  }
})

// Token Validated
app.post('/api/Validate', async (req, res) => {
  const {token, userID} = req.body

  try{
    const path = `/user/${userID}`;
    const user = await db.getData(path);
    const { base32:secret } = user.secret;

    const tokenValidates = speakeasy.totp.verify({ secret,
      encoding: 'base32',
      token, window: 1 });
    
      if (tokenValidates) {
        res.json({ tokenValidates: true });
      } else {
        res.json({ tokenValidates: false })
      }

  } catch (e) {
    console.log(e)
    res.status(500).json({ message: `Error Finding user`})
  }
})
app.listen(PORT, () => console.log(`Server is listening on PORT : ${PORT}`));
