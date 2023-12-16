
const express = require("express");
const bodyParser = require('body-parser');
const JsonDB = require('node-json-db').JsonDB;
const Config = require('node-json-db/dist/lib/JsonDBConfig').Config;
const uuid = require("uuid");
const speakeasy = require("speakeasy");
const jwt = require('jsonwebtoken');
const secretKey = 'yourSecretKey';

const app = express();

// The second argument is used to tell the DB to save after each push
// If you put false, you'll have to call the save() method.
// The third argument is to ask JsonDB to save the database in an human readable format. (default false)
// The last argument is the separator. By default it's slash (/)
var db = new JsonDB(new Config("myDataBase", true, false, '/'));

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

app.get("/api", (req,res) => {
  res.json({ message: "Welcome to the two factor authentication exmaple" })
});

// Middleware to verify JWT token
function verifyToken(req, res, next) {
  const token = req.headers.authorization;

  if (!token) {
    return res.status(401).json({ message: 'Unauthorized - Missing token' });
  }

  jwt.verify(token, secretKey, (err, decoded) => {
    if (err) {
      return res.status(401).json({ message: 'Unauthorized - Invalid token' });
    }
    req.user = decoded;
    next();
  });
}

const checkPermissions = (permissionName) => async (req, res, next) => {
  const userId = req.user.id;
  const roleId = req.user.roleId;

  try {
    // Get the user's permissions based on their role
    const userPermissions = await db.getData(`/roles/${roleId}/permissions`);

    // Check if the user has the required permission
    if (userPermissions.includes(permissionName)) {
      next();
    } else {
      res.status(403).json({ message: 'Forbidden - Insufficient permissions' });
    }
  } catch (error) {
    res.status(500).json({ message: 'Error checking permissions', error: error.message });
  }
};


app.post("/api/register", async (req, res) => {
  const id = uuid.v4();
  try {
    const { name, password, email, roleId } = req.body
    // console.log(">>>>>>>>",password);
    if (!name || !password || !email || !roleId) {
      return res.status(401).send({ "status":"400","message":"Name, password, email and roleId is required. " });
    }
    if (!isValidEmail(email)) {
      return res.status(401).send({ "status":"400","message":"Email ID is not valid" });
    }
    const path = `/user/${id}`;
    const pathUrl = `/user`;

    const users = await db.getData(pathUrl);
    let user = null
    // Loop through each user
    let isExist = true;
    for (const userId in users) {
      const user = users[userId];
      if (user.email === email) {
        isExist = false;
      }
    }
    if(isExist){
      // Create temporary secret until it it verified
      const temp_secret = speakeasy.generateSecret();
      // Create user in the database
      db.push(path, { id, temp_secret, name, password, email, roleId});
      // Send user id and base32 key to user
      res.json({ id, secret: temp_secret.base32 })
    }else{
      return res.status(401).send({ "status":"401","message":"Email id is already exist." });
    } 
    

  } catch(e) {
    console.log(e);
    res.status(500).json({ message: 'Error generating secret key'})
  }
})

app.post("/api/login", async (req, res) => {
  const id = uuid.v4();
  try {
    const { email, password } = req.body
    if(!email && !password){
      return res.status(400).send({ "status":"400","message":"Email ID and password are required." });
    }
    
    if (!isValidEmail(email)) {
      return res.status(401).send({ "status":"400","message":"Email ID is not valid" });
    }
    const path = `/user`;

    const users = await db.getData(path);
    let user = null
    // Loop through each user
    let checkLogin = true;
    for (const userId in users) {
      const user = users[userId];
      // Check if the email and password match
      if (user.email === email && user.password === password) {
        checkLogin = false;
        return res.json({ id: user.id, secret: user.temp_secret.base32 })
      }
    }

    if(checkLogin){
      return res.status(401).send({ "status":"401","message":"Invalid email id or password." });
    }

  } catch(e) {
    console.log(e);
    res.status(500).json({ message: 'Error generating secret key'})
  }
})

app.post("/api/verify", async (req,res) => {
  const { userId, token } = req.body;
  try {
    if(!userId && !token){
      return res.status(400).send({ "status":"400","message":"User ID and token are required." });
    }
    // Retrieve user from database
    const path = `/user/${userId}`;
    const user = await db.getData(path);
    const { base32: secret } = user.temp_secret;
    const verified = speakeasy.totp.verify({
      secret,
      encoding: 'base32',
      token
    });
    if (verified) {
      const jwtToken = jwt.sign(user, secretKey);
      return res.json({ verified: true, jwtToken })
    } else {
      return res.status(401).send({"status":"401","message":"Invalid user id or token.", verified: false});
    }
  } catch(error) {
    console.error(error);
    return res.status(500).json({ message: 'Error retrieving user'})
  };
})

// Protected route for CRUD operations on todos
app.use('/api/todos', verifyToken);


app.post('/api/todos', checkPermissions('create_todo'), (req, res) => {
  const { title } = req.body;
  if(!title || title === undefined){
    return res.status(400).send({ "status":"400","message":"Title is required." });
  }
  // Generate a unique ID (you may use a more robust ID generation method)
  const todoId = Date.now().toString();

  // Create the todo object
  const newTodo = { id: todoId, title, completed: false };

  // Save the todo to the database
  try {
    db.push(`/todos/${todoId}`, newTodo);
    res.status(201).json(newTodo);
  } catch (error) {
    res.status(500).json({ message: 'Error creating todo', error: error.message });
  }
});

// Get all todos
app.get('/api/todos', checkPermissions('list_todo'), async (req, res) => {
  try {
    const path = `/todos`;
    // Get all todos from the database
    const todos = await db.getData(path);
    res.json(todos);
  } catch (error) {
    res.status(500).json({ message: 'Error fetching todos', error: error.message });
  }
});

// Get a specific todo by ID
app.get('/api/todos/:id', checkPermissions('list_todo'),  async (req, res) => {
  const todoId = req.params.id;

  try {
    // Get the specific todo from the database
    const todo = await db.getData(`/todos/${todoId}`);
    res.json(todo);
  } catch (error) {
    res.status(404).json({ message: 'Todo not found', error: error.message });
  }
});

// Update a todo by ID
app.put('/api/todos/:id', checkPermissions('update_todo'),  (req, res) => {
  const todoId = req.params.id;
  const { title } = req.body;
  console.log(title);
  if(!title || title === undefined){
    return res.status(400).send({ "status":"400","message":"Title is required." });
  }
  try {
    // Update the todo in the database
    const newTodo = { id: todoId, title, completed: false };
    db.push(`/todos/${todoId}`, newTodo);
    res.json({ message: 'Todo updated successfully' });
  } catch (error) {
    res.status(500).json({ message: 'Error updating todo', error: error.message });
  }
});

// Delete a todo by ID
app.delete('/api/todos/:id', checkPermissions('delete_todo'),  (req, res) => {
  const todoId = req.params.id;

  try {
    // Delete the todo from the database
    db.delete(`/todos/${todoId}`);
    res.json({ message: 'Todo deleted successfully' });
  } catch (error) {
    res.status(500).json({ message: 'Error deleting todo', error: error.message });
  }
});

function isValidEmail(email) {
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return emailRegex.test(email);
}

const port = 9000;

app.listen(port, () => {
  console.log(`App is running on PORT: ${port}.`);
});