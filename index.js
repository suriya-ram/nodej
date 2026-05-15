import express from "express";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";

const app = express();
app.use(express.json());
const SECRET_KEY = "mySecretKey";

const authMiddleware = async(req,res,next)=>{
  const authHeader = req.headers.authorization;
  if(!authHeader)
  {
    return res.status(401).json({msg:'token is missing'})
  }
  const token = authHeader.split(" ")[1]
  const decoded = jwt.verify(token,SECRET_KEY);
  console.log("decoded is:",decoded)
  req.user = decoded
  next();
}
//app.use(authMiddleware);
const users = [];

app.get("/user", authMiddleware, (req, res) => {
  return res.json({
   sucess:true,
   user:req.user,
   msg:'protected user Info'
  });
});

app.post("/user", async (req, res) => {
  try {
    const { name, password, age } = req.body;
    if (!name || !password)
      throw Error("Name and password fields are mandatory");

    const hashedPassword = await bcrypt.hash(password, 10);
    users.push({ name, password: hashedPassword, age });
    console.log(users);
    return res.status(200).json({
      success: true,
      data: users,
    });
  } catch (err) {
    console.log(err.message);
    return res.status(500).json({
      msg: "Something went wrong",
      errorMsg: err.message,
    });
  }
});

app.post("/login", async (req, res) => {
  const { name, password } = req.body;
  const user = users.find((u) => u.name === name);
  console.log("found user", user);
  if (!user) {
    return res.status(400).json({ msg: "user not found" });
  }
  let isMatch = await bcrypt.compare(password, user.password);
  console.log("match result", isMatch);
  if (!isMatch) {
    return res.status(400).json({ msg: "Invalid password" });
  }
  const token = jwt.sign(
    {
      name: user.name,
    },
    SECRET_KEY,
    {
      expiresIn: "1hr",
    }
  );
  return res.status(200).json({ success: true, msg: "logged in", token });
});

const port = 3000;

app.listen(port, () => {
  console.log("server started on port 3000");
});
