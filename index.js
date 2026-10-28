const express = require("express");
const cors = require("cors");
require("dotenv").config();
const app = express();
const { MongoClient, ServerApiVersion, ObjectId } = require("mongodb");
const port = process.env.PORT || 3000;

//================== middleware =====================
app.use(express.json());
app.use(cors());

// =========== firebase admin sdk setup =============
const { initializeApp, cert } = require("firebase-admin/app");
const serviceAccount = require("./sokh-bilash-firebase-admin-sdk.json");
initializeApp({ credential: cert(serviceAccount) });

//=============  verifyFirebaseToken ================
const verifyFirebaseToken = async (req, res, next) => {
  const authorization = req.headers.authorization;

  if (!authorization?.startsWith("Bearer ")) {
    return res.status(401).send({
      success: false,
      message: "Unauthorized Access – Authentication required",
    });
  }

  const token = authorization.split(" ")[1];

  if (!token) {
    return res.status(401).send({
      success: false,
      message: "Unauthorized Access – Invalid token",
    });
  }

  try {
    const decodedToken = await getAuth().verifyIdToken(token);
    req.user = decodedToken;
    next();
  } catch (error) {
    console.error("Firebase Token Verification Failed:", error.message);

    return res.status(401).send({
      success: false,
      message: "Unauthorized Access – Invalid or expired token",
    });
  }
};

//================= mongodb setup ===================
const uri = `mongodb+srv://${process.env.DB_USER}:${process.env.DB_PASS}@cluster-sokh-bilash.a0v3zq0.mongodb.net/`;

// Create a MongoClient with a MongoClientOptions object to set the Stable API version
const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  },
});

async function run() {
  try {
    // Connect the client to the server	(optional starting in v4.7)
    await client.connect();

    // ++++++++++++++++++++++++++++++++++++++++++++++++
    const DB = client.db("sokhBilash");

    // Send a ping to confirm a successful connection
    await client.db("admin").command({ ping: 1 });
    console.log(
      "Pinged your deployment. You successfully connected to MongoDB!",
    );
  } finally {
    // Ensures that the client will close when you finish/error
    // await client.close();
  }
}
run().catch(console.dir);

app.get("/", (req, res) => {
  res.send("Successfully connected to SokhBilash");
});

app.listen(port, () => {
  console.log(`Example app listening on port ${port}`);
});
