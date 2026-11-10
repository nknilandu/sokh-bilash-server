const express = require("express");
const cors = require("cors");
require("dotenv").config();
const app = express();

// API routes are added only after MongoDB initialization.
const apiRouter = express.Router();
const { MongoClient, ServerApiVersion, ObjectId } = require("mongodb");
const port = process.env.PORT || 3000;

const {
  makeSearchLatin,
  buildProductSearchTerms,
  buildPublicSearchConditions,
  makeSearchRegex,
} = require("./utils/productSearch");

const registerCommerceRoutes = require("./routes/commerce.routes");

const registerProfileRoutes = require("./routes/profile.routes");

const registerWishlistRoutes = require("./routes/wishlist.routes");

//================== middleware =====================
app.use(express.json());
app.use(cors());

// =========== firebase admin sdk setup =============
const { getAuth } = require("firebase-admin/auth");
const { initializeApp, cert } = require("firebase-admin/app");

//================================
const decoded = Buffer.from(process.env.FB_SERVICE_KEY, "base64").toString(
  "utf8",
);
const serviceAccount = JSON.parse(decoded);

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
  // Register API routes on the dedicated router, not the outer app.
  const app = apiRouter;

  // await client.connect();

  const DB = client.db("sokhBilash");
  const users = DB.collection("users");
  const categories = DB.collection("categories");
  const occasions = DB.collection("occasions");
  const products = DB.collection("products");

  // ==========================================
  // ADMIN MIDDLEWARE
  // ==========================================

  const verifyAdmin = async (req, res, next) => {
    try {
      const admin = await users.findOne(
        {
          uid: req.user?.uid,
          role: "admin",
          status: "active",
        },
        {
          projection: { _id: 1 },
        },
      );

      if (!admin) {
        return res.status(403).send({
          success: false,
          message: "Only active admins can perform this action",
        });
      }

      next();
    } catch (error) {
      return respondError(res, error, "Verify Admin Error");
    }
  };

  // ==========================================
  // COMMON HELPERS
  // ==========================================

  registerProfileRoutes({
    app,
    users,
    verifyFirebaseToken,
    verifyAdmin,
  });

  await registerCommerceRoutes({
    app,
    DB,
    users,
    products,
    verifyFirebaseToken,
    verifyAdmin,
  });

  await registerWishlistRoutes({
    app,
    DB,
    users,
    products,
    verifyFirebaseToken,
  });

  const respondError = (res, error, label) => {
    console.error(`${label}:`, error);

    const status = error.status || (error.code === 11000 ? 409 : 500);

    return res.status(status).send({
      success: false,
      message: error.status
        ? error.message
        : error.code === 11000
          ? "Duplicate product information"
          : "Internal server error",
    });
  };

  const reject = (message, status = 400) => {
    const error = new Error(message);
    error.status = status;
    throw error;
  };

  const isValidUrl = (value) => {
    try {
      return (
        typeof value === "string" &&
        ["http:", "https:"].includes(new URL(value).protocol)
      );
    } catch {
      return false;
    }
  };

  const isMongoId = (value) => /^[a-f\d]{24}$/i.test(String(value || ""));

  const normalizeSku = (value) =>
    String(value || "")
      .trim()
      .toUpperCase();

  const parseCsv = (value) =>
    String(value ?? "")
      .split(",")
      .map((item) => item.trim())
      .filter((item) => /^[a-z0-9_-]{1,60}$/i.test(item))
      .slice(0, 30);

  const parseAmount = (value) => {
    if (value == null || value === "") return null;

    const number = Number(value);

    return Number.isFinite(number) && number >= 0 ? number : null;
  };

  const parsePage = (value) =>
    Math.min(10000, Math.max(1, Number.parseInt(value, 10) || 1));

  // ==========================================
  // MULTILINGUAL SEARCH HELPERS
  // ==========================================

  const getSearchFields = async (product) => {
    const [category, matchedOccasions] = await Promise.all([
      categories.findOne(
        { id: product.categoryId },
        { projection: { _id: 0, name: 1 } },
      ),

      occasions
        .find(
          {
            id: {
              $in: product.occasionIds || [],
            },
          },
          {
            projection: { _id: 0, name: 1 },
          },
        )
        .toArray(),
    ]);

    return {
      searchLatin: makeSearchLatin(
        `${product.name || ""} ${product.description || ""}`,
      ),

      searchTerms: buildProductSearchTerms(product, {
        categoryName: category?.name || "",

        occasionNames: matchedOccasions.map((item) => item.name),
      }),
    };
  };

  // Bangla + English + Banglish search.
  // AND between search words.
  // OR between aliases and matching fields.

  const getSearchConditions = async (search) => {
    const words = (
      String(search || "")
        .normalize("NFKC")
        .toLowerCase()
        .match(/[\p{L}\p{M}\p{N}]+/gu) || []
    ).slice(0, 8);

    if (!words.length) return [];

    const indexedConditions = buildPublicSearchConditions(search);

    const [categoryList, occasionList] = await Promise.all([
      categories
        .find(
          {},
          {
            projection: {
              _id: 0,
              id: 1,
              name: 1,
            },
          },
        )
        .toArray(),

      occasions
        .find(
          {},
          {
            projection: {
              _id: 0,
              id: 1,
              name: 1,
            },
          },
        )
        .toArray(),
    ]);

    return words.map((word, index) => {
      const regex = makeSearchRegex(word);

      const categoryIds = categoryList
        .filter((item) => regex.test(item.id) || regex.test(item.name))
        .map((item) => item.id);

      const occasionIds = occasionList
        .filter((item) => regex.test(item.id) || regex.test(item.name))
        .map((item) => item.id);

      const legacyFields = {
        $or: [
          { name: regex },
          { description: regex },
          { sku: regex },
          { slug: regex },
          { "variants.sku": regex },
          { "variants.title": regex },
          { searchKeywords: regex },
          { searchLatin: regex },
          { categoryId: regex },
          { occasionIds: regex },
          { categoryId: { $in: categoryIds } },
          { occasionIds: { $in: occasionIds } },
        ],
      };

      return {
        $or: [
          ...(indexedConditions[index] ? [indexedConditions[index]] : []),

          {
            $and: [{ searchTerms: { $exists: false } }, legacyFields],
          },
        ],
      };
    });
  };

  // ==========================================
  // DEFAULT CATEGORIES
  // ==========================================

  const DEFAULT_CATEGORIES = [
    [
      "photo-frames",
      "ফটো ফ্রেম ও স্মৃতির উপহার",
      "Photo+Frames",
      [
        "ফটো",
        "ছবি",
        "ফ্রেম",
        "ফটোফ্রেম",
        "photo",
        "photo frame",
        "foto",
        "fotoframe",
        "picture",
        "frame",
      ],
    ],
    [
      "magic-mirror-led",
      "ম্যাজিক মিরর ও LED গিফট",
      "Magic+Mirror",
      [
        "ম্যাজিক",
        "মিরর",
        "আয়না",
        "এলইডি",
        "magic mirror",
        "mirror",
        "led",
        "ayna",
        "magic",
        "light",
      ],
    ],
    [
      "personalized",
      "কাস্টমাইজড ও পার্সোনালাইজড গিফট",
      "Personalized+Gifts",
      [
        "কাস্টম",
        "কাস্টমাইজড",
        "পার্সোনালাইজড",
        "custom",
        "customized",
        "customizable",
        "personalized",
        "personalised",
      ],
    ],
    [
      "gift-combos",
      "গিফট কম্বো ও হ্যাম্পার",
      "Gift+Combos",
      [
        "গিফট",
        "কম্বো",
        "হ্যাম্পার",
        "গিফট বক্স",
        "gift",
        "combo",
        "hamper",
        "gift box",
        "gift set",
      ],
    ],
    [
      "flowers",
      "ফুল ও বুকেট",
      "Flowers",
      [
        "ফুল",
        "বুকেট",
        "ফুলের তোড়া",
        "গোলাপ",
        "flower",
        "flowers",
        "bouquet",
        "ful",
        "phul",
        "golap",
        "rose",
      ],
    ],
    [
      "chocolates",
      "চকলেট ও মিষ্টির উপহার",
      "Chocolates",
      [
        "চকলেট",
        "মিষ্টি",
        "চকলেট বক্স",
        "chocolate",
        "chocolates",
        "choklet",
        "sweet",
        "candy",
      ],
    ],
    [
      "clothing",
      "পোশাক ও কাপল সেট",
      "Clothing",
      [
        "পোশাক",
        "শাড়ি",
        "পাঞ্জাবি",
        "শার্ট",
        "কাপল",
        "clothing",
        "dress",
        "saree",
        "panjabi",
        "shirt",
        "couple",
        "kapor",
      ],
    ],
    [
      "party-decorations",
      "পার্টি ও অনুষ্ঠানের সাজসজ্জা",
      "Party+Decorations",
      [
        "পার্টি",
        "সাজসজ্জা",
        "ডেকোরেশন",
        "party",
        "decoration",
        "decor",
        "birthday decoration",
        "balloon",
      ],
    ],
    [
      "islamic",
      "ইসলামিক ও নিকাহ উপহার",
      "Islamic+Gifts",
      [
        "ইসলামিক",
        "ইসলামী",
        "নিকাহ",
        "নিকাহনামা",
        "islamic",
        "islami",
        "nikah",
        "nikahnama",
        "muslim",
      ],
    ],
    [
      "romantic-gifts",
      "টেডি বেয়ার ও রোমান্টিক গিফট",
      "Romantic+Gifts",
      [
        "টেডি",
        "ভালোবাসা",
        "প্রেম",
        "রোমান্টিক",
        "teddy",
        "bear",
        "romantic",
        "love",
        "couple",
        "valobasha",
      ],
    ],
    [
      "others",
      "অন্যান্য (Others)",
      "Other+Gifts",
      [
        "অন্যান্য",
        "উপহার",
        "বিবিধ",
        "others",
        "other",
        "misc",
        "gift",
        "upohar",
      ],
    ],
  ];

  // ==========================================
  // DEFAULT OCCASIONS
  // ==========================================

  const DEFAULT_OCCASIONS = [
    [
      "birthday",
      "জন্মদিন",
      "Birthday",
      ["জন্মদিন", "birthday", "birth day", "jonmodin", "jonmo din", "bday"],
    ],
    [
      "anniversary",
      "বিবাহবার্ষিকী",
      "Anniversary",
      [
        "বিবাহবার্ষিকী",
        "বার্ষিকী",
        "anniversary",
        "wedding anniversary",
        "bibaho barsiki",
        "barsiki",
      ],
    ],
    [
      "wedding-nikah",
      "বিয়ে ও নিকাহ",
      "Wedding+Nikah",
      [
        "বিয়ে",
        "বিবাহ",
        "নিকাহ",
        "wedding",
        "marriage",
        "nikah",
        "biye",
        "biya",
        "nikahnama",
      ],
    ],
    [
      "love-romance",
      "ভালোবাসা ও রোমান্স",
      "Love+Romance",
      [
        "ভালোবাসা",
        "প্রেম",
        "রোমান্স",
        "love",
        "romance",
        "romantic",
        "valobasha",
        "bhalobasha",
        "prem",
      ],
    ],
    [
      "islamic",
      "ইসলামিক উপলক্ষ",
      "Islamic+Occasions",
      [
        "ইসলামিক",
        "ইসলামী",
        "রমজান",
        "ঈদ",
        "islamic",
        "islami",
        "ramadan",
        "eid",
        "nikah",
      ],
    ],
    [
      "parents-day",
      "বাবা-মা দিবস",
      "Parents+Day",
      [
        "বাবা",
        "মা",
        "মায়ের দিন",
        "বাবার দিন",
        "mother",
        "father",
        "parents",
        "mother day",
        "father day",
        "ma",
        "baba",
      ],
    ],
    [
      "congratulations",
      "অভিনন্দন ও অর্জন",
      "Congratulations",
      [
        "অভিনন্দন",
        "অর্জন",
        "সফলতা",
        "congratulations",
        "congrats",
        "achievement",
        "success",
        "graduation",
        "obhinondon",
      ],
    ],
    [
      "surprise",
      "সারপ্রাইজ ও বিশেষ মুহূর্ত",
      "Surprise",
      [
        "সারপ্রাইজ",
        "চমক",
        "বিশেষ",
        "surprise",
        "surprize",
        "special",
        "special moment",
      ],
    ],
  ];

  // ==========================================
  // SEED TAXONOMY FUNCTION
  // ==========================================

  const seedTaxonomy = async (collection, entries) => {
    if (!entries.length) return;

    const operations = entries.flatMap(
      ([id, name, imageText, searchKeywords], index) => {
        const imageUrl = `https://placehold.co/800x600/F8F5FA/310039/png?text=${imageText}`;

        return [
          // Insert a new document if missing.
          {
            updateOne: {
              filter: { id },
              update: {
                $setOnInsert: {
                  id,
                  name,
                  imageUrl,
                  iconUrl: "",
                  searchKeywords,
                  sortOrder: index + 1,
                },
              },
              upsert: true,
            },
          },

          // Fill missing images only.
          {
            updateOne: {
              filter: {
                id,
                $or: [
                  { imageUrl: { $exists: false } },
                  { imageUrl: null },
                  { imageUrl: "" },
                ],
              },
              update: {
                $set: { imageUrl },
              },
            },
          },

          // Fill missing keywords only.
          {
            updateOne: {
              filter: {
                id,
                $or: [
                  { searchKeywords: { $exists: false } },
                  { searchKeywords: null },
                ],
              },
              update: {
                $set: { searchKeywords },
              },
            },
          },
        ];
      },
    );

    await collection.bulkWrite(operations);

    // Existing documents without iconUrl.
    await collection.updateMany(
      { iconUrl: { $exists: false } },
      { $set: { iconUrl: "" } },
    );

    // Other manually added documents.
    await collection.updateMany(
      { searchKeywords: { $exists: false } },
      { $set: { searchKeywords: [] } },
    );
  };

  // ==========================================
  // INITIALIZE CATEGORIES AND OCCASIONS
  // ==========================================

  await Promise.all([
    seedTaxonomy(categories, DEFAULT_CATEGORIES),
    seedTaxonomy(occasions, DEFAULT_OCCASIONS),
  ]);

  console.log("Category and Occasion taxonomy ready");

  // ==========================================
  // MONGODB PRODUCT INDEXES
  // ==========================================

  await Promise.all([
    products.createIndex(
      {
        status: 1,
        searchTerms: 1,
      },
      {
        name: "idx_public_product_search",
      },
    ),

    products.createIndex({
      status: 1,
      createdAt: -1,
    }),

    products.createIndex({
      status: 1,
      categoryId: 1,
      createdAt: -1,
    }),

    products.createIndex({
      status: 1,
      occasionIds: 1,
    }),
  ]);

  // ==========================================
  // OLD PRODUCTS SEARCH MIGRATION
  // ==========================================

  const [categoryData, occasionData] = await Promise.all([
    categories
      .find(
        {},
        {
          projection: {
            _id: 0,
            id: 1,
            name: 1,
          },
        },
      )
      .toArray(),

    occasions
      .find(
        {},
        {
          projection: {
            _id: 0,
            id: 1,
            name: 1,
          },
        },
      )
      .toArray(),
  ]);

  const categoryNames = new Map(
    categoryData.map((item) => [item.id, item.name]),
  );

  const occasionNames = new Map(
    occasionData.map((item) => [item.id, item.name]),
  );

  const migrationCursor = products.find({
    searchTerms: { $exists: false },
  });

  let operations = [];
  let migratedCount = 0;

  const flushMigration = async () => {
    if (!operations.length) return;

    const result = await products.bulkWrite(operations, {
      ordered: false,
    });

    migratedCount += result.modifiedCount;
    operations = [];
  };

  for await (const product of migrationCursor) {
    const names = (product.occasionIds || [])
      .map((id) => occasionNames.get(id))
      .filter(Boolean);

    operations.push({
      updateOne: {
        filter: {
          _id: product._id,
          searchTerms: { $exists: false },
        },

        update: {
          $set: {
            searchLatin: makeSearchLatin(
              `${product.name || ""} ${product.description || ""}`,
            ),

            searchTerms: buildProductSearchTerms(product, {
              categoryName: categoryNames.get(product.categoryId) || "",

              occasionNames: names,
            }),
          },
        },
      },
    });

    if (operations.length >= 100) {
      await flushMigration();
    }
  }

  await flushMigration();

  console.log(
    `Product search ready; migrated ${migratedCount} legacy products`,
  );

  // ==========================================
  // PUBLIC CATEGORIES API
  // GET /categories
  // GET /categories?search=photo
  // ==========================================

  app.get("/categories", async (req, res) => {
    try {
      const search = String(req.query.search || "")
        .trim()
        .slice(0, 100);

      const query = {};

      if (search) {
        const regex = makeSearchRegex(search);

        query.$or = [{ id: regex }, { name: regex }, { searchKeywords: regex }];
      }

      const categoryList = await categories
        .find(query, {
          projection: {
            _id: 0,
            id: 1,
            name: 1,
            imageUrl: 1,
            iconUrl: 1,
            searchKeywords: 1,
            sortOrder: 1,
          },
        })
        .sort({ sortOrder: 1, id: 1 })
        .toArray();

      res.set("Cache-Control", "no-store");

      return res.status(200).send({
        success: true,
        categories: categoryList,
      });
    } catch (error) {
      return respondError(res, error, "Get Categories Error");
    }
  });

  // ==========================================
  // PUBLIC OCCASIONS API
  // GET /occasions
  // GET /occasions?search=jonmodin
  // ==========================================

  app.get("/occasions", async (req, res) => {
    try {
      const search = String(req.query.search || "")
        .trim()
        .slice(0, 100);

      const query = {};

      if (search) {
        const regex = makeSearchRegex(search);

        query.$or = [{ id: regex }, { name: regex }, { searchKeywords: regex }];
      }

      const occasionList = await occasions
        .find(query, {
          projection: {
            _id: 0,
            id: 1,
            name: 1,
            imageUrl: 1,
            iconUrl: 1,
            searchKeywords: 1,
            sortOrder: 1,
          },
        })
        .sort({ sortOrder: 1, id: 1 })
        .toArray();

      res.set("Cache-Control", "no-store");

      return res.status(200).send({
        success: true,
        occasions: occasionList,
      });
    } catch (error) {
      return respondError(res, error, "Get Occasions Error");
    }
  });

  // ==========================================
  // CREATE CUSTOMER
  // PUT /users
  // ==========================================

  app.put("/users", verifyFirebaseToken, async (req, res) => {
    try {
      const { displayName, phone, photoUrl = "" } = req.body || {};

      const { uid, email } = req.user;

      if (
        !uid ||
        !email ||
        typeof displayName !== "string" ||
        !displayName.trim() ||
        typeof phone !== "string" ||
        !/^01[3-9]\d{8}$/.test(phone.trim()) ||
        typeof photoUrl !== "string"
      ) {
        return res.status(400).send({
          success: false,
          message: "Valid name, email and phone are required",
        });
      }

      const existing = await users.findOne({
        $or: [{ uid }, { email }],
      });

      if (existing) {
        if (existing.uid !== uid) {
          return res.status(409).send({
            success: false,
            message: "Email already belongs to another account",
          });
        }

        return res.send({
          success: true,
          message: "User already exists",
          insertedId: existing._id,
          existing: true,
        });
      }

      const now = new Date();

      const result = await users.insertOne({
        uid,
        email,
        displayName: displayName.trim(),
        phone: phone.trim(),
        photoUrl: photoUrl.trim() || null,
        role: "customer",
        status: "active",
        createdAt: now,
        updatedAt: now,
      });

      return res.status(201).send({
        success: true,
        message: "User registered successfully",
        insertedId: result.insertedId,
        existing: false,
      });
    } catch (error) {
      return respondError(res, error, "User Registration Error");
    }
  });

  // ==========================================
  // GET USER ROLE
  // ==========================================

  app.get("/users/role", verifyFirebaseToken, async (req, res) => {
    try {
      const user = await users.findOne(
        { uid: req.user.uid },
        {
          projection: {
            _id: 0,
            role: 1,
            status: 1,
          },
        },
      );

      if (!user) {
        return res.status(404).send({
          success: false,
          message: "User not found",
        });
      }

      return res.send({
        success: true,
        role: user.role,
        status: user.status,
      });
    } catch (error) {
      return respondError(res, error, "Get User Role Error");
    }
  });

  // ======================================================
  // PRODUCT ADD / EDIT API
  //
  // Existing dependencies in this scope:
  // app
  // products
  // categories
  // occasions
  // ObjectId
  // verifyFirebaseToken
  // verifyAdmin
  // getSearchFields
  // ======================================================

  const PRODUCT_OPTION_TYPES = ["size", "color", "type"];

  const PRODUCT_MAX_VARIANTS = 100;
  const PRODUCT_MAX_IMAGES = 5;

  // ======================================================
  // HELPERS
  // ======================================================

  const productFail = (message, status = 400) => {
    const error = new Error(message);
    error.status = status;
    throw error;
  };

  const productIsRecord = (value) =>
    value !== null && typeof value === "object" && !Array.isArray(value);

  const productHasOwn = (object, key) =>
    Object.prototype.hasOwnProperty.call(object, key);

  const productText = (value, field, maxLength, { required = false } = {}) => {
    if (value === undefined || value === null) {
      if (required) {
        productFail(`${field} is required`);
      }

      return "";
    }

    if (typeof value !== "string") {
      productFail(`${field} must be a string`);
    }

    const result = value.trim();

    if (required && !result) {
      productFail(`${field} is required`);
    }

    if (result.length > maxLength) {
      productFail(`${field} exceeds ${maxLength} characters`);
    }

    return result;
  };

  const productNormalizeLabel = (value) =>
    String(value ?? "")
      .normalize("NFKC")
      .replace(/\p{Cf}/gu, "")
      .trim()
      .replace(/\s+/gu, " ")
      .toLowerCase();

  const productIsReservedDefault = (value) =>
    ["default", "ডিফল্ট", "ডিফল্ট্"].includes(productNormalizeLabel(value));

  const productNormalizeSku = (value, field = "SKU") =>
    productText(value, field, 150, {
      required: true,
    }).toUpperCase();

  const productValidUrl = (value) => {
    try {
      const url = new URL(value);

      return (
        ["http:", "https:"].includes(url.protocol) &&
        Boolean(url.hostname) &&
        !url.username &&
        !url.password
      );
    } catch {
      return false;
    }
  };

  const productValidId = (value) =>
    typeof value === "string" && /^[a-f0-9]{24}$/i.test(value);

  const productNumber = (value, field, { allowZero = false } = {}) => {
    if (
      (typeof value !== "string" && typeof value !== "number") ||
      (typeof value === "string" && !value.trim())
    ) {
      productFail(`${field} must be a valid number`);
    }

    const result = Number(value);

    if (!Number.isFinite(result) || (allowZero ? result < 0 : result <= 0)) {
      productFail(
        allowZero
          ? `${field} must be zero or greater`
          : `${field} must be greater than zero`,
      );
    }

    return result;
  };

  const productBoolean = (value, field, fallback = false) => {
    if (value === undefined) return fallback;

    if (typeof value !== "boolean") {
      productFail(`${field} must be a boolean`);
    }

    return value;
  };

  const productBasePrice = (product) => {
    const regular = Number(product.regularPrice);
    const sale = Number(product.salePrice);

    return Number.isFinite(sale) && sale > 0 && sale < regular ? sale : regular;
  };

  const productVariantSignature = (options) =>
    JSON.stringify(
      PRODUCT_OPTION_TYPES.map((type) => [
        type,
        productNormalizeLabel(options?.[type]),
      ]),
    );

  const productApiError = (res, error, label) => {
    console.error(label, error);

    const status =
      Number.isInteger(error.status) &&
      error.status >= 400 &&
      error.status <= 599
        ? error.status
        : error.code === 11000
          ? 409
          : 500;

    return res.status(status).json({
      success: false,
      message:
        status === 500
          ? "Internal server error"
          : error.code === 11000
            ? "Duplicate product information"
            : error.message,
    });
  };

  // ======================================================
  // REBUILD COMPLETE OVERRIDES FROM SAVED VARIANTS
  //
  // Actual variant data is authoritative.
  // Metadata can retain intentional base-price inheritance.
  // ======================================================

  function productBuildOverrides(variants, previousOverrides = {}, basePrice) {
    const source = productIsRecord(previousOverrides) ? previousOverrides : {};

    return Object.fromEntries(
      variants.map((variant) => {
        const metadata = productIsRecord(source[variant.key])
          ? source[variant.key]
          : {};

        // Only keep the blank-price marker when the actual
        // saved price agrees with the product's base price.
        const inheritsBasePrice =
          metadata.price === "" &&
          Number.isFinite(Number(variant.price)) &&
          Number(variant.price) === basePrice;

        return [
          variant.key,
          {
            sku: variant.sku,
            autoSku:
              typeof variant.autoSku === "boolean"
                ? variant.autoSku
                : metadata.autoSku === true,
            price: inheritsBasePrice ? "" : variant.price,
            imageUrl: variant.imageUrl || "",
            available: variant.available !== false,
          },
        ];
      }),
    );
  }

  // ======================================================
  // SHARED PRODUCT VALIDATION
  // Used by POST and PATCH.
  // ======================================================

  const buildValidatedProduct = async (data, existing = null) => {
    if (!productIsRecord(data)) {
      productFail("Invalid product information");
    }

    // ----------------------------------------------------
    // BASIC DETAILS
    // ----------------------------------------------------

    const name = productText(data.name, "Product name", 300, {
      required: true,
    });

    const sku = productNormalizeSku(data.sku, "Product SKU");

    const description = productText(data.description, "Description", 30000);

    const autoSku = productBoolean(data.autoSku, "autoSku", false);

    const regularPrice = productNumber(data.regularPrice, "Regular price");

    const salePrice =
      data.salePrice === undefined ||
      data.salePrice === null ||
      data.salePrice === ""
        ? null
        : productNumber(data.salePrice, "Sale price");

    if (salePrice !== null && salePrice >= regularPrice) {
      productFail("Sale price must be lower than regular price");
    }

    const basePrice = salePrice !== null ? salePrice : regularPrice;

    const available = productBoolean(data.available, "available", false);

    const featured = productBoolean(data.featured, "featured", false);

    const customizable = productBoolean(
      data.customizable,
      "customizable",
      false,
    );

    const variantsEnabled = productBoolean(
      data.variantsEnabled,
      "variantsEnabled",
      false,
    );

    // ----------------------------------------------------
    // CATEGORY / OCCASIONS
    // ----------------------------------------------------

    const categoryId = productText(data.categoryId, "Category", 100, {
      required: true,
    });

    if (
      !Array.isArray(data.occasionIds) ||
      data.occasionIds.length === 0 ||
      data.occasionIds.length > 100
    ) {
      productFail("Select at least one valid occasion");
    }

    const occasionIds = data.occasionIds.map((value) =>
      productText(value, "Occasion ID", 100, {
        required: true,
      }),
    );

    if (new Set(occasionIds).size !== occasionIds.length) {
      productFail("Duplicate occasions are not allowed");
    }

    const [category, occasionCount] = await Promise.all([
      categories.findOne({ id: categoryId }, { projection: { _id: 1 } }),
      occasions.countDocuments({
        id: { $in: occasionIds },
      }),
    ]);

    if (!category) {
      productFail("Invalid category selected");
    }

    if (occasionCount !== occasionIds.length) {
      productFail("Invalid occasion selected");
    }

    // ----------------------------------------------------
    // PRODUCT PHOTOS
    // At least one photo is required for Default.
    // ----------------------------------------------------

    if (
      !Array.isArray(data.images) ||
      data.images.length === 0 ||
      data.images.length > PRODUCT_MAX_IMAGES
    ) {
      productFail("Provide 1 to 5 valid product images");
    }

    const images = data.images.map((image, index) => {
      if (typeof image !== "string" && !productIsRecord(image)) {
        productFail("Invalid product image");
      }

      const url = productText(
        typeof image === "string" ? image : image.url,
        "Product image URL",
        4096,
        { required: true },
      );

      if (!productValidUrl(url)) {
        productFail("Invalid product image URL");
      }

      const id =
        typeof image === "string" || !image.id
          ? `product-image-${index + 1}`
          : productText(image.id, "Image ID", 150, {
              required: true,
            });

      return { id, url };
    });

    if (new Set(images.map((image) => image.url)).size !== images.length) {
      productFail("Duplicate product image URLs are not allowed");
    }

    if (new Set(images.map((image) => image.id)).size !== images.length) {
      productFail("Duplicate product image IDs are not allowed");
    }

    // ----------------------------------------------------
    // OPTION GROUPS
    // Default is reserved, including disabled groups.
    // ----------------------------------------------------

    const sourceOptions = data.options ?? {};

    if (!productIsRecord(sourceOptions)) {
      productFail("Invalid variant options");
    }

    const options = {};

    for (const type of PRODUCT_OPTION_TYPES) {
      const group = sourceOptions[type] ?? {};

      if (!productIsRecord(group)) {
        productFail(`Invalid ${type} option group`);
      }

      const enabled = productBoolean(group.enabled, `${type}.enabled`, false);

      const rawValues = group.values ?? [];

      if (!Array.isArray(rawValues) || rawValues.length > 100) {
        productFail(`${type}: maximum 100 options are allowed`);
      }

      const values = rawValues.map((value) => {
        if (!productIsRecord(value)) {
          productFail(`${type}: option must contain id and label`);
        }

        const id = productText(value.id, `${type} option ID`, 100, {
          required: true,
        });

        const label = productText(value.label, `${type} option label`, 150, {
          required: true,
        });

        if (!/^[a-zA-Z0-9_-]+$/.test(id)) {
          productFail(`${type}: invalid option ID`);
        }

        if (productIsReservedDefault(label)) {
          productFail(
            `${type}: Default is automatic and cannot be added manually`,
          );
        }

        return { id, label };
      });

      if (new Set(values.map((value) => value.id)).size !== values.length) {
        productFail(`${type}: duplicate option IDs`);
      }

      const normalizedLabels = values.map((value) =>
        productNormalizeLabel(value.label),
      );

      if (new Set(normalizedLabels).size !== normalizedLabels.length) {
        productFail(`${type}: duplicate option labels`);
      }

      options[type] = {
        enabled,
        values,
      };
    }

    const activeTypes = PRODUCT_OPTION_TYPES.filter(
      (type) => options[type].enabled && options[type].values.length > 0,
    );

    // ----------------------------------------------------
    // VARIANTS
    // ----------------------------------------------------

    if (data.variants !== undefined && !Array.isArray(data.variants)) {
      productFail("Variants must be an array");
    }

    const suppliedVariants = data.variants ?? [];

    // Check reserved names even if variantsEnabled is false.
    for (const variant of suppliedVariants) {
      if (!productIsRecord(variant)) {
        productFail("Invalid variant");
      }

      if (
        productIsReservedDefault(variant.title) ||
        PRODUCT_OPTION_TYPES.some((type) =>
          productIsReservedDefault(variant.options?.[type]),
        )
      ) {
        productFail("Default is automatic; do not create a Default variant");
      }
    }

    const rawVariants = variantsEnabled ? suppliedVariants : [];

    if (
      rawVariants.length > PRODUCT_MAX_VARIANTS ||
      (variantsEnabled && rawVariants.length === 0)
    ) {
      productFail("Provide 1 to 100 variants when variants are enabled");
    }

    if (variantsEnabled && activeTypes.length === 0) {
      productFail("Enable at least one Size, Color or Type option group");
    }

    const variants = rawVariants.map((rawVariant) => {
      const key = productText(rawVariant.key, "Variant key", 200, {
        required: true,
      });

      if (!/^[a-zA-Z0-9_:|-]+$/.test(key)) {
        productFail("Invalid variant key");
      }

      if (!productIsRecord(rawVariant.options)) {
        productFail("Invalid variant options");
      }

      const variantOptions = {};

      for (const type of PRODUCT_OPTION_TYPES) {
        const label = productText(
          rawVariant.options[type],
          `Variant ${type}`,
          150,
        );

        if (productIsReservedDefault(label)) {
          productFail("Default cannot be used as a saved variant option");
        }

        if (activeTypes.includes(type)) {
          if (!label) {
            productFail(`Variant ${key}: ${type} is required`);
          }

          const matchingOption = options[type].values.find(
            (option) =>
              productNormalizeLabel(option.label) ===
              productNormalizeLabel(label),
          );

          if (!matchingOption) {
            productFail(
              `Variant ${key}: ${type} does not match the configured options`,
            );
          }

          // Store the canonical label from the option group.
          variantOptions[type] = matchingOption.label;
        } else {
          if (label) {
            productFail(
              `Variant ${key}: ${type} is not an active option group`,
            );
          }

          variantOptions[type] = "";
        }
      }

      const title = activeTypes.map((type) => variantOptions[type]).join(" / ");

      const variantSku = productNormalizeSku(
        rawVariant.sku,
        `Variant ${title} SKU`,
      );

      const price = productNumber(rawVariant.price, `Variant ${title} price`);

      const imageUrl = productText(
        rawVariant.imageUrl,
        `Variant ${title} image URL`,
        4096,
      );

      if (imageUrl && !productValidUrl(imageUrl)) {
        productFail(`Variant ${title}: invalid image URL`);
      }

      return {
        // Preserve the submitted existing key.
        // Do not regenerate keys or SKUs on the server.
        key,
        title,
        options: variantOptions,
        sku: variantSku,
        autoSku: productBoolean(
          rawVariant.autoSku,
          `Variant ${title} autoSku`,
          false,
        ),
        price,
        imageUrl,
        available: productBoolean(
          rawVariant.available,
          `Variant ${title} available`,
          true,
        ),
      };
    });

    const variantKeys = variants.map((variant) => variant.key);

    if (new Set(variantKeys).size !== variantKeys.length) {
      productFail("Duplicate variant keys are not allowed");
    }

    const signatures = variants.map((variant) =>
      productVariantSignature(variant.options),
    );

    if (new Set(signatures).size !== signatures.length) {
      productFail("Duplicate variant combinations are not allowed");
    }

    // ----------------------------------------------------
    // COMPLETE VARIANT OVERRIDES
    // ----------------------------------------------------

    const rawOverrides = data.variantOverrides ?? {};

    if (!productIsRecord(rawOverrides)) {
      productFail("Invalid variant overrides");
    }

    const variantOverrides = productBuildOverrides(
      variants,
      rawOverrides,
      basePrice,
    );

    // ----------------------------------------------------
    // SKU UNIQUENESS
    // ----------------------------------------------------

    const allSkus = [sku, ...variants.map((variant) => variant.sku)];

    if (new Set(allSkus).size !== allSkus.length) {
      productFail("Product and variant SKUs must be unique", 409);
    }

    const duplicate = await products.findOne(
      {
        ...(existing ? { _id: { $ne: existing._id } } : {}),
        $or: [{ sku: { $in: allSkus } }, { "variants.sku": { $in: allSkus } }],
      },
      {
        projection: { _id: 1 },
      },
    );

    if (duplicate) {
      productFail("Product or variant SKU already exists", 409);
    }

    // ----------------------------------------------------
    // PACKAGING
    // ----------------------------------------------------

    const packaging = data.packaging ?? "regular";

    if (!["regular", "premium"].includes(packaging)) {
      productFail("Invalid packaging");
    }

    const premiumBoxPrice = productNumber(
      data.premiumBoxPrice ?? 0,
      "Premium box price",
      { allowZero: true },
    );

    // ----------------------------------------------------
    // CUSTOMER CUSTOMIZATION
    // ----------------------------------------------------

    const requestedFieldType = data.customerFieldType ?? "none";

    if (!["none", "frame", "note"].includes(requestedFieldType)) {
      productFail("Invalid customer field type");
    }

    const customerFieldType = customizable ? requestedFieldType : "none";

    const customerFields =
      !customizable || customerFieldType === "none"
        ? []
        : customerFieldType === "frame"
          ? [
              {
                key: "photos",
                label: "আপনার ছবি আপলোড করুন",
                type: "file",
                maxFiles: 20,
              },
              {
                key: "name",
                label: "নাম",
                type: "text",
              },
              {
                key: "dob",
                label: "জন্মতারিখ / বিবাহবার্ষিকী",
                type: "date",
              },
              {
                key: "engraving",
                label: "ফ্রেমের নিচের খোদাই বার্তা / উইশ",
                type: "textarea",
              },
            ]
          : [
              {
                key: "customNote",
                label: "বিশেষ নির্দেশনা",
                type: "textarea",
              },
            ];

    // ----------------------------------------------------
    // VALIDATED DOCUMENT
    // ----------------------------------------------------

    return {
      name,
      sku,
      autoSku,
      description,
      regularPrice,
      salePrice,
      categoryId,
      occasionIds,
      images,
      available,
      featured,
      customizable,
      variantsEnabled,
      options,
      variants,
      variantOverrides,
      customerFieldType,
      customerFields,
      packaging,
      premiumBoxPrice,
    };
  };

  // ======================================================
  // ADMIN ADD PRODUCT
  // POST /admin/products
  // ======================================================

  app.post(
    "/admin/products",
    verifyFirebaseToken,
    verifyAdmin,
    async (req, res) => {
      try {
        const document = await buildValidatedProduct(req.body);

        const _id = new ObjectId();

        const nameSlug = document.name
          .normalize("NFC")
          .toLowerCase()
          .replace(/[^\p{L}\p{M}\p{N}]+/gu, "-")
          .replace(/^-+|-+$/g, "")
          .slice(0, 90);

        const slug = `${nameSlug || "product"}-${_id.toHexString().slice(-8)}`;

        const now = new Date();

        const product = {
          _id,
          ...document,
          slug,
          status: "published",
          createdBy: req.user.uid,
          createdAt: now,
          updatedAt: now,
        };

        Object.assign(product, await getSearchFields(product));

        await products.insertOne(product);

        res.set("Cache-Control", "no-store");

        return res.status(201).json({
          success: true,
          message: "Product added successfully",
          insertedId: _id.toString(),
          slug,
        });
      } catch (error) {
        return productApiError(res, error, "Add Product Error:");
      }
    },
  );

  // ======================================================
  // ADMIN GET SINGLE PRODUCT
  // GET /admin/products/:productId
  // ======================================================

  app.get(
    "/admin/products/:productId",
    verifyFirebaseToken,
    verifyAdmin,
    async (req, res) => {
      try {
        const { productId } = req.params;

        if (!productValidId(productId)) {
          productFail("Invalid product ID");
        }

        const product = await products.findOne({
          _id: new ObjectId(productId),
          status: { $ne: "deleted" },
        });

        if (!product) {
          productFail("Product not found", 404);
        }

        const variants = Array.isArray(product.variants)
          ? product.variants
          : [];

        // Response repair only.
        // GET does not write anything to the database.
        const variantOverrides = productBuildOverrides(
          variants,
          product.variantOverrides,
          productBasePrice(product),
        );

        res.set("Cache-Control", "no-store");

        return res.json({
          success: true,
          message: "Product fetched successfully",
          product: {
            ...product,
            _id: product._id.toString(),
            variants,
            variantOverrides,
          },
        });
      } catch (error) {
        return productApiError(res, error, "Get Admin Product Error:");
      }
    },
  );

  // ======================================================
  // ADMIN UPDATE PRODUCT
  // PATCH /admin/products/:productId
  // ======================================================

  app.patch(
    "/admin/products/:productId",
    verifyFirebaseToken,
    verifyAdmin,
    async (req, res) => {
      try {
        const { productId } = req.params;

        if (!productValidId(productId)) {
          productFail("Invalid product ID");
        }

        if (!productIsRecord(req.body)) {
          productFail("Invalid request body");
        }

        const _id = new ObjectId(productId);

        const existing = await products.findOne({
          _id,
          status: { $ne: "deleted" },
        });

        if (!existing) {
          productFail("Product not found", 404);
        }

        const changes = Object.fromEntries(
          Object.entries(req.body).filter(([field]) =>
            PATCHABLE_FIELDS.has(field),
          ),
        );

        if (!Object.keys(changes).length) {
          productFail("No valid fields to update");
        }

        const merged = {
          ...existing,
          ...changes,
        };

        // For structural variant edits, require the final
        // variant array so stale data is not combined silently.
        const changingVariantStructure =
          productHasOwn(changes, "options") ||
          productHasOwn(changes, "variantOverrides") ||
          (productHasOwn(changes, "variantsEnabled") &&
            changes.variantsEnabled !== existing.variantsEnabled);

        if (
          merged.variantsEnabled === true &&
          changingVariantStructure &&
          !productHasOwn(changes, "variants")
        ) {
          productFail(
            "Send the complete variants array when changing variant options or overrides",
          );
        }

        const document = await buildValidatedProduct(merged, existing);

        const now = new Date();

        const updatedProduct = {
          ...document,
          updatedBy: req.user.uid,
          updatedAt: now,
        };

        // Keep the existing slug and unrelated product fields.
        // Prevent the removed Surprise Box field contributing
        // to regenerated search data.
        const searchProduct = {
          ...existing,
          ...updatedProduct,
        };

        delete searchProduct.surpriseBox;

        Object.assign(updatedProduct, await getSearchFields(searchProduct));

        // Detect another update occurring after this read.
        const updateFilter = {
          _id,
          status: { $ne: "deleted" },
          updatedAt: productHasOwn(existing, "updatedAt")
            ? existing.updatedAt
            : { $exists: false },
        };

        const result = await products.updateOne(updateFilter, {
          $set: updatedProduct,
          $unset: {
            surpriseBox: "",
          },
        });

        if (!result.matchedCount) {
          productFail(
            "Product changed during this update. Reload and try again.",
            409,
          );
        }

        res.set("Cache-Control", "no-store");

        return res.json({
          success: true,
          message: "Product updated successfully",
          updatedId: productId,
          variantCount: document.variants.length,
          updatedAt: now,
        });
      } catch (error) {
        return productApiError(res, error, "Update Product Error:");
      }
    },
  );

  // ==========================================
  // ADMIN PRODUCT LIST
  // GET /admin/products
  // ==========================================

  app.get(
    "/admin/products",
    verifyFirebaseToken,
    verifyAdmin,
    async (req, res) => {
      try {
        const search = String(req.query.search || "")
          .trim()
          .slice(0, 100);

        const status = String(req.query.status || "all");

        const category = String(req.query.category || "all");

        const sort = String(req.query.sort || "newest");

        const page = parsePage(req.query.page);

        const limit = 10;

        const baseQuery = {
          status: { $ne: "deleted" },
        };

        const conditions = [baseQuery];

        // Status
        if (status === "available") {
          conditions.push({ available: true });
        } else if (status === "unavailable") {
          conditions.push({ available: false });
        } else if (status === "featured") {
          conditions.push({ featured: true });
        }

        // Category
        if (category !== "all") {
          conditions.push({
            categoryId: category,
          });
        }

        // Search
        if (search) {
          conditions.push(...(await getSearchConditions(search)));
        }

        const query = {
          $and: conditions,
        };

        const sorts = {
          newest: {
            createdAt: -1,
            _id: -1,
          },
          oldest: {
            createdAt: 1,
            _id: 1,
          },
          price_low: {
            effectivePrice: 1,
            _id: -1,
          },
          price_high: {
            effectivePrice: -1,
            _id: -1,
          },
          name: {
            name: 1,
            _id: 1,
          },
        };

        // Price calculation for admin sorting
        const pipeline = [
          {
            $match: query,
          },

          {
            $addFields: {
              effectivePrice: {
                $cond: [
                  {
                    $and: [
                      {
                        $gt: ["$salePrice", 0],
                      },
                      {
                        $lt: ["$salePrice", "$regularPrice"],
                      },
                    ],
                  },

                  "$salePrice",
                  "$regularPrice",
                ],
              },
            },
          },

          {
            $sort: sorts[sort] || sorts.newest,
          },

          {
            $skip: (page - 1) * limit,
          },

          {
            $limit: limit,
          },

          {
            $project: {
              name: 1,
              slug: 1,
              sku: 1,

              categoryId: 1,
              occasionIds: 1,

              regularPrice: 1,
              salePrice: 1,

              available: 1,
              featured: 1,
              customizable: 1,
              surpriseBox: 1,
              variantsEnabled: 1,

              createdAt: 1,

              images: {
                $slice: [
                  {
                    $ifNull: ["$images", []],
                  },
                  1,
                ],
              },
            },
          },
        ];

        // Dashboard stats
        const statsPipeline = [
          {
            $match: baseQuery,
          },

          {
            $group: {
              _id: null,

              total: {
                $sum: 1,
              },

              available: {
                $sum: {
                  $cond: [
                    {
                      $eq: ["$available", true],
                    },
                    1,
                    0,
                  ],
                },
              },

              unavailable: {
                $sum: {
                  $cond: [
                    {
                      $ne: ["$available", true],
                    },
                    1,
                    0,
                  ],
                },
              },

              featured: {
                $sum: {
                  $cond: [
                    {
                      $eq: ["$featured", true],
                    },
                    1,
                    0,
                  ],
                },
              },
            },
          },
        ];

        const [productList, total, statsRows] = await Promise.all([
          products.aggregate(pipeline).toArray(),

          products.countDocuments(query),

          products.aggregate(statsPipeline).toArray(),
        ]);

        const stats = statsRows[0] || {
          total: 0,
          available: 0,
          unavailable: 0,
          featured: 0,
        };

        const totalPages = Math.max(1, Math.ceil(total / limit));

        res.set("Cache-Control", "no-store");

        return res.send({
          success: true,

          products: productList.map((item) => ({
            ...item,
            _id: item._id.toString(),
          })),

          stats: {
            total: stats.total,
            available: stats.available,
            unavailable: stats.unavailable,
            featured: stats.featured,
          },

          pagination: {
            page,
            limit,
            total,
            totalPages,

            hasNextPage: page < totalPages,

            hasPreviousPage: page > 1,
          },
        });
      } catch (error) {
        return respondError(res, error, "Get Admin Products Error");
      }
    },
  );

  // ==========================================
  // ALLOWED PRODUCT UPDATE FIELDS
  // Used by the product PATCH route above.
  // ==========================================

  const PATCHABLE_FIELDS = new Set([
    "name",
    "sku",
    "autoSku",
    "description",

    "regularPrice",
    "salePrice",

    "categoryId",
    "occasionIds",

    "images",
    "available",
    "featured",
    "customizable",

    "variantsEnabled",
    "options",
    "variantOverrides",
    "variants",

    "customerFieldType",

    "packaging",
    "premiumBoxPrice",
  ]);

  // ==========================================
  // UPDATE PRODUCT AVAILABILITY
  // ==========================================

  app.patch(
    "/admin/products/:productId/availability",
    verifyFirebaseToken,
    verifyAdmin,
    async (req, res) => {
      try {
        const { productId } = req.params;

        if (!isMongoId(productId)) {
          reject("Invalid product ID");
        }

        if (typeof req.body?.available !== "boolean") {
          reject("Available must be true or false");
        }

        const result = await products.updateOne(
          {
            _id: new ObjectId(productId),
          },
          {
            $set: {
              available: req.body.available,

              updatedAt: new Date(),
            },
          },
        );

        if (!result.matchedCount) {
          reject("Product not found", 404);
        }

        return res.send({
          success: true,

          message: "Product availability updated",

          available: req.body.available,
        });
      } catch (error) {
        return respondError(res, error, "Update Availability Error");
      }
    },
  );

  // ==========================================
  // DELETE PRODUCT
  // ==========================================

  app.delete(
    "/admin/products/:productId",
    verifyFirebaseToken,
    verifyAdmin,
    async (req, res) => {
      try {
        const { productId } = req.params;

        if (!isMongoId(productId)) {
          reject("Invalid product ID");
        }

        const result = await products.deleteOne({
          _id: new ObjectId(productId),
        });

        if (!result.deletedCount) {
          reject("Product not found", 404);
        }

        return res.send({
          success: true,
          message: "Product deleted successfully",
        });
      } catch (error) {
        return respondError(res, error, "Delete Product Error");
      }
    },
  );

  // ==========================================
  // PUBLIC PRODUCTS CONFIGURATION
  // No Login Required
  // ==========================================

  const PUBLIC_FEATURES = new Set([
    "customizable",
    "surpriseBox",
    "featured",
    "discounted",
    "variants",
  ]);

  const publicProductProjection = {
    name: 1,
    slug: 1,
    sku: 1,
    description: 1,

    categoryId: 1,
    occasionIds: 1,

    images: 1,

    regularPrice: 1,
    salePrice: 1,

    available: 1,
    featured: 1,
    customizable: 1,
    surpriseBox: 1,
    variantsEnabled: 1,

    options: 1,
    variants: 1,

    customerFieldType: 1,
    customerFields: 1,

    packaging: 1,
    premiumBoxPrice: 1,
  };

  const getPublicProduct = async (identifier) => {
    const value = String(identifier || "").trim();

    if (!value || value.length > 200) {
      return null;
    }

    const identifierQuery = isMongoId(value)
      ? {
          $or: [
            {
              _id: new ObjectId(value),
            },
            {
              slug: value,
            },
          ],
        }
      : {
          slug: value,
        };

    return products.findOne(
      {
        status: "published",
        ...identifierQuery,
      },
      {
        projection: publicProductProjection,
      },
    );
  };

  // ==========================================
  // PUBLIC PRODUCTS LIST
  // GET /products
  // Search + Filters + Sorting + Pagination
  // ==========================================

  app.get("/products", async (req, res) => {
    try {
      // ================= QUERY PARAMS =================

      const search = String(req.query.search || "")
        .normalize("NFKC")
        .trim()
        .slice(0, 120);

      const selectedCategories = parseCsv(req.query.categories);

      const selectedOccasions = parseCsv(req.query.occasions);

      const features = parseCsv(req.query.features).filter((feature) =>
        PUBLIC_FEATURES.has(feature),
      );

      const availability = String(req.query.availability || "all");

      const sort = String(req.query.sort || "featured");

      const page = parsePage(req.query.page);

      const limit = 12;
      const skip = (page - 1) * limit;

      const minPrice = parseAmount(req.query.minPrice);

      const maxPrice = parseAmount(req.query.maxPrice);

      if (minPrice !== null && maxPrice !== null && minPrice > maxPrice) {
        return res.status(400).send({
          success: false,
          message: "Minimum price cannot exceed maximum price",
        });
      }

      // ================= BASE FILTER =================

      const conditions = [{ status: "published" }];

      // ================= AVAILABILITY =================

      if (availability === "available") {
        conditions.push({ available: true });
      }

      if (availability === "unavailable") {
        conditions.push({ available: false });
      }

      // ================= CATEGORY =================

      if (selectedCategories.length) {
        conditions.push({
          categoryId: {
            $in: selectedCategories,
          },
        });
      }

      // ================= OCCASION =================

      if (selectedOccasions.length) {
        conditions.push({
          occasionIds: {
            $in: selectedOccasions,
          },
        });
      }

      // ================= FEATURES =================

      const featureQueries = {
        customizable: {
          customizable: true,
        },

        surpriseBox: {
          surpriseBox: true,
        },

        featured: {
          featured: true,
        },

        variants: {
          variantsEnabled: true,
        },

        discounted: {
          $expr: {
            $and: [
              {
                $gt: ["$salePrice", 0],
              },
              {
                $lt: ["$salePrice", "$regularPrice"],
              },
            ],
          },
        },
      };

      if (features.length) {
        conditions.push({
          $or: features.map((feature) => featureQueries[feature]),
        });
      }

      // ================= MULTILINGUAL SEARCH =================

      if (search) {
        conditions.push(...(await getSearchConditions(search)));
      }

      // ================= PRICE CALCULATION =================
      //
      // Normal Product:
      // price = salePrice (if valid), else regularPrice
      // maxPrice = price
      //
      // Variant Product:
      // price = lowest available variant price
      // maxPrice = highest available variant price

      const priceStages = [
        {
          $addFields: {
            // Base product price
            basePrice: {
              $cond: [
                {
                  $and: [
                    {
                      $gt: ["$salePrice", 0],
                    },
                    {
                      $lt: ["$salePrice", "$regularPrice"],
                    },
                  ],
                },

                "$salePrice",
                "$regularPrice",
              ],
            },

            // Only prices of available variants
            availableVariantPrices: {
              $map: {
                input: {
                  $filter: {
                    input: {
                      $cond: [
                        {
                          $isArray: "$variants",
                        },
                        "$variants",
                        [],
                      ],
                    },

                    as: "variant",

                    cond: {
                      $and: [
                        {
                          $ne: ["$$variant.available", false],
                        },
                        {
                          $isNumber: "$$variant.price",
                        },
                        {
                          $gt: ["$$variant.price", 0],
                        },
                      ],
                    },
                  },
                },

                as: "variant",
                in: "$$variant.price",
              },
            },
          },
        },

        {
          $addFields: {
            hasAvailableVariants: {
              $and: [
                {
                  $eq: ["$variantsEnabled", true],
                },

                {
                  $gt: [
                    {
                      $size: "$availableVariantPrices",
                    },
                    0,
                  ],
                },
              ],
            },
          },
        },

        {
          $addFields: {
            // Lowest price
            effectivePrice: {
              $cond: [
                "$hasAvailableVariants",

                {
                  $min: "$availableVariantPrices",
                },

                "$basePrice",
              ],
            },

            // Highest price
            effectiveMaxPrice: {
              $cond: [
                "$hasAvailableVariants",

                {
                  $max: "$availableVariantPrices",
                },

                "$basePrice",
              ],
            },
          },
        },
      ];

      // ================= PRICE FILTER =================
      // Existing behavior: filter by lowest price.

      const priceRange = {};

      if (minPrice !== null) {
        priceRange.$gte = minPrice;
      }

      if (maxPrice !== null) {
        priceRange.$lte = maxPrice;
      }

      // ================= SORT OPTIONS =================

      const sorts = {
        featured: {
          featured: -1,
          createdAt: -1,
          _id: -1,
        },

        newest: {
          createdAt: -1,
          _id: -1,
        },

        "price-low": {
          effectivePrice: 1,
          _id: -1,
        },

        "price-high": {
          effectivePrice: -1,
          _id: -1,
        },
      };

      // ================= AGGREGATION =================

      const pipeline = [
        {
          $match: {
            $and: conditions,
          },
        },

        ...priceStages,

        ...(Object.keys(priceRange).length
          ? [
              {
                $match: {
                  effectivePrice: priceRange,
                },
              },
            ]
          : []),

        {
          $facet: {
            // ================= PRODUCTS =================

            items: [
              {
                $sort: sorts[sort] || sorts.featured,
              },

              {
                $skip: skip,
              },

              {
                $limit: limit,
              },

              // ================= PROJECTION =================

              {
                $project: {
                  name: 1,
                  slug: 1,
                  description: 1,

                  categoryId: 1,
                  occasionIds: 1,

                  regularPrice: 1,
                  salePrice: 1,

                  // NEW PRICE RANGE FIELDS
                  price: "$effectivePrice",
                  maxPrice: "$effectiveMaxPrice",

                  images: {
                    $slice: [
                      {
                        $ifNull: ["$images", []],
                      },
                      1,
                    ],
                  },

                  available: 1,
                  featured: 1,
                  customizable: 1,
                  surpriseBox: 1,
                  variantsEnabled: 1,
                },
              },
            ],

            // ================= COUNT =================

            count: [
              {
                $count: "value",
              },
            ],
          },
        },
      ];

      // ================= CATEGORY COUNTS =================

      const [data, categoryStats] = await Promise.all([
        products.aggregate(pipeline).toArray(),

        products
          .aggregate([
            {
              $match: {
                status: "published",
              },
            },
            {
              $group: {
                _id: "$categoryId",
                total: {
                  $sum: 1,
                },
              },
            },
          ])
          .toArray(),
      ]);

      // ================= PAGINATION =================

      const result = data[0] || {
        items: [],
        count: [],
      };

      const total = result.count[0]?.value || 0;

      const totalPages = Math.ceil(total / limit);

      const categoryCounts = Object.fromEntries(
        categoryStats
          .filter((item) => typeof item._id === "string")
          .map((item) => [item._id, item.total]),
      );

      // ================= RESPONSE =================

      res.set("Cache-Control", "no-store");

      return res.status(200).send({
        success: true,

        products: result.items.map((item) => ({
          ...item,
          _id: item._id.toString(),
        })),

        pagination: {
          page,
          limit,
          total,
          totalPages,

          hasNextPage: page < totalPages,
          hasPreviousPage: page > 1,
        },

        categoryCounts,
      });
    } catch (error) {
      console.error("Public Products Error:", error);

      return res.status(500).send({
        success: false,
        message: "Failed to load products",
      });
    }
  });

  // ==========================================
  // PUBLIC RELATED PRODUCTS
  // GET /products/:identifier/related
  // ==========================================

  app.get("/products/:identifier/related", async (req, res) => {
    try {
      const product = await getPublicProduct(req.params.identifier);

      if (!product) {
        return res.status(404).send({
          success: false,
          message: "Product not found",
        });
      }

      const related = await products
        .find(
          {
            _id: {
              $ne: product._id,
            },

            categoryId: product.categoryId,

            status: "published",
            available: true,
          },
          {
            projection: publicProductProjection,
          },
        )
        .sort({
          featured: -1,
          createdAt: -1,
        })
        .limit(4)
        .toArray();

      return res.send({
        success: true,

        products: related.map((item) => ({
          ...item,
          _id: item._id.toString(),
        })),
      });
    } catch (error) {
      return respondError(res, error, "Related Products Error");
    }
  });

  // ==========================================
  // PUBLIC SINGLE PRODUCT
  // GET /products/:identifier
  // ==========================================

  app.get("/products/:identifier", async (req, res) => {
    try {
      const product = await getPublicProduct(req.params.identifier);

      if (!product) {
        return res.status(404).send({
          success: false,
          message: "Product not found",
        });
      }

      res.set("Cache-Control", "no-store");

      return res.send({
        success: true,

        product: {
          ...product,
          _id: product._id.toString(),
        },
      });
    } catch (error) {
      return respondError(res, error, "Get Product Details Error");
    }
  });

  // ==========================================
  // CONNECTION CHECK
  // ==========================================

  // await client.db("admin").command({
  //   ping: 1,
  // });

  // console.log("SokhBilash MongoDB connected; routes initialized");
}
// Initialize MongoDB, seed data, create indexes, and register routes once.
const routesReady = run();

// Health endpoint: reachable even while database initialization is pending.
app.get("/", (req, res) => {
  res.status(200).json({
    success: true,
    message: "SokhBilash Backend API is running",
  });
});

// Wait for database initialization, then forward requests to the API router.
app.use(async (req, res, next) => {
  try {
    await routesReady;
    return apiRouter(req, res, next);
  } catch (error) {
    console.error("Backend initialization failed:", error.message);

    if (res.headersSent) return next(error);

    return res.status(503).json({
      success: false,
      message: "Backend initialization failed. Check server logs.",
    });
  }
});

// Vercel uses the exported Express app.
module.exports = app;

// Local Node.js / nodemon runs a normal HTTP server.
if (require.main === module) {
  routesReady
    .then(() => {
      app.listen(port, () => {
        console.log(`SokhBilash API running on port ${port}`);
      });
    })
    .catch((error) => {
      console.error("Server initialization failed:", error);
      process.exitCode = 1;
    });
}
