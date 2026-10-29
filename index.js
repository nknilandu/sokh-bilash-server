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
const { getAuth } = require("firebase-admin/auth");
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
    const users = DB.collection("users");

    const categories = DB.collection("categories");
    const occasions = DB.collection("occasions");
    const products = DB.collection("products");

    // ================ admin middleware ==================
    const verifyAdmin = async (req, res, next) => {
      try {
        const admin = await users.findOne({
          uid: req.user.uid,
          role: "admin",
          status: "active",
        });

        if (!admin) {
          return res.status(403).send({
            success: false,
            message: "Only active admins can perform this action",
          });
        }

        next();
      } catch (error) {
        console.error("Verify Admin Error:", error);

        res.status(500).send({
          success: false,
          message: "Authorization failed",
        });
      }
    };

    // ============== inject categories and occasions ==============
    const DEFAULT_CATEGORIES = [
      {
        id: "photo-frames",
        name: "ফটো ফ্রেম ও স্মৃতির উপহার",
        imageUrl:
          "https://placehold.co/800x600/F8F5FA/310039/png?text=Photo+Frames",
      },
      {
        id: "magic-mirror-led",
        name: "ম্যাজিক মিরর ও LED গিফট",
        imageUrl:
          "https://placehold.co/800x600/F8F5FA/310039/png?text=Magic+Mirror",
      },
      {
        id: "personalized",
        name: "কাস্টমাইজড ও পার্সোনালাইজড গিফট",
        imageUrl:
          "https://placehold.co/800x600/F8F5FA/310039/png?text=Personalized+Gifts",
      },
      {
        id: "gift-combos",
        name: "গিফট কম্বো ও হ্যাম্পার",
        imageUrl:
          "https://placehold.co/800x600/F8F5FA/310039/png?text=Gift+Combos",
      },
      {
        id: "flowers",
        name: "ফুল ও বুকেট",
        imageUrl: "https://placehold.co/800x600/F8F5FA/310039/png?text=Flowers",
      },
      {
        id: "chocolates",
        name: "চকলেট ও মিষ্টির উপহার",
        imageUrl:
          "https://placehold.co/800x600/F8F5FA/310039/png?text=Chocolates",
      },
      {
        id: "clothing",
        name: "পোশাক ও কাপল সেট",
        imageUrl:
          "https://placehold.co/800x600/F8F5FA/310039/png?text=Clothing",
      },
      {
        id: "party-decorations",
        name: "পার্টি ও অনুষ্ঠানের সাজসজ্জা",
        imageUrl:
          "https://placehold.co/800x600/F8F5FA/310039/png?text=Party+Decorations",
      },
      {
        id: "islamic",
        name: "ইসলামিক ও নিকাহ উপহার",
        imageUrl:
          "https://placehold.co/800x600/F8F5FA/310039/png?text=Islamic+Gifts",
      },
      {
        id: "romantic-gifts",
        name: "টেডি বেয়ার ও রোমান্টিক গিফট",
        imageUrl:
          "https://placehold.co/800x600/F8F5FA/310039/png?text=Romantic+Gifts",
      },
      {
        id: "others",
        name: "অন্যান্য (Others)",
        imageUrl:
          "https://placehold.co/800x600/F8F5FA/310039/png?text=Other+Gifts",
      },
    ];

    const DEFAULT_OCCASIONS = [
      {
        id: "birthday",
        name: "জন্মদিন",
        imageUrl:
          "https://placehold.co/800x600/F8F5FA/310039/png?text=Birthday",
      },
      {
        id: "anniversary",
        name: "বিবাহবার্ষিকী",
        imageUrl:
          "https://placehold.co/800x600/F8F5FA/310039/png?text=Anniversary",
      },
      {
        id: "wedding-nikah",
        name: "বিয়ে ও নিকাহ",
        imageUrl:
          "https://placehold.co/800x600/F8F5FA/310039/png?text=Wedding+Nikah",
      },
      {
        id: "love-romance",
        name: "ভালোবাসা ও রোমান্স",
        imageUrl:
          "https://placehold.co/800x600/F8F5FA/310039/png?text=Love+Romance",
      },
      {
        id: "islamic",
        name: "ইসলামিক উপলক্ষ",
        imageUrl:
          "https://placehold.co/800x600/F8F5FA/310039/png?text=Islamic+Occasions",
      },
      {
        id: "parents-day",
        name: "বাবা-মা দিবস",
        imageUrl:
          "https://placehold.co/800x600/F8F5FA/310039/png?text=Parents+Day",
      },
      {
        id: "congratulations",
        name: "অভিনন্দন ও অর্জন",
        imageUrl:
          "https://placehold.co/800x600/F8F5FA/310039/png?text=Congratulations",
      },
      {
        id: "surprise",
        name: "সারপ্রাইজ ও বিশেষ মুহূর্ত",
        imageUrl:
          "https://placehold.co/800x600/F8F5FA/310039/png?text=Surprise",
      },
    ];

    // ================= Seed Categories =================
    await categories.bulkWrite(
      DEFAULT_CATEGORIES.flatMap((category, index) => [
        {
          updateOne: {
            filter: { id: category.id },
            update: {
              $setOnInsert: {
                ...category,
                sortOrder: index + 1,
              },
            },
            upsert: true,
          },
        },
        {
          updateOne: {
            filter: {
              id: category.id,
              $or: [
                { imageUrl: { $exists: false } },
                { imageUrl: "" },
                { imageUrl: null },
              ],
            },
            update: {
              $set: { imageUrl: category.imageUrl },
            },
          },
        },
      ]),
    );

    // ================= Seed Occasions =================
    await occasions.bulkWrite(
      DEFAULT_OCCASIONS.flatMap((occasion, index) => [
        {
          updateOne: {
            filter: { id: occasion.id },
            update: {
              $setOnInsert: {
                ...occasion,
                sortOrder: index + 1,
              },
            },
            upsert: true,
          },
        },
        {
          updateOne: {
            filter: {
              id: occasion.id,
              $or: [
                { imageUrl: { $exists: false } },
                { imageUrl: "" },
                { imageUrl: null },
              ],
            },
            update: {
              $set: { imageUrl: occasion.imageUrl },
            },
          },
        },
      ]),
    );

    // ================= GET Categories =================
    app.get("/categories", async (req, res) => {
      try {
        const result = await categories
          .find({}, { projection: { _id: 0, id: 1, name: 1 } })
          .sort({ sortOrder: 1 })
          .toArray();

        res.send({
          success: true,
          categories: result,
        });
      } catch (error) {
        console.error("Get Categories Error:", error);

        res.status(500).send({
          success: false,
          message: "Failed to fetch categories",
        });
      }
    });

    // ================= GET Occasions =================
    app.get("/occasions", async (req, res) => {
      try {
        const result = await occasions
          .find({}, { projection: { _id: 0, id: 1, name: 1 } })
          .sort({ sortOrder: 1 })
          .toArray();

        res.send({
          success: true,
          occasions: result,
        });
      } catch (error) {
        console.error("Get Occasions Error:", error);

        res.status(500).send({
          success: false,
          message: "Failed to fetch occasions",
        });
      }
    });

    // ================= Create User ===================
    app.put("/users", verifyFirebaseToken, async (req, res) => {
      try {
        const { displayName, phone, photoUrl = "" } = req.body;

        // Firebase verified data
        const uid = req.user.uid;
        const email = req.user.email;

        // Validate required fields
        if (!uid || !email || !displayName?.trim() || !phone?.trim()) {
          return res.status(400).send({
            success: false,
            message: "Name, email and phone are required",
          });
        }

        if (
          typeof displayName !== "string" ||
          typeof phone !== "string" ||
          typeof photoUrl !== "string" ||
          !/^01[3-9]\d{8}$/.test(phone.trim())
        ) {
          return res.status(400).send({
            success: false,
            message: "Invalid user information",
          });
        }

        // Check existing user
        const existingUser = await users.findOne({
          $or: [{ uid }, { email }],
        });

        if (existingUser) {
          // Prevent matching another Firebase account
          if (existingUser.uid !== uid) {
            return res.status(409).send({
              success: false,
              message: "Email already belongs to another account",
            });
          }

          return res.status(200).send({
            success: true,
            message: "User already exists",
            insertedId: existingUser._id,
            existing: true,
          });
        }

        // New user document
        const newUser = {
          uid,
          displayName: displayName.trim(),
          email,
          phone: phone.trim(),
          photoUrl: photoUrl.trim() || null,
          role: "customer",
          status: "active",
          createdAt: new Date(),
          updatedAt: new Date(),
        };

        // Insert new user
        const result = await users.insertOne(newUser);

        if (result.acknowledged) {
          return res.status(201).send({
            success: true,
            message: "User registered successfully",
            insertedId: result.insertedId,
            existing: false,
          });
        }

        return res.status(400).send({
          success: false,
          message: "User not added",
        });
      } catch (error) {
        console.error("User Registration Error:", error);

        return res.status(500).send({
          success: false,
          message: "Internal server error",
        });
      }
    });

    // ================= Get User Role =================
    app.get("/users/role", verifyFirebaseToken, async (req, res) => {
      try {
        const uid = req.user.uid;

        const user = await users.findOne(
          { uid },
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

        return res.status(200).send({
          success: true,
          role: user.role,
          status: user.status,
        });
      } catch (error) {
        console.error("Get User Role Error:", error);

        return res.status(500).send({
          success: false,
          message: "Internal server error",
        });
      }
    });

    //===================== admin add product ======================
    app.post(
      "/admin/products",
      verifyFirebaseToken,
      verifyAdmin,
      async (req, res) => {
        try {
          const body = req.body || {};
          const name = String(body.name || "").trim();
          const sku = String(body.sku || "")
            .trim()
            .toUpperCase();
          const description = String(body.description || "").trim();
          const categoryId = String(body.categoryId || "").trim();
          const occasionIds = body.occasionIds;
          const regularPrice = Number(body.regularPrice);

          const salePrice =
            body.salePrice === "" ||
            body.salePrice === null ||
            body.salePrice === undefined
              ? null
              : Number(body.salePrice);

          // ================= BASIC VALIDATION =================
          if (!name || !sku || !categoryId) {
            return res.status(400).send({
              success: false,
              message: "Product name, SKU and category are required",
            });
          }

          if (!Number.isFinite(regularPrice) || regularPrice <= 0) {
            return res.status(400).send({
              success: false,
              message: "Invalid regular price",
            });
          }

          if (
            salePrice !== null &&
            (!Number.isFinite(salePrice) ||
              salePrice <= 0 ||
              salePrice >= regularPrice)
          ) {
            return res.status(400).send({
              success: false,
              message: "Sale price must be lower than regular price",
            });
          }

          // ================= CATEGORY VALIDATION =================
          const category = await categories.findOne({
            id: categoryId,
          });

          if (!category) {
            return res.status(400).send({
              success: false,
              message: "Invalid category selected",
            });
          }

          // ================= OCCASION VALIDATION =================
          if (
            !Array.isArray(occasionIds) ||
            occasionIds.length === 0 ||
            occasionIds.some((id) => typeof id !== "string" || !id.trim()) ||
            new Set(occasionIds).size !== occasionIds.length
          ) {
            return res.status(400).send({
              success: false,
              message: "Select at least one valid occasion",
            });
          }

          const occasionCount = await occasions.countDocuments({
            id: { $in: occasionIds },
          });

          if (occasionCount !== occasionIds.length) {
            return res.status(400).send({
              success: false,
              message: "Invalid occasion selected",
            });
          }

          // ================= IMAGE VALIDATION =================
          const validImageUrl = (url) => {
            try {
              return ["http:", "https:"].includes(new URL(url).protocol);
            } catch {
              return false;
            }
          };

          const images = Array.isArray(body.images)
            ? body.images
                .filter(
                  (image) =>
                    image && typeof image.url === "string" && image.url.trim(),
                )
                .map((image) => ({
                  id: String(image.id || ""),
                  url: image.url.trim(),
                }))
            : [];

          if (
            images.length === 0 ||
            images.length > 5 ||
            images.some((image) => !validImageUrl(image.url))
          ) {
            return res.status(400).send({
              success: false,
              message: "Provide 1 to 5 valid product images",
            });
          }

          const imageUrls = images.map((image) => image.url);

          if (new Set(imageUrls).size !== imageUrls.length) {
            return res.status(400).send({
              success: false,
              message: "Duplicate image URLs are not allowed",
            });
          }

          // ================= VARIANT VALIDATION =================
          const variantsEnabled = body.variantsEnabled === true;
          const rawVariants = variantsEnabled ? body.variants : [];

          if (
            !Array.isArray(rawVariants) ||
            rawVariants.length > 100 ||
            (variantsEnabled && rawVariants.length === 0)
          ) {
            return res.status(400).send({
              success: false,
              message: "Invalid variants (maximum 100)",
            });
          }

          const variants = [];

          for (const variant of rawVariants) {
            if (!variant || typeof variant !== "object") {
              return res.status(400).send({
                success: false,
                message: "Invalid variant data",
              });
            }

            const variantSku = String(variant.sku || "")
              .trim()
              .toUpperCase();

            const variantPrice = Number(variant.price);
            const imageUrl = String(variant.imageUrl || "").trim();

            if (
              !variantSku ||
              !Number.isFinite(variantPrice) ||
              variantPrice <= 0 ||
              (imageUrl && !validImageUrl(imageUrl))
            ) {
              return res.status(400).send({
                success: false,
                message: "Invalid variant SKU, price or image",
              });
            }

            variants.push({
              key: String(variant.key || ""),
              title: String(variant.title || ""),
              options: {
                size: String(variant.options?.size || ""),
                color: String(variant.options?.color || ""),
                type: String(variant.options?.type || ""),
              },
              sku: variantSku,
              autoSku: variant.autoSku === true,
              price: variantPrice,
              imageUrl,
              available: variant.available !== false,
            });
          }

          // ================= SKU VALIDATION =================
          const allSkus = [sku, ...variants.map((variant) => variant.sku)];

          if (new Set(allSkus).size !== allSkus.length) {
            return res.status(409).send({
              success: false,
              message: "Product and variant SKUs must be unique",
            });
          }

          const existingProduct = await products.findOne({
            $or: [
              { sku: { $in: allSkus } },
              { "variants.sku": { $in: allSkus } },
            ],
          });

          if (existingProduct) {
            return res.status(409).send({
              success: false,
              message: "Product or variant SKU already exists",
            });
          }

          // ================= PACKAGING VALIDATION =================
          const premiumBoxPrice = Number(body.premiumBoxPrice);

          if (!Number.isFinite(premiumBoxPrice) || premiumBoxPrice < 0) {
            return res.status(400).send({
              success: false,
              message: "Invalid premium box price",
            });
          }

          // ================= GENERATE UNIQUE SLUG =================
          const productId = new ObjectId();

          const nameSlug = name
            .normalize("NFC")
            .toLowerCase()
            .replace(/[^\p{L}\p{M}\p{N}]+/gu, "-")
            .replace(/^-+|-+$/g, "")
            .slice(0, 90);

          const slug = `${
            nameSlug || "product"
          }-${productId.toHexString().slice(-8)}`;

          // ================= PRODUCT DOCUMENT =================
          const newProduct = {
            _id: productId,

            name,
            slug,
            sku,
            autoSku: body.autoSku === true,
            description,

            regularPrice,
            salePrice,

            categoryId,
            occasionIds,

            images,

            available: body.available === true,
            featured: body.featured === true,
            customizable: body.customizable === true,

            variantsEnabled,

            options: body.options || {},
            variantOverrides: body.variantOverrides || {},
            variants,

            customerFieldType: body.customizable
              ? body.customerFieldType || "none"
              : "none",

            customerFields:
              body.customizable && Array.isArray(body.customerFields)
                ? body.customerFields
                : [],

            surpriseBox: body.surpriseBox === true,

            packaging: body.packaging === "premium" ? "premium" : "regular",

            premiumBoxPrice,

            status: "published",

            createdBy: req.user.uid,
            createdAt: new Date(),
            updatedAt: new Date(),
          };

          // ================= SAVE TO MONGODB =================
          const result = await products.insertOne(newProduct);

          return res.status(201).send({
            success: true,
            message: "Product added successfully",
            insertedId: result.insertedId.toString(),
            slug,
          });
        } catch (error) {
          console.error("Add Product Error:", error);

          return res.status(error.code === 11000 ? 409 : 500).send({
            success: false,
            message:
              error.code === 11000
                ? "Duplicate product information"
                : "Failed to add product",
          });
        }
      },
    );

    // ================= MULTILINGUAL SEARCH =================

    // Common Bangla, English and Banglish gift terms.
    // Add more aliases as your product catalog grows.

    const SEARCH_GROUPS = [
      ["ফটো", "ছবি", "photo", "foto", "picture", "pic"],
      ["ফ্রেম", "frame", "frem"],
      ["গিফট", "উপহার", "gift", "gifts", "upohar", "upahar"],
      ["ফুল", "ফুলের", "flower", "flowers", "ful", "phul", "fuler"],
      ["বুকেট", "bouquet", "buke", "buket"],
      ["গোলাপ", "গোলাপের", "rose", "golap", "golaper"],
      ["চকলেট", "chocolate", "chocolates", "choklet"],
      ["বক্স", "box", "boks"],
      ["জন্মদিন", "birthday", "jonmodin", "jonmo", "jonmodine"],
      ["বিবাহবার্ষিকী", "anniversary", "bibahobarshiki", "barsiki"],
      ["বিয়ে", "বিবাহ", "wedding", "biye", "biya"],
      ["নিকাহ", "নিকাহনামা", "nikah", "nikahnama"],
      ["ভালোবাসা", "প্রেম", "love", "valobasha", "bhalobasha", "prem"],
      ["রোমান্টিক", "romantic", "romance"],
      ["ইসলামিক", "ইসলামী", "islamic", "islami"],
      ["সারপ্রাইজ", "surprise", "surprize", "sarprise"],
      ["কাস্টম", "কাস্টমাইজড", "custom", "customized", "customised"],
      ["পার্সোনালাইজড", "personalized", "personalised"],
      ["পোশাক", "clothing", "dress", "kapor", "কাপড়"],
      ["শাড়ি", "শাড়ি", "saree", "sharee", "sari"],
      ["পাঞ্জাবি", "পাঞ্জাবী", "panjabi", "punjabi"],
      ["শার্ট", "shirt", "shart"],
      ["কাপল", "couple", "couples", "kapol"],
      ["টেডি", "teddy", "tedi"],
      ["বেয়ার", "বেয়ার", "bear"],
      ["মিরর", "আয়না", "mirror", "ayna"],
      ["ম্যাজিক", "magic", "majik"],
      ["এলইডি", "led"],
      ["কম্বো", "combo", "combos"],
      ["হ্যাম্পার", "hamper", "hampers"],
      ["পেন", "কলম", "pen", "kolom"],
      ["প্রিমিয়াম", "premium", "premiam"],
      ["লাক্সারি", "luxury", "luxari"],
      ["অভিনন্দন", "congratulations", "obhinondon"],
      ["অর্জন", "achievement", "orjon"],
    ];

    const escapeSearch = (text) => text.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

    const makeSearchRegex = (word) => {
      const normalized = word.normalize("NFKC").toLowerCase();

      const group = SEARCH_GROUPS.find((items) =>
        items.some((item) => item.toLowerCase() === normalized),
      );

      const words = group || [normalized];

      return new RegExp([...new Set(words)].map(escapeSearch).join("|"), "i");
    };

    // ================= GET ADMIN PRODUCTS =================
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

          const page = Math.max(1, Number.parseInt(req.query.page, 10) || 1);

          const limit = 10;
          const skip = (page - 1) * limit;

          const baseQuery = {
            status: { $ne: "deleted" },
          };

          const conditions = [];

          // ================= STATUS FILTER =================
          if (status === "available") {
            conditions.push({ available: true });
          } else if (status === "unavailable") {
            conditions.push({ available: false });
          } else if (status === "featured") {
            conditions.push({ featured: true });
          }

          // ================= CATEGORY FILTER =================
          if (category !== "all") {
            conditions.push({ categoryId: category });
          }

          // ================= SEARCH FILTER =================
          if (search) {
            const words = search.split(/\s+/u).filter(Boolean).slice(0, 8);

            for (const word of words) {
              const regex = makeSearchRegex(word);

              // Search in category and occasion names too
              const [matchedCategories, matchedOccasions] = await Promise.all([
                categories
                  .find(
                    {
                      $or: [{ id: regex }, { name: regex }],
                    },
                    { projection: { _id: 0, id: 1 } },
                  )
                  .toArray(),

                occasions
                  .find(
                    {
                      $or: [{ id: regex }, { name: regex }],
                    },
                    { projection: { _id: 0, id: 1 } },
                  )
                  .toArray(),
              ]);

              const categoryIds = matchedCategories.map((c) => c.id);
              const occasionIds = matchedOccasions.map((o) => o.id);

              conditions.push({
                $or: [
                  { name: regex },
                  { description: regex },
                  { sku: regex },
                  { slug: regex },
                  { "variants.sku": regex },
                  { searchKeywords: regex },
                  { categoryId: regex },
                  { occasionIds: regex },
                  { categoryId: { $in: categoryIds } },
                  { occasionIds: { $in: occasionIds } },
                ],
              });
            }
          }

          const query = conditions.length
            ? { $and: [baseQuery, ...conditions] }
            : baseQuery;

          // ================= SORT =================

          const sorts = {
            newest: { createdAt: -1, _id: -1 },
            oldest: { createdAt: 1, _id: 1 },
            price_low: { effectivePrice: 1, _id: -1 },
            price_high: { effectivePrice: -1, _id: -1 },
            name: { name: 1, _id: 1 },
          };

          const sortOption = sorts[sort] || sorts.newest;

          // ================= PROJECTION =================
          const pipeline = [
            { $match: query },
            {
              $addFields: {
                effectivePrice: {
                  $cond: [
                    { $gt: ["$salePrice", 0] },
                    "$salePrice",
                    "$regularPrice",
                  ],
                },
              },
            },
            { $sort: sortOption },
            { $skip: skip },
            { $limit: limit },
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
                variantsEnabled: 1,
                createdAt: 1,
                images: {
                  $slice: [{ $ifNull: ["$images", []] }, 1],
                },
              },
            },
          ];

          // ================= DYNAMIC STATS =================
          const statsPipeline = [
            { $match: baseQuery },
            {
              $group: {
                _id: null,
                total: { $sum: 1 },
                available: {
                  $sum: {
                    $cond: [{ $eq: ["$available", true] }, 1, 0],
                  },
                },
                unavailable: {
                  $sum: {
                    $cond: [{ $ne: ["$available", true] }, 1, 0],
                  },
                },
                featured: {
                  $sum: {
                    $cond: [{ $eq: ["$featured", true] }, 1, 0],
                  },
                },
              },
            },
          ];

          const [productList, total, statsResult] = await Promise.all([
            products.aggregate(pipeline).toArray(),
            products.countDocuments(query),
            products.aggregate(statsPipeline).toArray(),
          ]);

          const stats = statsResult[0] || {
            total: 0,
            available: 0,
            unavailable: 0,
            featured: 0,
          };

          return res.status(200).send({
            success: true,
            products: productList.map((product) => ({
              ...product,
              _id: product._id.toString(),
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
              totalPages: Math.max(1, Math.ceil(total / limit)),
              hasNextPage: page * limit < total,
              hasPreviousPage: page > 1,
            },
          });
        } catch (error) {
          console.error("Get Admin Products Error:", error);

          return res.status(500).send({
            success: false,
            message: "Failed to fetch products",
          });
        }
      },
    );

    // ================= GET SINGLE ADMIN PRODUCT =================
    app.get(
      "/admin/products/:productId",
      verifyFirebaseToken,
      verifyAdmin,
      async (req, res) => {
        try {
          const { productId } = req.params;

          // Validate MongoDB ObjectId
          if (!/^[a-fA-F0-9]{24}$/.test(productId)) {
            return res.status(400).send({
              success: false,
              message: "Invalid product ID",
            });
          }

          // Fetch complete product from MongoDB
          const product = await products.findOne({
            _id: new ObjectId(productId),
            status: { $ne: "deleted" },
          });

          if (!product) {
            return res.status(404).send({
              success: false,
              message: "Product not found",
            });
          }

          // Don't cache admin edit data
          res.set("Cache-Control", "no-store");

          return res.status(200).send({
            success: true,
            message: "Product fetched successfully",
            product: {
              ...product,
              _id: product._id.toString(),
            },
          });
        } catch (error) {
          console.error("Get Single Product Error:", error);

          return res.status(500).send({
            success: false,
            message: "Failed to fetch product",
          });
        }
      },
    );

    //================== ADMIN UPDATE PRODUCT ==============
    app.patch(
      "/admin/products/:productId",
      verifyFirebaseToken,
      verifyAdmin,
      async (req, res) => {
        try {
          const { productId } = req.params;
          const body = req.body;

          const fail = (message, status = 400) =>
            res.status(status).send({
              success: false,
              message,
            });

          if (!/^[a-f\d]{24}$/i.test(productId)) {
            return fail("Invalid product ID");
          }

          if (!body || typeof body !== "object" || Array.isArray(body)) {
            return fail("Invalid request body");
          }

          const id = new ObjectId(productId);

          const existing = await products.findOne({ _id: id });

          if (!existing) {
            return fail("Product not found", 404);
          }

          // Allow updating only known product fields
          const allowedFields = [
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
            "surpriseBox",
            "packaging",
            "premiumBoxPrice",
          ];

          const changes = {};

          for (const field of allowedFields) {
            if (Object.prototype.hasOwnProperty.call(body, field)) {
              changes[field] = body[field];
            }
          }

          if (!Object.keys(changes).length) {
            return fail("No valid fields to update");
          }

          // Merge with existing values for partial PATCH requests
          const data = { ...existing, ...changes };

          const name = String(data.name || "").trim();
          const sku = String(data.sku || "")
            .trim()
            .toUpperCase();
          const description = String(data.description || "").trim();

          const categoryId = String(data.categoryId || "").trim();
          const occasionIds = data.occasionIds;

          const regularPrice = Number(data.regularPrice);

          const salePrice =
            data.salePrice === "" ||
            data.salePrice === null ||
            data.salePrice === undefined
              ? null
              : Number(data.salePrice);

          // ================= BASIC VALIDATION =================

          if (!name || !sku || !categoryId) {
            return fail("Product name, SKU and category are required");
          }

          if (!Number.isFinite(regularPrice) || regularPrice <= 0) {
            return fail("Invalid regular price");
          }

          if (
            salePrice !== null &&
            (!Number.isFinite(salePrice) ||
              salePrice <= 0 ||
              salePrice >= regularPrice)
          ) {
            return fail("Sale price must be lower than regular price");
          }

          // ================= CATEGORY =================

          const categoryExists = await categories.findOne({
            id: categoryId,
          });

          if (!categoryExists) {
            return fail("Invalid category selected");
          }

          // ================= OCCASIONS =================

          if (
            !Array.isArray(occasionIds) ||
            !occasionIds.length ||
            occasionIds.some(
              (value) => typeof value !== "string" || !value.trim(),
            ) ||
            new Set(occasionIds).size !== occasionIds.length
          ) {
            return fail("Select at least one valid occasion");
          }

          const validOccasionCount = await occasions.countDocuments({
            id: { $in: occasionIds },
          });

          if (validOccasionCount !== occasionIds.length) {
            return fail("Invalid occasion selected");
          }

          // ================= IMAGES =================

          const validUrl = (value) => {
            try {
              return (
                typeof value === "string" &&
                ["http:", "https:"].includes(new URL(value).protocol)
              );
            } catch {
              return false;
            }
          };

          if (
            !Array.isArray(data.images) ||
            !data.images.length ||
            data.images.length > 5
          ) {
            return fail("Provide 1 to 5 product images");
          }

          const images = [];

          for (const image of data.images) {
            if (!image || typeof image !== "object") {
              return fail("Invalid product image");
            }

            const url = String(image.url || "").trim();

            if (!validUrl(url)) {
              return fail("Invalid product image URL");
            }

            images.push({
              id: String(image.id || ""),
              url,
            });
          }

          if (
            new Set(images.map((image) => image.url)).size !== images.length
          ) {
            return fail("Duplicate image URLs are not allowed");
          }

          // ================= VARIANTS =================

          const variantsEnabled = data.variantsEnabled === true;

          const rawVariants = variantsEnabled ? data.variants : [];

          if (
            !Array.isArray(rawVariants) ||
            rawVariants.length > 100 ||
            (variantsEnabled && !rawVariants.length)
          ) {
            return fail("Invalid variants (maximum 100)");
          }

          const variants = [];

          for (const variant of rawVariants) {
            if (!variant || typeof variant !== "object") {
              return fail("Invalid variant");
            }

            const variantSku = String(variant.sku || "")
              .trim()
              .toUpperCase();

            const variantPrice = Number(variant.price);
            const imageUrl = String(variant.imageUrl || "").trim();

            if (
              !variantSku ||
              !Number.isFinite(variantPrice) ||
              variantPrice <= 0 ||
              (imageUrl && !validUrl(imageUrl))
            ) {
              return fail("Invalid variant SKU, price or image URL");
            }

            variants.push({
              key: String(variant.key || ""),
              title: String(variant.title || ""),
              options: {
                size: String(variant.options?.size || ""),
                color: String(variant.options?.color || ""),
                type: String(variant.options?.type || ""),
              },
              sku: variantSku,
              autoSku: variant.autoSku === true,
              price: variantPrice,
              imageUrl,
              available: variant.available !== false,
            });
          }

          // ================= DUPLICATE SKU =================

          const allSkus = [sku, ...variants.map((variant) => variant.sku)];

          if (new Set(allSkus).size !== allSkus.length) {
            return fail("Product and variant SKUs must be unique", 409);
          }

          const duplicateProduct = await products.findOne({
            _id: { $ne: id },
            $or: [
              { sku: { $in: allSkus } },
              { "variants.sku": { $in: allSkus } },
            ],
          });

          if (duplicateProduct) {
            return fail("Product or variant SKU already exists", 409);
          }

          // ================= OPTIONS =================

          if (
            !data.options ||
            typeof data.options !== "object" ||
            Array.isArray(data.options)
          ) {
            return fail("Invalid variant options");
          }

          const options = {};

          for (const type of ["size", "color", "type"]) {
            const group = data.options[type] || {};
            const values = group.values || [];

            if (!Array.isArray(values) || values.length > 100) {
              return fail("Invalid variant options");
            }

            if (
              values.some(
                (value) =>
                  typeof value?.id !== "string" ||
                  typeof value?.label !== "string" ||
                  !value.label.trim(),
              )
            ) {
              return fail("Invalid variant option value");
            }

            options[type] = {
              enabled: group.enabled === true,
              values: values.map((value) => ({
                id: value.id,
                label: value.label.trim(),
              })),
            };
          }

          // ================= VARIANT OVERRIDES =================

          if (
            !data.variantOverrides ||
            typeof data.variantOverrides !== "object" ||
            Array.isArray(data.variantOverrides)
          ) {
            return fail("Invalid variant overrides");
          }

          const variantOverrides = {};

          for (const [key, value] of Object.entries(data.variantOverrides)) {
            if (
              !key ||
              key.length > 200 ||
              !/^[a-zA-Z0-9_:|-]+$/.test(key) ||
              !value ||
              typeof value !== "object" ||
              Array.isArray(value)
            ) {
              return fail("Invalid variant override");
            }

            const overridePrice =
              value.price === "" || value.price == null
                ? ""
                : Number(value.price);

            const overrideImage = String(value.imageUrl || "").trim();

            if (
              (overridePrice !== "" &&
                (!Number.isFinite(overridePrice) || overridePrice <= 0)) ||
              (overrideImage && !validUrl(overrideImage))
            ) {
              return fail("Invalid variant override price or image");
            }

            variantOverrides[key] = {
              autoSku: value.autoSku !== false,
              sku: String(value.sku || "")
                .trim()
                .toUpperCase(),
              price: overridePrice,
              imageUrl: overrideImage,
              available: value.available !== false,
            };
          }

          // ================= PACKAGING =================

          const premiumBoxPrice = Number(data.premiumBoxPrice);

          if (!Number.isFinite(premiumBoxPrice) || premiumBoxPrice < 0) {
            return fail("Invalid premium box price");
          }

          // ================= CUSTOMIZATION =================

          const customizable = data.customizable === true;

          const customerFieldType =
            customizable && ["frame", "note"].includes(data.customerFieldType)
              ? data.customerFieldType
              : "none";

          const customerFields =
            customerFieldType === "frame"
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
              : customerFieldType === "note"
                ? [
                    {
                      key: "customNote",
                      label: "বিশেষ নির্দেশনা",
                      type: "textarea",
                    },
                  ]
                : [];

          // ================= UPDATED DOCUMENT =================
          const updatedProduct = {
            name,
            sku,
            autoSku: data.autoSku === true,
            description,

            regularPrice,
            salePrice,

            categoryId,
            occasionIds,
            images,

            available: data.available === true,
            featured: data.featured === true,
            customizable,

            variantsEnabled,
            options,
            variantOverrides,
            variants,

            customerFieldType,
            customerFields,

            surpriseBox: data.surpriseBox === true,
            packaging: data.packaging === "premium" ? "premium" : "regular",
            premiumBoxPrice,

            updatedAt: new Date(),
            updatedBy: req.user.uid,
          };

          // Preserve original _id, slug, createdAt and createdBy
          await products.updateOne(
            { _id: id },
            {
              $set: updatedProduct,
            },
          );

          return res.status(200).send({
            success: true,
            message: "Product updated successfully",
            updatedId: productId,
          });
        } catch (error) {
          console.error("Update Product Error:", error);

          return res.status(error.code === 11000 ? 409 : 500).send({
            success: false,
            message:
              error.code === 11000
                ? "Duplicate SKU"
                : "Failed to update product",
          });
        }
      },
    );

    // ================= PATCH AVAILABILITY =================
    app.patch(
      "/admin/products/:productId/availability",
      verifyFirebaseToken,
      verifyAdmin,
      async (req, res) => {
        try {
          const { productId } = req.params;
          const { available } = req.body || {};

          if (!ObjectId.isValid(productId)) {
            return res.status(400).send({
              success: false,
              message: "Invalid product ID",
            });
          }

          if (typeof available !== "boolean") {
            return res.status(400).send({
              success: false,
              message: "Available must be true or false",
            });
          }

          const result = await products.updateOne(
            { _id: new ObjectId(productId) },
            {
              $set: {
                available,
                updatedAt: new Date(),
              },
            },
          );

          if (!result.matchedCount) {
            return res.status(404).send({
              success: false,
              message: "Product not found",
            });
          }

          return res.send({
            success: true,
            message: "Product availability updated",
            available,
          });
        } catch (error) {
          console.error("Update Availability Error:", error);

          return res.status(500).send({
            success: false,
            message: "Failed to update availability",
          });
        }
      },
    );

    // ================= DELETE PRODUCT =================
    app.delete(
      "/admin/products/:productId",
      verifyFirebaseToken,
      verifyAdmin,
      async (req, res) => {
        try {
          const { productId } = req.params;

          if (!ObjectId.isValid(productId)) {
            return res.status(400).send({
              success: false,
              message: "Invalid product ID",
            });
          }

          const result = await products.deleteOne({
            _id: new ObjectId(productId),
          });

          if (!result.deletedCount) {
            return res.status(404).send({
              success: false,
              message: "Product not found",
            });
          }

          return res.send({
            success: true,
            message: "Product deleted successfully",
          });
        } catch (error) {
          console.error("Delete Product Error:", error);

          return res.status(500).send({
            success: false,
            message: "Failed to delete product",
          });
        }
      },
    );

    

    // =============================================
    // PUBLIC GET SINGLE PRODUCT BY ID OR SLUG
    // GET /products/:identifier
    // =============================================

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
      variantsEnabled: 1,
      options: 1,
      variants: 1,
      customerFieldType: 1,
      customerFields: 1,
      surpriseBox: 1,
      packaging: 1,
      premiumBoxPrice: 1,
      rating: 1,
      reviewCount: 1,
    };

    const getPublicProduct = async (identifier) => {
      const value = String(identifier || "").trim();

      if (!value || value.length > 200) {
        return null;
      }

      const isMongoId = /^[a-fA-F0-9]{24}$/.test(value);

      const identifierQuery = isMongoId
        ? {
            $or: [
              { _id: new ObjectId(value) },
              { slug: value },
            ],
          }
        : { slug: value };

      return products.findOne(
        {
          status: "published",
          ...identifierQuery,
        },
        {
          projection: publicProductProjection,
        }
      );
    };

    // Related route must come before the single-product route.

    app.get("/products/:identifier/related", async (req, res) => {
      try {
        const product = await getPublicProduct(
          req.params.identifier
        );

        if (!product) {
          return res.status(404).send({
            success: false,
            message: "Product not found",
          });
        }

        const relatedProducts = await products
          .find(
            {
              _id: { $ne: product._id },
              categoryId: product.categoryId,
              status: "published",
              available: true,
            },
            {
              projection: publicProductProjection,
            }
          )
          .sort({ featured: -1, createdAt: -1 })
          .limit(4)
          .toArray();

        return res.status(200).send({
          success: true,
          products: relatedProducts.map((item) => ({
            ...item,
            _id: item._id.toString(),
          })),
        });
      } catch (error) {
        console.error("Related Products Error:", error);

        return res.status(500).send({
          success: false,
          message: "Failed to fetch related products",
        });
      }
    });

    app.get("/products/:identifier", async (req, res) => {
      try {
        const product = await getPublicProduct(
          req.params.identifier
        );

        if (!product) {
          return res.status(404).send({
            success: false,
            message: "Product not found",
          });
        }

        res.set("Cache-Control", "no-store");

        return res.status(200).send({
          success: true,
          product: {
            ...product,
            _id: product._id.toString(),
          },
        });
      } catch (error) {
        console.error("Get Product Details Error:", error);

        return res.status(500).send({
          success: false,
          message: "Failed to fetch product details",
        });
      }
    });



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
