const express = require("express");
const cors = require("cors");
require("dotenv").config();
const app = express();
const { MongoClient, ServerApiVersion, ObjectId } = require("mongodb");
const port = process.env.PORT || 3000;

const {
  makeSearchLatin,
  buildProductSearchTerms,
  buildPublicSearchConditions,
  makeSearchRegex,
} = require("./utils/productSearch");

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
  await client.connect();

  const DB = client.db("sokhBilash");
  const users = DB.collection("users");
  const categories = DB.collection("categories");
  const occasions = DB.collection("occasions");
  const products = DB.collection("products");

  // ==========================================
  // COMMON HELPERS
  // ==========================================

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
  // DEFAULT CATEGORIES & OCCASIONS
  // ==========================================

  const DEFAULT_CATEGORIES = [
    ["photo-frames", "ফটো ফ্রেম ও স্মৃতির উপহার", "Photo+Frames"],
    ["magic-mirror-led", "ম্যাজিক মিরর ও LED গিফট", "Magic+Mirror"],
    ["personalized", "কাস্টমাইজড ও পার্সোনালাইজড গিফট", "Personalized+Gifts"],
    ["gift-combos", "গিফট কম্বো ও হ্যাম্পার", "Gift+Combos"],
    ["flowers", "ফুল ও বুকেট", "Flowers"],
    ["chocolates", "চকলেট ও মিষ্টির উপহার", "Chocolates"],
    ["clothing", "পোশাক ও কাপল সেট", "Clothing"],
    ["party-decorations", "পার্টি ও অনুষ্ঠানের সাজসজ্জা", "Party+Decorations"],
    ["islamic", "ইসলামিক ও নিকাহ উপহার", "Islamic+Gifts"],
    ["romantic-gifts", "টেডি বেয়ার ও রোমান্টিক গিফট", "Romantic+Gifts"],
    ["others", "অন্যান্য (Others)", "Other+Gifts"],
  ];

  const DEFAULT_OCCASIONS = [
    ["birthday", "জন্মদিন", "Birthday"],
    ["anniversary", "বিবাহবার্ষিকী", "Anniversary"],
    ["wedding-nikah", "বিয়ে ও নিকাহ", "Wedding+Nikah"],
    ["love-romance", "ভালোবাসা ও রোমান্স", "Love+Romance"],
    ["islamic", "ইসলামিক উপলক্ষ", "Islamic+Occasions"],
    ["parents-day", "বাবা-মা দিবস", "Parents+Day"],
    ["congratulations", "অভিনন্দন ও অর্জন", "Congratulations"],
    ["surprise", "সারপ্রাইজ ও বিশেষ মুহূর্ত", "Surprise"],
  ];

  // ==========================================
  // SEED CATEGORIES & OCCASIONS
  // ==========================================

  const seedTaxonomy = async (collection, entries) => {
    if (!entries.length) return;

    await collection.bulkWrite(
      entries.flatMap(([id, name, imageText], index) => {
        const imageUrl = `https://placehold.co/800x600/F8F5FA/310039/png?text=${imageText}`;

        return [
          {
            updateOne: {
              filter: { id },

              update: {
                $setOnInsert: {
                  id,
                  name,
                  imageUrl,
                  sortOrder: index + 1,
                },
              },

              upsert: true,
            },
          },
          {
            updateOne: {
              filter: {
                id,

                $or: [
                  { imageUrl: { $exists: false } },
                  { imageUrl: "" },
                  { imageUrl: null },
                ],
              },

              update: {
                $set: { imageUrl },
              },
            },
          },
        ];
      }),
    );
  };

  await Promise.all([
    seedTaxonomy(categories, DEFAULT_CATEGORIES),
    seedTaxonomy(occasions, DEFAULT_OCCASIONS),
  ]);

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
  // PUBLIC CATEGORY API
  // ==========================================

  app.get("/categories", async (_req, res) => {
    try {
      const result = await categories
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
        .sort({ sortOrder: 1 })
        .toArray();

      return res.send({
        success: true,
        categories: result,
      });
    } catch (error) {
      return respondError(res, error, "Get Categories Error");
    }
  });

  // ==========================================
  // PUBLIC OCCASIONS API
  // ==========================================

  app.get("/occasions", async (_req, res) => {
    try {
      const result = await occasions
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
        .sort({ sortOrder: 1 })
        .toArray();

      return res.send({
        success: true,
        occasions: result,
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

  // ==========================================
  // SHARED PRODUCT VALIDATION
  // Used by POST and PATCH
  // ==========================================

  const buildValidatedProduct = async (data, existing = null) => {
    const name = String(data.name || "").trim();
    const sku = normalizeSku(data.sku);

    const description = String(data.description || "").trim();

    const categoryId = String(data.categoryId || "").trim();

    const occasionIds = data.occasionIds;

    const regularPrice = Number(data.regularPrice);

    const salePrice =
      data.salePrice == null || data.salePrice === ""
        ? null
        : Number(data.salePrice);

    // ============== BASIC VALIDATION ==============

    if (!name || !sku || !categoryId) {
      reject("Product name, SKU and category are required");
    }

    if (!Number.isFinite(regularPrice) || regularPrice <= 0) {
      reject("Invalid regular price");
    }

    if (
      salePrice !== null &&
      (!Number.isFinite(salePrice) ||
        salePrice <= 0 ||
        salePrice >= regularPrice)
    ) {
      reject("Sale price must be lower than regular price");
    }

    // ============== CATEGORY ==============

    const category = await categories.findOne(
      { id: categoryId },
      { projection: { _id: 1 } },
    );

    if (!category) {
      reject("Invalid category selected");
    }

    // ============== OCCASIONS ==============

    if (
      !Array.isArray(occasionIds) ||
      !occasionIds.length ||
      occasionIds.some((id) => typeof id !== "string" || !id.trim()) ||
      new Set(occasionIds).size !== occasionIds.length
    ) {
      reject("Select at least one valid occasion");
    }

    const occasionCount = await occasions.countDocuments({
      id: { $in: occasionIds },
    });

    if (occasionCount !== occasionIds.length) {
      reject("Invalid occasion selected");
    }

    // ============== IMAGES ==============

    if (
      !Array.isArray(data.images) ||
      !data.images.length ||
      data.images.length > 5
    ) {
      reject("Provide 1 to 5 valid product images");
    }

    const images = data.images.map((image) => ({
      id: String(image?.id || ""),
      url: String(image?.url || "").trim(),
    }));

    if (images.some((image) => !isValidUrl(image.url))) {
      reject("Invalid product image URL");
    }

    if (new Set(images.map((image) => image.url)).size !== images.length) {
      reject("Duplicate image URLs are not allowed");
    }

    // ============== VARIANTS ==============

    const variantsEnabled = data.variantsEnabled === true;

    const rawVariants = variantsEnabled ? data.variants : [];

    if (
      !Array.isArray(rawVariants) ||
      rawVariants.length > 100 ||
      (variantsEnabled && rawVariants.length === 0)
    ) {
      reject("Invalid variants (maximum 100)");
    }

    const variants = rawVariants.map((variant) => ({
      key: String(variant?.key || ""),
      title: String(variant?.title || ""),

      options: {
        size: String(variant?.options?.size || ""),

        color: String(variant?.options?.color || ""),

        type: String(variant?.options?.type || ""),
      },

      sku: normalizeSku(variant?.sku),

      autoSku: variant?.autoSku === true,

      price: Number(variant?.price),

      imageUrl: String(variant?.imageUrl || "").trim(),

      available: variant?.available !== false,
    }));

    for (const variant of variants) {
      if (
        !variant.sku ||
        !Number.isFinite(variant.price) ||
        variant.price <= 0 ||
        (variant.imageUrl && !isValidUrl(variant.imageUrl))
      ) {
        reject("Invalid variant SKU, price or image URL");
      }
    }

    // ============== UNIQUE SKU ==============

    const allSkus = [sku, ...variants.map((variant) => variant.sku)];

    if (new Set(allSkus).size !== allSkus.length) {
      reject("Product and variant SKUs must be unique", 409);
    }

    const duplicate = await products.findOne(
      {
        ...(existing ? { _id: { $ne: existing._id } } : {}),

        $or: [
          { sku: { $in: allSkus } },
          {
            "variants.sku": {
              $in: allSkus,
            },
          },
        ],
      },
      {
        projection: { _id: 1 },
      },
    );

    if (duplicate) {
      reject("Product or variant SKU already exists", 409);
    }

    // ============== VARIANT OPTIONS ==============

    const sourceOptions = data.options || {};

    if (typeof sourceOptions !== "object" || Array.isArray(sourceOptions)) {
      reject("Invalid variant options");
    }

    const options = {};

    for (const type of ["size", "color", "type"]) {
      const group = sourceOptions[type] || {};
      const values = group.values || [];

      if (
        !Array.isArray(values) ||
        values.length > 100 ||
        values.some(
          (value) =>
            typeof value?.id !== "string" ||
            typeof value?.label !== "string" ||
            !value.label.trim(),
        )
      ) {
        reject("Invalid variant option value");
      }

      options[type] = {
        enabled: group.enabled === true,

        values: values.map((value) => ({
          id: value.id,
          label: value.label.trim(),
        })),
      };
    }

    // ============== VARIANT OVERRIDES ==============

    const rawOverrides = data.variantOverrides || {};

    if (typeof rawOverrides !== "object" || Array.isArray(rawOverrides)) {
      reject("Invalid variant overrides");
    }

    const variantOverrides = {};

    for (const [key, value] of Object.entries(rawOverrides)) {
      if (
        !key ||
        key.length > 200 ||
        !/^[a-zA-Z0-9_:|-]+$/.test(key) ||
        !value ||
        typeof value !== "object" ||
        Array.isArray(value)
      ) {
        reject("Invalid variant override");
      }

      const price =
        value.price == null || value.price === "" ? "" : Number(value.price);

      const imageUrl = String(value.imageUrl || "").trim();

      if (
        (price !== "" && (!Number.isFinite(price) || price <= 0)) ||
        (imageUrl && !isValidUrl(imageUrl))
      ) {
        reject("Invalid variant override price or image");
      }

      variantOverrides[key] = {
        autoSku: value.autoSku !== false,

        sku: normalizeSku(value.sku),

        price,

        imageUrl,

        available: value.available !== false,
      };
    }

    // ============== PACKAGING ==============

    const premiumBoxPrice = Number(data.premiumBoxPrice);

    if (!Number.isFinite(premiumBoxPrice) || premiumBoxPrice < 0) {
      reject("Invalid premium box price");
    }

    // ============== CUSTOMIZATION ==============

    const customizable = data.customizable === true;

    const customerFieldType =
      customizable && ["frame", "note"].includes(data.customerFieldType)
        ? data.customerFieldType
        : "none";

    const customerFields = !customizable
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
        : customerFieldType === "note"
          ? [
              {
                key: "customNote",
                label: "বিশেষ নির্দেশনা",
                type: "textarea",
              },
            ]
          : [];

    // ============== FINAL PRODUCT FIELDS ==============

    return {
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
    };
  };

  // ==========================================
  // ADMIN ADD PRODUCT
  // POST /admin/products
  // ==========================================

  app.post(
    "/admin/products",
    verifyFirebaseToken,
    verifyAdmin,
    async (req, res) => {
      try {
        const document = await buildValidatedProduct(req.body || {});

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

        const result = await products.insertOne(product);

        return res.status(201).send({
          success: true,
          message: "Product added successfully",
          insertedId: result.insertedId.toString(),
          slug,
        });
      } catch (error) {
        return respondError(res, error, "Add Product Error");
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
  // GET SINGLE ADMIN PRODUCT
  // ==========================================

  app.get(
    "/admin/products/:productId",
    verifyFirebaseToken,
    verifyAdmin,
    async (req, res) => {
      try {
        const { productId } = req.params;

        if (!isMongoId(productId)) {
          return res.status(400).send({
            success: false,
            message: "Invalid product ID",
          });
        }

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

        res.set("Cache-Control", "no-store");

        return res.send({
          success: true,
          message: "Product fetched successfully",

          product: {
            ...product,
            _id: product._id.toString(),
          },
        });
      } catch (error) {
        return respondError(res, error, "Get Admin Product Error");
      }
    },
  );

  // ==========================================
  // ADMIN UPDATE PRODUCT
  // PATCH /admin/products/:productId
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
    "surpriseBox",

    "packaging",
    "premiumBoxPrice",
  ]);

  app.patch(
    "/admin/products/:productId",
    verifyFirebaseToken,
    verifyAdmin,
    async (req, res) => {
      try {
        const { productId } = req.params;

        if (!isMongoId(productId)) {
          reject("Invalid product ID");
        }

        if (
          !req.body ||
          typeof req.body !== "object" ||
          Array.isArray(req.body)
        ) {
          reject("Invalid request body");
        }

        const _id = new ObjectId(productId);

        const existing = await products.findOne({
          _id,
        });

        if (!existing) {
          reject("Product not found", 404);
        }

        const changes = Object.fromEntries(
          Object.entries(req.body).filter(([field]) =>
            PATCHABLE_FIELDS.has(field),
          ),
        );

        if (!Object.keys(changes).length) {
          reject("No valid fields to update");
        }

        const document = await buildValidatedProduct(
          {
            ...existing,
            ...changes,
          },
          existing,
        );

        const updatedProduct = {
          ...document,
          updatedBy: req.user.uid,
          updatedAt: new Date(),
        };

        Object.assign(
          updatedProduct,
          await getSearchFields({
            ...existing,
            ...updatedProduct,
          }),
        );

        await products.updateOne(
          { _id },
          {
            $set: updatedProduct,
          },
        );

        return res.send({
          success: true,
          message: "Product updated successfully",

          updatedId: productId,
        });
      } catch (error) {
        return respondError(res, error, "Update Product Error");
      }
    },
  );

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

  await client.db("admin").command({
    ping: 1,
  });

  console.log("SokhBilash MongoDB connected; routes initialized");
}
run().catch(console.dir);

app.get("/", (req, res) => {
  res.send("Successfully connected to SokhBilash");
});

app.listen(port, () => {
  console.log(`Example app listening on port ${port}`);
});
