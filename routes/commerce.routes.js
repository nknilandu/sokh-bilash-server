const { ObjectId } = require("mongodb");
const { getAuth } = require("firebase-admin/auth");
const { rateLimit } = require("express-rate-limit");

const {
  randomUUID,
  randomBytes,
  createHash,
  createHmac,
  timingSafeEqual,
} = require("node:crypto");

// ===========================================
// BANGLADESH DIVISIONS & DISTRICTS
// ===========================================

const DISTRICTS = require("../utils/bangladeshRegions");

// ===========================================
// MAIN ROUTE REGISTRATION
// ===========================================

module.exports = async function registerCommerceRoutes({
  app,
  DB,
  users,
  products,
  verifyFirebaseToken,
  verifyAdmin,
}) {
  const carts = DB.collection("carts");
  const orders = DB.collection("orders");

  const LIMIT_ITEMS = 100;
  const LIMIT_QTY = 10;
  const LIMIT_PHOTOS = 20;

  const guestSecret = process.env.ORDER_GUEST_TOKEN_SECRET;

  if (typeof guestSecret !== "string" || guestSecret.length < 32) {
    throw new Error(
      "ORDER_GUEST_TOKEN_SECRET must contain at least 32 characters",
    );
  }

  const allowedImageHosts = new Set(
    (process.env.CUSTOMER_IMAGE_HOSTS || "i.ibb.co")
      .split(",")
      .map((host) => host.trim().toLowerCase())
      .filter(Boolean),
  );

  // =========================================
  // DATABASE INDEXES & MIGRATION
  // =========================================

  // Populate transaction history keys for
  // existing orders that have a TrxID.
  //
  // Back up the database and check for
  // historical duplicate TrxIDs first.

  await orders.updateMany(
    {
      "payment.trxId": { $type: "string" },
      paymentTrxIds: { $exists: false },
    },
    [
      {
        $set: {
          paymentTrxIds: [
            {
              $concat: ["$payment.method", ":", "$payment.trxId"],
            },
          ],
        },
      },
    ],
  );

  await Promise.all([
    carts.createIndex({ uid: 1 }, { unique: true }),

    orders.createIndex({ checkoutId: 1 }, { unique: true }),

    orders.createIndex({ orderNumber: 1 }, { unique: true }),

    orders.createIndex(
      { paymentTrxIds: 1 },
      {
        unique: true,
        partialFilterExpression: {
          paymentTrxIds: { $exists: true },
        },
      },
    ),

    orders.createIndex({
      uid: 1,
      createdAt: -1,
    }),

    orders.createIndex({
      status: 1,
      createdAt: -1,
    }),

    orders.createIndex({
      "payment.status": 1,
      createdAt: -1,
    }),
  ]);

  // =========================================
  // RATE LIMITING
  // =========================================

  const limit = (max, message) =>
    rateLimit({
      windowMs: 15 * 60 * 1000,
      limit: max,
      standardHeaders: "draft-7",
      legacyHeaders: false,
      message: {
        success: false,
        message,
      },
    });

  const quoteLimit = limit(40, "Too many quote requests");

  const orderLimit = limit(8, "Too many order attempts");

  const trackingLimit = limit(5, "Too many tracking attempts");

  const proofLimit = limit(5, "Too many payment submissions");

  const lookupLimit = limit(10, "Too many order lookups");

  // =========================================
  // COMMON HELPERS
  // =========================================

  const fail = (message, status = 400) => {
    const error = new Error(message);
    error.status = status;
    throw error;
  };

  const handle = (fn) => async (req, res) => {
    try {
      await fn(req, res);
    } catch (error) {
      console.error("Commerce API:", error.message);

      const status = error.status || (error.code === 11000 ? 409 : 500);

      if (!res.headersSent) {
        res.status(status).json({
          success: false,
          message: error.status
            ? error.message
            : status === 409
              ? "Duplicate order or transaction information"
              : "Internal server error",
        });
      }
    }
  };

  const str = (value, max = 500) => {
    if (value == null) return "";

    if (typeof value !== "string") {
      fail("Invalid text value");
    }

    const clean = value.trim();

    if (clean.length > max) {
      fail(`Text exceeds ${max} characters`);
    }

    return clean;
  };

  const validObjectId = (value) => /^[a-f0-9]{24}$/i.test(String(value || ""));

  const requireId = (value) => {
    const id = str(value, 128);

    if (!/^[a-zA-Z0-9_-]{8,128}$/.test(id)) {
      fail("Invalid request ID");
    }

    return id;
  };

  // Secure UUID v4 only.
  const checkoutIdOf = (value) => {
    const id = requireId(value).toLowerCase();

    if (
      !/^[a-f\d]{8}-[a-f\d]{4}-4[a-f\d]{3}-[89ab][a-f\d]{3}-[a-f\d]{12}$/.test(
        id,
      )
    ) {
      fail("checkoutId must be UUID v4");
    }

    return id;
  };

  const currency = (value) =>
    Math.round((Number(value) + Number.EPSILON) * 100) / 100;

  // Strict amount validation.
  // Reject missing, negative, exponential,
  // invalid and >2-decimal amounts.

  const parseAmount = (value, label = "Amount") => {
    if (typeof value !== "string" && typeof value !== "number") {
      fail(`${label} required`);
    }

    if (!/^(?:0|[1-9]\d*)(?:\.\d{1,2})?$/.test(String(value))) {
      fail(`Invalid ${label}`);
    }

    const cents = Math.round(Number(value) * 100);

    if (!Number.isSafeInteger(cents) || cents <= 0) {
      fail(`Invalid ${label}`);
    }

    return cents / 100;
  };

  const digest = (input) => createHash("sha256").update(input).digest("hex");

  const guestToken = (checkoutId) =>
    createHmac("sha256", guestSecret)
      .update(`sokhbilash-guest-order:v1:${checkoutId}`)
      .digest("hex");

  const validHttpsUrl = (value) => {
    try {
      const url = new URL(value);

      return url.protocol === "https:" && !url.username && !url.password;
    } catch {
      return false;
    }
  };

  const validCustomerPhoto = (value) => {
    if (!validHttpsUrl(value)) {
      return false;
    }

    return allowedImageHosts.has(new URL(value).hostname.toLowerCase());
  };

  const orderFilter = (identifier) => {
    const value = str(identifier, 100);

    if (!value) {
      fail("Order identifier required");
    }

    if (validObjectId(value)) {
      return {
        $or: [
          {
            _id: new ObjectId(value),
          },
          {
            orderNumber: value,
          },
        ],
      };
    }

    return {
      orderNumber: value.toUpperCase(),
    };
  };

  // Never expose internal order secrets.

  const viewOrder = (doc) => {
    if (!doc) return null;

    const { checkoutId, guestTokenHash, paymentTrxIds, ...rest } = doc;

    return {
      ...rest,
      _id: rest._id.toString(),
    };
  };

  // =========================================
  // DELIVERY VALIDATION
  // =========================================

  const region = (customer) => {
    const division = str(customer?.division, 80);

    const district = str(customer?.district, 80);

    if (!DISTRICTS[division]?.includes(district)) {
      fail("Invalid division or district");
    }

    return {
      division,
      district,
    };
  };

  // =========================================
  // OPTIONAL FIREBASE AUTH
  // =========================================

  const optionalAuth = async (req, res, next) => {
    const header = req.headers.authorization;

    if (!header) {
      req.user = null;
      return next();
    }

    if (!header.startsWith("Bearer ")) {
      return res.status(401).json({
        success: false,
        message: "Invalid authorization header",
      });
    }

    try {
      req.user = await getAuth().verifyIdToken(header.slice(7).trim());

      return next();
    } catch {
      return res.status(401).json({
        success: false,
        message: "Invalid Firebase token",
      });
    }
  };

  // ==========================================
  // ALLOW GUEST OR ACTIVE CUSTOMER ONLY
  // BLOCK ADMIN FROM CHECKOUT AND ORDERS
  // ==========================================

  const customerOrGuest = async (req, res, next) => {
    // Guest customer (no Firebase account)
    if (!req.user) {
      return next();
    }

    try {
      const account = await users.findOne({
        uid: req.user.uid,
        role: "customer",
        status: "active",
      });

      if (!account) {
        return res.status(403).json({
          success: false,
          message:
            "Only customers can place orders. Admin accounts are not allowed.",
        });
      }

      req.account = account;
      return next();
    } catch (error) {
      console.error("Checkout role verification error:", error);

      return res.status(500).json({
        success: false,
        message: "Account verification failed",
      });
    }
  };

  // =========================================
  // ACTIVE ACCOUNT CHECK
  // =========================================

  const activeAccount = async (req, res, next) => {
    try {
      const account = await users.findOne({
        uid: req.user?.uid,
        status: "active",
        role: "customer",
      });

      if (!account) {
        return res.status(403).json({
          success: false,
          message: "Only active customers can use the shopping cart",
        });
      }

      req.account = account;
      return next();
    } catch (error) {
      console.error("Account verification error:", error);

      return res.status(500).json({
        success: false,
        message: "Account verification failed",
      });
    }
  };

  // =========================================
  // PRODUCT + VARIANT VALIDATION
  // =========================================

  const buildCartLine = async (raw) => {
    if (!raw || typeof raw !== "object" || Array.isArray(raw)) {
      fail("Invalid cart item");
    }

    const productId = str(raw.productId || raw.id, 50);

    if (!validObjectId(productId)) {
      fail("Invalid product ID");
    }

    const quantity = Number(raw.quantity ?? 1);

    if (!Number.isInteger(quantity) || quantity < 1 || quantity > LIMIT_QTY) {
      fail("Invalid quantity");
    }

    // Always load product from MongoDB.

    const product = await products.findOne({
      _id: new ObjectId(productId),
      status: "published",
    });

    if (!product) {
      fail("Product not found", 404);
    }

    if (product.available !== true) {
      fail("Product unavailable", 409);
    }

    // VARIANT

    let variant = null;
    let variantKey = "";

    if (product.variantsEnabled === true) {
      variantKey = str(raw.variantKey, 220);

      variant = (product.variants || []).find((v) => v.key === variantKey);

      if (!variant || variant.available === false) {
        fail("Variant unavailable", 409);
      }
    }

    // SERVER-SIDE PRICE

    const regularPrice = Number(product.regularPrice);

    const sale = Number(product.salePrice);

    if (!Number.isFinite(regularPrice) || regularPrice <= 0) {
      fail("Invalid product price", 409);
    }

    const basePrice =
      Number.isFinite(sale) && sale > 0 && sale < regularPrice
        ? sale
        : regularPrice;

    const variantPrice = variant ? Number(variant.price) : basePrice;

    if (!Number.isFinite(variantPrice) || variantPrice <= 0) {
      fail("Invalid variant price", 409);
    }

    // PACKAGING

    const packaging = raw.packaging ?? "regular";

    if (!["regular", "premium"].includes(packaging)) {
      fail("Invalid packaging");
    }

    const premiumBoxPrice = Number(product.premiumBoxPrice ?? 0);

    if (!Number.isFinite(premiumBoxPrice) || premiumBoxPrice < 0) {
      fail("Invalid packaging price", 409);
    }

    const extra = packaging === "premium" ? premiumBoxPrice : 0;

    const unitPrice = currency(variantPrice + extra);

    if (unitPrice <= 0) {
      fail("Invalid unit price", 409);
    }

    // =======================================
    // CUSTOMER CUSTOMIZATION
    // =======================================

    const custom = raw.customization ?? {};

    if (!custom || typeof custom !== "object" || Array.isArray(custom)) {
      fail("Invalid customization");
    }

    const mode =
      product.customizable === true &&
      ["frame", "note"].includes(product.customerFieldType)
        ? product.customerFieldType
        : "none";

    const customization = {
      mode,
      name: "",
      date: "",
      message: "",
      note: "",
      photos: [],
    };

    if (mode === "frame") {
      const photoList = custom.photos ?? [];

      const configuredLimit = Number(
        product.customerFields?.find((f) => f.key === "photos")?.maxFiles ??
          LIMIT_PHOTOS,
      );

      if (
        !Array.isArray(photoList) ||
        photoList.length > LIMIT_PHOTOS ||
        !Number.isInteger(configuredLimit) ||
        configuredLimit < 0 ||
        photoList.length > configuredLimit
      ) {
        fail("Too many customer photos");
      }

      customization.photos = photoList.map((photo) => {
        const url = str(photo?.url, 2048);

        const size = Number(photo?.size || 0);

        if (!validCustomerPhoto(url)) {
          fail("Unapproved customer image URL");
        }

        if (!Number.isFinite(size) || size < 0 || size > 10 * 1024 * 1024) {
          fail("Invalid photo size");
        }

        return {
          id: str(photo?.id, 100) || randomUUID(),

          name: str(photo?.name, 200),

          size,
          url,
        };
      });

      if (
        new Set(customization.photos.map((p) => p.url)).size !==
        customization.photos.length
      ) {
        fail("Duplicate customer photos");
      }

      customization.name = str(custom.name, 150);

      customization.date = str(custom.date, 20);

      customization.message = str(custom.message, 1000);

      if (
        customization.date &&
        !/^\d{4}-\d{2}-\d{2}$/.test(customization.date)
      ) {
        fail("Invalid customization date");
      }
    }

    if (mode === "note") {
      customization.note = str(custom.note, 2000);
    }

    // =======================================
    // CART ITEM IDENTITY
    // =======================================

    const surpriseBox =
      product.surpriseBox === true && raw.surpriseBox === true;

    const signature = digest(
      JSON.stringify({
        productId,
        variantKey,
        packaging,
        surpriseBox,
        mode,

        name: customization.name,

        date: customization.date,

        message: customization.message,

        note: customization.note,

        photoUrls: customization.photos.map((p) => p.url),
      }),
    );

    const image =
      variant?.imageUrl ||
      product.images?.[0]?.url ||
      (typeof product.images?.[0] === "string" ? product.images[0] : "");

    return {
      cartId:
        typeof raw.cartId === "string" &&
        /^[a-zA-Z0-9_-]{8,128}$/.test(raw.cartId)
          ? raw.cartId
          : randomUUID(),

      signature,
      productId,

      slug: product.slug || "",

      name: product.name,

      sku: variant?.sku || product.sku,

      image,
      quantity,

      variantKey,

      variantTitle: variant?.title || "",

      selectedOptions: variant
        ? {
            ...variant.options,
          }
        : {},

      packaging,

      premiumBoxPrice: extra,

      surpriseBox,
      customization,

      price: unitPrice,

      unitPrice,

      addedAt: new Date().toISOString(),
    };
  };

  // =========================================
  // CART ITEM MERGING
  // =========================================

  const combineLine = (lines, incoming) => {
    const old = lines.find((line) => line.signature === incoming.signature);

    if (old) {
      const quantity = old.quantity + incoming.quantity;

      if (quantity > LIMIT_QTY) {
        fail("Maximum 10 units per configuration", 409);
      }

      return lines.map((line) =>
        line.cartId === old.cartId
          ? {
              ...incoming,

              cartId: old.cartId,

              quantity,

              addedAt: old.addedAt,
            }
          : line,
      );
    }

    if (lines.length >= LIMIT_ITEMS) {
      fail("Cart limit reached", 409);
    }

    const cartId = lines.some((line) => line.cartId === incoming.cartId)
      ? randomUUID()
      : incoming.cartId;

    return [
      ...lines,
      {
        ...incoming,
        cartId,
      },
    ];
  };

  // =========================================
  // ATOMIC CART UPDATE
  // =========================================

  const mutateCart = async (uid, cb) => {
    for (let attempt = 0; attempt < 10; attempt++) {
      const current = await carts.findOne({
        uid,
      });

      const base = current || {
        uid,
        version: 0,
        items: [],
        mergeIds: [],
        operationIds: [],
      };

      const change = await cb({
        items: [...(base.items || [])],

        mergeIds: [...(base.mergeIds || [])],

        operationIds: [...(base.operationIds || [])],
      });

      if (change === null) {
        return base;
      }

      const data = {
        uid,

        items: change.items,

        mergeIds: change.mergeIds,

        operationIds: change.operationIds,

        updatedAt: new Date(),
      };

      if (!current) {
        try {
          await carts.insertOne({
            ...data,

            version: 1,

            createdAt: new Date(),
          });

          return {
            ...data,
            version: 1,
          };
        } catch (error) {
          if (error.code === 11000) {
            continue;
          }

          throw error;
        }
      }

      const result = await carts.updateOne(
        {
          uid,

          version: current.version,
        },
        {
          $set: data,

          $inc: {
            version: 1,
          },
        },
      );

      if (result.modifiedCount === 1) {
        return {
          ...data,

          version: current.version + 1,
        };
      }
    }

    fail("Cart is busy. Retry", 409);
  };

  const viewCart = async (uid) => {
    const doc = await carts.findOne({
      uid,
    });

    const hydrated = await Promise.all(
      (doc?.items || []).map(async (item) => {
        try {
          const fresh = await buildCartLine(item);

          return {
            ...fresh,

            cartId: item.cartId,

            addedAt: item.addedAt,

            unavailable: false,
          };
        } catch (error) {
          return {
            ...item,

            unavailable: true,

            unavailableReason: error.message,
          };
        }
      }),
    );

    return {
      items: hydrated,

      version: doc?.version || 0,

      totalQuantity: hydrated.reduce((sum, line) => sum + line.quantity, 0),

      subtotal: currency(
        hydrated
          .filter((l) => !l.unavailable)
          .reduce((sum, line) => sum + line.unitPrice * line.quantity, 0),
      ),
    };
  };

  // =========================================
  // GET CART
  // =========================================

  app.get(
    "/cart",
    verifyFirebaseToken,
    activeAccount,
    handle(async (req, res) => {
      res.set("Cache-Control", "no-store");

      res.json({
        success: true,

        ...(await viewCart(req.user.uid)),
      });
    }),
  );

  // =========================================
  // ADD TO CART
  // =========================================

  app.post(
    "/cart/items",
    verifyFirebaseToken,
    activeAccount,
    handle(async (req, res) => {
      const incoming = await buildCartLine(req.body.item || req.body);

      const requestId = req.body.requestId
        ? requireId(req.body.requestId)
        : null;

      await mutateCart(req.user.uid, (cart) => {
        if (requestId && cart.operationIds.includes(requestId)) {
          return null;
        }

        cart.items = combineLine(cart.items, incoming);

        if (requestId) {
          cart.operationIds = [...cart.operationIds, requestId].slice(-50);
        }

        return cart;
      });

      res.status(201).json({
        success: true,

        message: "Product added to cart",

        cart: await viewCart(req.user.uid),
      });
    }),
  );

  // =========================================
  // UPDATE CART CONFIGURATION
  // =========================================

  app.patch(
    "/cart/items/:cartId/configuration",
    verifyFirebaseToken,
    activeAccount,
    handle(async (req, res) => {
      const cartId = requireId(req.params.cartId);

      const validated = await buildCartLine({
        ...(req.body.item || req.body),

        cartId,
      });

      await mutateCart(req.user.uid, (cart) => {
        const index = cart.items.findIndex((line) => line.cartId === cartId);

        if (index < 0) {
          fail("Cart item not found", 404);
        }

        const previous = cart.items[index];

        if (previous.productId !== validated.productId) {
          fail("Cannot replace product while editing");
        }

        if (
          cart.items.some(
            (line, i) => i !== index && line.signature === validated.signature,
          )
        ) {
          fail("This configuration already exists in cart", 409);
        }

        cart.items[index] = {
          ...validated,

          cartId,

          addedAt: previous.addedAt,

          updatedAt: new Date().toISOString(),
        };

        return cart;
      });

      res.json({
        success: true,

        message: "Cart item updated",

        cart: await viewCart(req.user.uid),
      });
    }),
  );

  // =========================================
  // UPDATE QUANTITY
  // =========================================

  app.patch(
    "/cart/items/:cartId",
    verifyFirebaseToken,
    activeAccount,
    handle(async (req, res) => {
      const quantity = Number(req.body.quantity);

      if (!Number.isInteger(quantity) || quantity < 1 || quantity > LIMIT_QTY) {
        fail("Invalid quantity");
      }

      await mutateCart(req.user.uid, (cart) => {
        const item = cart.items.find(
          (line) => line.cartId === req.params.cartId,
        );

        if (!item) {
          fail("Cart item not found", 404);
        }

        cart.items = cart.items.map((line) =>
          line.cartId === item.cartId
            ? {
                ...line,
                quantity,
              }
            : line,
        );

        return cart;
      });

      res.json({
        success: true,

        cart: await viewCart(req.user.uid),
      });
    }),
  );

  // =========================================
  // REMOVE CART ITEM
  // =========================================

  app.delete(
    "/cart/items/:cartId",
    verifyFirebaseToken,
    activeAccount,
    handle(async (req, res) => {
      await mutateCart(req.user.uid, (cart) => {
        const previous = cart.items.length;

        cart.items = cart.items.filter(
          (line) => line.cartId !== req.params.cartId,
        );

        if (previous === cart.items.length) {
          fail("Cart item not found", 404);
        }

        return cart;
      });

      res.json({
        success: true,

        cart: await viewCart(req.user.uid),
      });
    }),
  );

  // =========================================
  // CLEAR CART
  // =========================================

  app.delete(
    "/cart",
    verifyFirebaseToken,
    activeAccount,
    handle(async (req, res) => {
      await mutateCart(req.user.uid, (cart) => ({
        ...cart,
        items: [],
      }));

      res.json({
        success: true,
        message: "Cart cleared",
      });
    }),
  );

  // =========================================
  // MERGE GUEST CART
  // =========================================

  // =========================================
  // MERGE GUEST CART
  // POST /cart/merge
  // =========================================

  app.post(
    "/cart/merge",
    verifyFirebaseToken,
    activeAccount,
    handle(async (req, res) => {
      const mergeId = requireId(req.body?.mergeId);
      const guestItems = req.body?.items;

      // ======================================
      // VALIDATE GUEST CART
      // ======================================

      if (!Array.isArray(guestItems) || guestItems.length > LIMIT_ITEMS) {
        fail("Invalid guest cart", 400);
      }

      // Revalidate each product using MongoDB.
      // Never trust guest-side prices.

      const validated = await Promise.all(guestItems.map(buildCartLine));

      // ======================================
      // MERGE STATUS
      // ======================================

      let alreadyMerged = false;

      // ======================================
      // ATOMIC CART MERGE
      // ======================================

      await mutateCart(req.user.uid, (cart) => {
        // Same mergeId already processed.
        // Do not merge the products again.

        if (cart.mergeIds.includes(mergeId)) {
          alreadyMerged = true;
          return null;
        }

        // This is a new merge attempt.
        // Reset when mutateCart retries.

        alreadyMerged = false;

        // ====================================
        // MERGE VALIDATED ITEMS
        // ====================================

        for (const line of validated) {
          const present = cart.items.some(
            (item) =>
              item.cartId === line.cartId && item.signature === line.signature,
          );

          if (!present) {
            cart.items = combineLine(cart.items, line);
          }
        }

        // ====================================
        // SAVE PROCESSED MERGE ID
        // ====================================

        cart.mergeIds = [...cart.mergeIds, mergeId].slice(-50);

        return cart;
      });

      // ======================================
      // RESPONSE
      // ======================================

      res.set("Cache-Control", "no-store");

      return res.status(200).json({
        success: true,

        message: alreadyMerged
          ? "Guest cart already merged"
          : "Guest cart merged successfully",

        alreadyMerged,

        cart: await viewCart(req.user.uid),
      });
    }),
  );

  // =========================================
  // VALIDATE CUSTOMER
  // =========================================

  const validateCustomer = (value) => {
    const input = value || {};

    const name = str(input.name, 150);

    const phone = str(input.phone, 30).replace(/\s/g, "");

    const address = str(input.address, 500);

    const note = str(input.note, 1000);

    const email = str(input.email, 200);

    const { division, district } = region(input);

    if (
      name.length < 2 ||
      !/^01[3-9]\d{8}$/.test(phone) ||
      address.length < 5
    ) {
      fail("Valid name, phone and address required");
    }

    if (email && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      fail("Invalid email");
    }

    return {
      name,
      phone,
      email,
      address,
      division,
      district,
      note,
    };
  };

  // ============================================
  // SAVED CHECKOUT PROFILE
  // Add INSIDE registerCommerceRoutes()
  // AFTER validateCustomer, BEFORE calculateQuote
  //
  // Existing variables used:
  // app, users, orders,
  // verifyFirebaseToken, activeAccount,
  // handle, validateCustomer, fail
  // ============================================

  const cleanProfileString = (value) =>
    typeof value === "string" ? value.trim() : "";

  // Database first:
  // 1. Saved checkout profile
  // 2. Customer's latest authenticated order
  // 3. Registered account name and phone
  //
  // Never expose order payment information here.

  const checkoutProfileView = async (account) => {
    const saved = account.checkoutProfile || {};

    const lastOrder = await orders.findOne(
      { uid: account.uid },
      {
        sort: { createdAt: -1 },
        projection: {
          _id: 0,
          customer: 1,
        },
      },
    );

    const previous = lastOrder?.customer || {};

    const pick = (...values) =>
      values.map(cleanProfileString).find(Boolean) || "";

    const savedRegionValid = Boolean(
      DISTRICTS[saved.division]?.includes(saved.district),
    );

    const previousRegionValid = Boolean(
      DISTRICTS[previous.division]?.includes(previous.district),
    );

    const division = savedRegionValid
      ? saved.division
      : previousRegionValid
        ? previous.division
        : "";

    const district = savedRegionValid
      ? saved.district
      : previousRegionValid
        ? previous.district
        : "";

    return {
      name: pick(saved.name, previous.name, account.displayName),

      phone: pick(saved.phone, previous.phone, account.phone),

      division,
      district,

      address: pick(saved.address, previous.address),
    };
  };

  // ============================================
  // GET /checkout/profile
  // Fetch only signed-in user's own profile.
  // ============================================

  app.get(
    "/checkout/profile",
    verifyFirebaseToken,
    activeAccount,
    handle(async (req, res) => {
      const account = await users.findOne(
        {
          uid: req.user.uid,
          status: "active",
        },
        {
          projection: {
            uid: 1,
            displayName: 1,
            phone: 1,
            checkoutProfile: 1,
          },
        },
      );

      if (!account) {
        fail("Account unavailable", 403);
      }

      const profile = await checkoutProfileView(account);

      res.set("Cache-Control", "no-store");

      return res.json({
        success: true,
        profile,
      });
    }),
  );

  // ============================================
  // POST /checkout/profile/merge-guest
  //
  // Fills only missing checkoutProfile fields.
  // Does not replace existing DB values.
  // Does not touch user role/email/payment.
  // ============================================

  const checkoutProfileMergeLimit = limit(12, "Too many profile sync requests");

  app.post(
    "/checkout/profile/merge-guest",
    checkoutProfileMergeLimit,
    verifyFirebaseToken,
    activeAccount,
    handle(async (req, res) => {
      const guest = req.body?.profile;

      // Revalidate browser-stored data.
      // localStorage is untrusted input.

      const validated = validateCustomer({
        name: guest?.name,
        phone: guest?.phone,
        address: guest?.address,
        division: guest?.division,
        district: guest?.district,
        note: "",
      });

      const account = await users.findOne(
        {
          uid: req.user.uid,
          status: "active",
        },
        {
          projection: {
            uid: 1,
            displayName: 1,
            phone: 1,
            checkoutProfile: 1,
          },
        },
      );

      if (!account) {
        fail("Account unavailable", 403);
      }

      const dbProfile = await checkoutProfileView(account);

      // If a value already exists in MongoDB or
      // a previous account order, prefer that.
      const candidate = {
        name: dbProfile.name || validated.name,
        phone: dbProfile.phone || validated.phone,

        division: dbProfile.division || validated.division,

        district: dbProfile.district || validated.district,

        address: dbProfile.address || validated.address,
      };

      // Atomic update: a concurrent request cannot
      // replace existing nonblank profile fields.

      const blank = (path) => ({
        $eq: [{ $ifNull: [path, ""] }, ""],
      });

      const fillOnlyBlank = (field, value) => ({
        $cond: [
          blank(`$checkoutProfile.${field}`),
          { $literal: value },
          `$checkoutProfile.${field}`,
        ],
      });

      // Division/District must remain a valid pair.
      // Never mix districts from unrelated divisions.

      const compatibleRegion = {
        $and: [
          {
            $in: [
              {
                $ifNull: ["$checkoutProfile.division", ""],
              },
              ["", candidate.division],
            ],
          },
          {
            $in: [
              {
                $ifNull: ["$checkoutProfile.district", ""],
              },
              ["", candidate.district],
            ],
          },
        ],
      };

      await users.updateOne(
        {
          uid: req.user.uid,
          status: "active",
        },
        [
          {
            $set: {
              "checkoutProfile.name": fillOnlyBlank("name", candidate.name),

              "checkoutProfile.phone": fillOnlyBlank("phone", candidate.phone),

              "checkoutProfile.address": fillOnlyBlank(
                "address",
                candidate.address,
              ),

              "checkoutProfile.division": {
                $cond: [
                  compatibleRegion,
                  fillOnlyBlank("division", candidate.division),
                  "$checkoutProfile.division",
                ],
              },

              "checkoutProfile.district": {
                $cond: [
                  compatibleRegion,
                  fillOnlyBlank("district", candidate.district),
                  "$checkoutProfile.district",
                ],
              },
            },
          },
        ],
      );

      const fresh = await users.findOne(
        {
          uid: req.user.uid,
          status: "active",
        },
        {
          projection: {
            uid: 1,
            displayName: 1,
            phone: 1,
            checkoutProfile: 1,
          },
        },
      );

      res.set("Cache-Control", "no-store");

      return res.json({
        success: true,
        profile: await checkoutProfileView(fresh),
      });
    }),
  );

  // =========================================
  // SERVER-SIDE CHECKOUT QUOTE
  // =========================================

  const calculateQuote = async ({
    items,
    customer,
    giftOptions,
    couponCode,
  }) => {
    if (
      !Array.isArray(items) ||
      items.length < 1 ||
      items.length > LIMIT_ITEMS
    ) {
      fail("Invalid checkout items");
    }

    if (couponCode) {
      fail("Coupons are not enabled");
    }

    const lines = await Promise.all(items.map(buildCartLine));

    const unique = new Set();

    for (const line of lines) {
      if (unique.has(line.signature)) {
        fail("Duplicate configuration in checkout");
      }

      unique.add(line.signature);
    }

    const subtotal = currency(
      lines.reduce((sum, line) => sum + line.unitPrice * line.quantity, 0),
    );

    const { district } = region(customer);

    const deliveryCharge = district === "নরসিংদী" ? 80 : 130;

    const options = giftOptions ?? {};

    if (typeof options !== "object" || Array.isArray(options)) {
      fail("Invalid gift options", 400);
    }

    if (
      options.giftWrap !== undefined &&
      typeof options.giftWrap !== "boolean"
    ) {
      fail("Invalid giftWrap", 400);
    }

    if (
      options.surpriseBox !== undefined &&
      typeof options.surpriseBox !== "boolean"
    ) {
      fail("Invalid surpriseBox", 400);
    }

    const giftWrap = options.giftWrap === true;
    const surpriseBox = options.surpriseBox === true;

    const giftWrapCharge = giftWrap ? 50 : 0;
    const message = str(options.message, 250);

    const total = currency(subtotal + deliveryCharge + giftWrapCharge);

    return {
      items: lines,
      subtotal,
      deliveryCharge,
      giftWrapCharge,

      giftOptions: {
        giftWrap,
        surpriseBox,
        message,
      },

      discount: 0,
      total,
    };
  };

  // =========================================
  // VALIDATE PAYMENT
  // =========================================

  const validatePayment = (input, total) => {
    const payment = input || {};

    const method = str(payment.method, 20).toLowerCase();

    if (!["bkash", "nagad", "rocket", "cod"].includes(method)) {
      fail("Invalid payment method");
    }

    if (method === "cod") {
      return {
        method,
        status: "cod_pending",

        senderPhone: null,

        trxId: null,

        claimedAmount: 0,

        verifiedAmount: 0,

        dueAmount: total,

        verifiedAt: null,

        verifiedBy: null,

        rejectedReason: null,
      };
    }

    const senderPhone = str(payment.senderPhone, 30).replace(/\s/g, "");

    const trxId = str(payment.trxId, 60).toUpperCase();

    if (
      !/^01[3-9]\d{8}$/.test(senderPhone) ||
      !/^[A-Z0-9_-]{5,60}$/.test(trxId)
    ) {
      fail("Invalid sender phone or TrxID");
    }

    const claimedAmount = parseAmount(payment.amount, "payment amount");

    if (claimedAmount > total) {
      fail("Claimed amount exceeds order total");
    }

    return {
      method,
      status: "pending",

      senderPhone,
      trxId,
      claimedAmount,

      note: str(payment.note, 200),

      verifiedAmount: 0,

      dueAmount: total,

      verifiedAt: null,

      verifiedBy: null,

      rejectedReason: null,
    };
  };

  // =========================================
  // POST /checkout/quote
  // =========================================

  app.post(
    "/checkout/quote",
    quoteLimit,
    optionalAuth,
    customerOrGuest,
    handle(async (req, res) => {
      res.set("Cache-Control", "no-store");

      res.json({
        success: true,
        ...(await calculateQuote(req.body)),
      });
    }),
  );
  // =========================================
  // GUEST IDEMPOTENCY RESPONSE
  // =========================================

  const answerExisting = (req, res, existing, checkoutId) => {
    const sameOwner = req.user?.uid && existing.uid === req.user.uid;

    const token = guestToken(checkoutId);

    const sameGuest =
      existing.guest === true && existing.guestTokenHash === digest(token);

    if (!sameOwner && !sameGuest) {
      fail("Checkout already submitted", 409);
    }

    res.set("Cache-Control", "no-store");

    return res.json({
      success: true,

      alreadyCreated: true,

      orderId: existing._id.toString(),

      orderNumber: existing.orderNumber,

      status: existing.status,

      paymentStatus: existing.payment?.status,

      total: existing.total,

      accessToken: sameGuest ? token : null,
    });
  };

  // =========================================
  // POST /orders
  // =========================================

  app.post(
    "/orders",
    orderLimit,
    optionalAuth,
    customerOrGuest,
    handle(async (req, res) => {
      const checkoutId = checkoutIdOf(req.body.checkoutId);

      const previous = await orders.findOne({
        checkoutId,
      });

      if (previous) {
        return answerExisting(req, res, previous, checkoutId);
      }

      let account = null;

      if (req.user) {
        account = await users.findOne({
          uid: req.user.uid,
          role: "customer",
          status: "active",
        });

        if (!account) {
          fail("Active account required", 403);
        }
      }

      const customer = validateCustomer(req.body.customer);

      if (account) {
        customer.email = req.user.email || account.email || "";
      }

      const quote = await calculateQuote({
        items: req.body.items,

        customer,

        giftOptions: req.body.giftOptions,

        couponCode: req.body.couponCode,
      });

      const payment = validatePayment(req.body.payment, quote.total);

      const now = new Date();

      const orderNumber =
        `SKB-${Date.now().toString(36).toUpperCase()}-` +
        randomBytes(4).toString("hex").toUpperCase();

      const accessToken = account ? null : guestToken(checkoutId);

      const order = {
        checkoutId,
        orderNumber,

        uid: account?.uid || null,

        guest: !account,

        customer,

        shipping: {
          recipientName: customer.name,

          phone: customer.phone,

          division: customer.division,

          district: customer.district,

          address: customer.address,

          note: customer.note,
        },

        items: quote.items.map((line) => ({
          ...line,

          lineTotal: currency(line.unitPrice * line.quantity),
        })),

        subtotal: quote.subtotal,

        deliveryCharge: quote.deliveryCharge,

        giftWrapCharge: quote.giftWrapCharge,

        giftOptions: quote.giftOptions,

        discount: 0,

        total: quote.total,

        payment,

        ...(payment.trxId
          ? {
              paymentTrxIds: [`${payment.method}:${payment.trxId}`],
            }
          : {}),

        status: "pending",

        phoneConfirmed: false,

        courier: {
          name: null,

          trackingNumber: null,

          trackingUrl: null,
        },

        estimatedDelivery: null,

        history: [
          {
            status: "placed",

            date: now,

            note: "Order successfully placed",

            by: "system",
          },
        ],

        guestTokenHash: accessToken ? digest(accessToken) : null,

        revision: 1,

        createdAt: now,

        updatedAt: now,
      };

      let result;

      try {
        result = await orders.insertOne(order);
      } catch (error) {
        if (error.code === 11000) {
          const first = await orders.findOne({
            checkoutId,
          });

          if (first) {
            return answerExisting(req, res, first, checkoutId);
          }

          fail("Duplicate order or TrxID", 409);
        }

        throw error;
      }

      // ============================================
      // SAVE LAST SUCCESSFUL CHECKOUT DETAILS
      // Registered customer only
      //
      // Place AFTER successful orders.insertOne()
      // and BEFORE account cart cleanup.
      // ============================================

      if (account) {
        try {
          await users.updateOne(
            {
              uid: account.uid,
              status: "active",
            },
            {
              $set: {
                checkoutProfile: {
                  name: customer.name,
                  phone: customer.phone,
                  division: customer.division,
                  district: customer.district,
                  address: customer.address,
                  updatedAt: new Date(),
                },
              },
            },
          );
        } catch (profileError) {
          // Order already exists; never create another
          // order just because profile saving failed.
          console.error(
            "Checkout profile update failed:",
            profileError.message,
          );
        }
      }

      // Remove purchased items from account cart.
      // Do not clear unrelated cart items.

      if (account) {
        try {
          await mutateCart(account.uid, (cart) => {
            const bought = new Map(
              quote.items.map((line) => [line.cartId, line]),
            );

            cart.items = cart.items.flatMap((line) => {
              const boughtLine = bought.get(line.cartId);

              if (!boughtLine || line.signature !== boughtLine.signature) {
                return [line];
              }

              const remaining = line.quantity - boughtLine.quantity;

              return remaining > 0
                ? [
                    {
                      ...line,
                      quantity: remaining,
                    },
                  ]
                : [];
            });

            return cart;
          });
        } catch (error) {
          console.error("Order cart cleanup failed:", error.message);
        }
      }

      res.set("Cache-Control", "no-store");

      res.status(201).json({
        success: true,

        message: "Order placed successfully",

        orderId: result.insertedId.toString(),

        orderNumber,

        status: "pending",

        paymentStatus: payment.status,

        total: quote.total,

        accessToken,
      });
    }),
  );

  // =========================================
  // SECURE ORDER ACCESS
  // =========================================

  const canReadOrder = (req, order, token) => {
    if (order.uid && req.user?.uid === order.uid) {
      return true;
    }

    if (
      order.guest !== true ||
      typeof token !== "string" ||
      !order.guestTokenHash ||
      !/^[a-f0-9]{64}$/i.test(token)
    ) {
      return false;
    }

    const stored = Buffer.from(order.guestTokenHash, "hex");

    const provided = Buffer.from(digest(token), "hex");

    return (
      stored.length === provided.length && timingSafeEqual(stored, provided)
    );
  };

  // =========================================
  // GET /orders/my
  // =========================================

  // ============================================
  // CUSTOMER ORDER HISTORY
  // GET /orders/my
  //
  // Security:
  // - Firebase verified identity only
  // - UID always comes from req.user
  // - No customer-supplied UID accepted
  // - Filter validation and pagination limits
  // - Minimal list response
  // - No phone, address, TrxID or customization
  // ============================================

  app.get(
    "/orders/my",
    verifyFirebaseToken,
    handle(async (req, res) => {
      // ========================================
      // AUTHENTICATION
      // ========================================

      const uid = req.user?.uid;

      if (!uid) {
        return res.status(401).json({
          success: false,
          message: "Authentication required",
        });
      }

      // Respect explicitly suspended accounts.
      // Accounts with legacy missing status
      // can still access their own order history.

      const account = await users.findOne(
        { uid },
        { projection: { status: 1 } },
      );

      const blockedStatuses = new Set([
        "blocked",
        "suspended",
        "disabled",
        "banned",
      ]);

      if (account && blockedStatuses.has(account.status)) {
        return res.status(403).json({
          success: false,
          message: "Account access restricted",
        });
      }

      // ========================================
      // PAGINATION VALIDATION
      // ========================================

      const rawPage = req.query.page === undefined ? "1" : req.query.page;

      if (
        typeof rawPage !== "string" ||
        !/^[0-9]{1,5}$/.test(rawPage) ||
        Number(rawPage) < 1
      ) {
        fail("Invalid page number", 400);
      }

      const page = Math.min(10000, Number(rawPage));

      const perPage = 10;

      const skip = (page - 1) * perPage;

      // ========================================
      // SAFE QUERY PARAMETERS
      // ========================================

      const readFilter = (value, maxLength = 60) => {
        if (value === undefined) return "";

        if (typeof value !== "string") {
          fail("Invalid filter parameter", 400);
        }

        return str(value, maxLength);
      };

      const status = readFilter(req.query.status, 40).toLowerCase();

      const paymentStatus = readFilter(
        req.query.paymentStatus,
        40,
      ).toLowerCase();

      const search = readFilter(req.query.search, 60)
        .replace(/^#/, "")
        .toUpperCase();

      // ========================================
      // STATUS ALLOWLIST
      // ========================================

      const allowedOrderStatuses = new Set([
        "pending",
        "verified",
        "processing",
        "shipped",
        "delivered",
        "rejected",
        "cancelled",
      ]);

      const allowedPaymentStatuses = new Set([
        "pending",
        "cod_pending",
        "partially_paid",
        "verified",
        "rejected",
      ]);

      if (status && status !== "all" && !allowedOrderStatuses.has(status)) {
        fail("Invalid order status filter", 400);
      }

      if (
        paymentStatus &&
        paymentStatus !== "all" &&
        !allowedPaymentStatuses.has(paymentStatus)
      ) {
        fail("Invalid payment status filter", 400);
      }

      // Order numbers consist of uppercase
      // alphanumeric characters and hyphens.

      if (search && !/^[A-Z0-9-]{1,60}$/.test(search)) {
        fail("Invalid order number search", 400);
      }

      // ========================================
      // OWNER-SCOPED MONGODB QUERY
      // ========================================

      const query = {
        uid,
      };

      if (status && status !== "all") {
        query.status = status;
      }

      if (paymentStatus && paymentStatus !== "all") {
        query["payment.status"] = paymentStatus;
      }

      if (search) {
        // Safe prefix search.
        // No arbitrary regex operators are
        // accepted from the frontend.

        query.orderNumber = new RegExp(`^${search}`);
      }

      // ========================================
      // MINIMAL FIELD PROJECTION
      // ========================================

      const projection = {
        _id: 1,
        orderNumber: 1,
        createdAt: 1,
        status: 1,
        total: 1,

        "payment.method": 1,
        "payment.status": 1,

        "items.name": 1,
        "items.image": 1,
        "items.quantity": 1,
      };

      // ========================================
      // DATABASE QUERIES
      // ========================================

      const [orderDocuments, filteredTotal, statusCounts] = await Promise.all([
        // Current page

        orders
          .find(query, { projection })
          .sort({
            createdAt: -1,
            _id: -1,
          })
          .skip(skip)
          .limit(perPage)
          .toArray(),

        // Total after filters

        orders.countDocuments(query),

        // Stats across ALL current user's
        // orders, independent of filters.

        orders
          .aggregate([
            {
              $match: {
                uid,
              },
            },
            {
              $group: {
                _id: "$status",
                count: {
                  $sum: 1,
                },
              },
            },
          ])
          .toArray(),
      ]);

      // ========================================
      // FORMAT ORDER LIST
      // ========================================

      const formattedOrders = orderDocuments.map((order) => {
        const items = Array.isArray(order.items) ? order.items : [];

        const itemCount = items.reduce(
          (sum, item) => sum + (Number(item.quantity) || 0),
          0,
        );

        const previewItems = items.slice(0, 2).map((item) => ({
          name: item.name || "",
          image: item.image || "",
          quantity: Number(item.quantity) || 1,
        }));

        return {
          _id: order._id.toString(),
          orderNumber: order.orderNumber,

          createdAt: order.createdAt,
          status: order.status,

          total: Number(order.total) || 0,

          payment: {
            method: order.payment?.method || null,

            status: order.payment?.status || null,
          },

          itemCount,
          previewItems,
        };
      });

      // ========================================
      // FORMAT STATISTICS
      // ========================================

      const counts = Object.fromEntries(
        statusCounts.map((item) => [item._id, item.count]),
      );

      const totalOrders = statusCounts.reduce(
        (sum, item) => sum + item.count,
        0,
      );

      const stats = {
        total: totalOrders,

        pending: counts.pending || 0,

        verified: counts.verified || 0,

        processing: counts.processing || 0,

        shipped: counts.shipped || 0,

        delivered: counts.delivered || 0,

        cancelled: (counts.cancelled || 0) + (counts.rejected || 0),
      };

      // ========================================
      // RESPONSE
      // ========================================

      res.set("Cache-Control", "no-store");

      return res.status(200).json({
        success: true,

        orders: formattedOrders,

        stats,

        pagination: {
          page,
          limit: perPage,

          total: filteredTotal,

          totalPages: Math.ceil(filteredTotal / perPage),

          hasNextPage: page * perPage < filteredTotal,

          hasPreviousPage: page > 1,
        },
      });
    }),
  );

  // =========================================
  // POST /orders/lookup
  // =========================================

  app.post(
    "/orders/lookup",
    lookupLimit,
    optionalAuth,
    handle(async (req, res) => {
      const order = await orders.findOne(orderFilter(req.body?.orderNumber));

      if (
        !order ||
        !canReadOrder(
          req,
          order,
          req.headers["x-order-access-token"] || req.body?.accessToken,
        )
      ) {
        fail("Order not found or access denied", 404);
      }

      res.set("Cache-Control", "no-store");

      res.json({
        success: true,

        order: viewOrder(order),
      });
    }),
  );

  // =========================================
  // POST /orders/public/track
  // =========================================

  app.post(
    "/orders/public/track",
    trackingLimit,
    handle(async (req, res) => {
      const phone = str(req.body?.phone, 30).replace(/\s/g, "");

      const identifier = str(req.body?.orderNumber, 100);

      const deny = () =>
        res.status(404).json({
          success: false,

          message: "Order not found or access denied",
        });

      if (!identifier || !/^01[3-9]\d{8}$/.test(phone)) {
        return deny();
      }

      const order = await orders.findOne({
        ...orderFilter(identifier),

        "customer.phone": phone,
      });

      if (!order) {
        return deny();
      }

      res.set("Cache-Control", "no-store");

      res.json({
        success: true,

        visibility: "limited",

        order: {
          orderNumber: order.orderNumber,

          createdAt: order.createdAt,

          status: order.status,

          phoneConfirmed: order.phoneConfirmed === true,

          payment: {
            method: order.payment?.method || null,

            status: order.payment?.status || null,
          },

          estimatedDelivery: order.estimatedDelivery || null,

          history: (order.history || []).slice(-15).map((h) => ({
            status: h.status,

            date: h.date,
          })),
        },
      });
    }),
  );

  // =========================================
  // GET /orders/:identifier
  // =========================================

  app.get(
    "/orders/:identifier",
    optionalAuth,
    handle(async (req, res) => {
      const order = await orders.findOne(orderFilter(req.params.identifier));

      if (
        !order ||
        !canReadOrder(req, order, req.headers["x-order-access-token"])
      ) {
        fail("Order not found or access denied", 404);
      }

      res.set("Cache-Control", "no-store");

      res.json({
        success: true,

        order: viewOrder(order),
      });
    }),
  );

  // =========================================
  // ATOMIC ORDER UPDATE
  // =========================================

  const updateOrder = async (identifier, buildChange) => {
    for (let i = 0; i < 8; i++) {
      const previous = await orders.findOne(orderFilter(identifier));

      if (!previous) {
        fail("Order not found", 404);
      }

      const change = await buildChange(previous);

      if (!change?.set) {
        fail("No changes supplied");
      }

      const now = new Date();

      const result = await orders.updateOne(
        {
          _id: previous._id,

          revision: previous.revision,
        },
        {
          $set: {
            ...change.set,

            updatedAt: now,
          },

          $inc: {
            revision: 1,
          },

          $push: {
            history: {
              status: change.event,

              note: change.note || "",

              by: change.by || "system",

              date: now,
            },
          },
        },
      );

      if (result.modifiedCount === 1) {
        return orders.findOne({
          _id: previous._id,
        });
      }
    }

    fail("Order changed concurrently; retry", 409);
  };

  // =========================================
  // POST /orders/:identifier/payment-proof
  // =========================================

  app.post(
    "/orders/:identifier/payment-proof",
    proofLimit,
    optionalAuth,
    handle(async (req, res) => {
      const updated = await updateOrder(
        req.params.identifier,

        (order) => {
          if (!canReadOrder(req, order, req.headers["x-order-access-token"])) {
            fail("Access denied", 403);
          }

          if (
            order.payment.method === "cod" ||
            order.payment.status !== "rejected" ||
            order.status !== "rejected"
          ) {
            fail("Cannot resubmit payment for this order", 409);
          }

          const payment = validatePayment(
            {
              ...req.body,

              method: order.payment.method,
            },

            order.total,
          );

          const verified = currency(order.payment.verifiedAmount || 0);

          if (payment.claimedAmount > currency(order.total - verified)) {
            fail("Claim exceeds remaining due");
          }

          const trxKey = `${payment.method}:${payment.trxId}`;

          if ((order.paymentTrxIds || []).includes(trxKey)) {
            fail("Previously submitted TrxID", 409);
          }

          return {
            set: {
              payment: {
                ...payment,

                verifiedAmount: verified,

                dueAmount: currency(order.total - verified),

                status: verified > 0 ? "partially_paid" : "pending",
              },

              paymentTrxIds: [...(order.paymentTrxIds || []), trxKey],

              status: "pending",
            },

            event: "payment_resubmitted",

            note: "Customer resubmitted payment proof",

            by: order.uid || "guest",
          };
        },
      );

      res.set("Cache-Control", "no-store");

      res.json({
        success: true,

        order: viewOrder(updated),
      });
    }),
  );

  // =========================================
  // ADMIN ORDER/PAYMENT LISTS
  // =========================================

  const listAdmin = (kind) => [
    verifyFirebaseToken,

    verifyAdmin,

    handle(async (req, res) => {
      const page = Math.min(
        10000,

        Math.max(
          1,

          parseInt(req.query.page, 10) || 1,
        ),
      );

      const filter = {};

      const status = str(req.query.status, 40);

      const method = str(req.query.method, 20);

      const search = str(req.query.search, 100);

      if (status && status !== "all") {
        filter[kind === "payments" ? "payment.status" : "status"] = status;
      }

      if (method && method !== "all" && kind === "payments") {
        filter["payment.method"] = method;
      }

      if (search && kind === "orders") {
        const escaped = search.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

        const rx = new RegExp(escaped, "i");

        filter.$or = [
          {
            orderNumber: rx,
          },

          {
            "customer.name": rx,
          },

          {
            "customer.phone": rx,
          },

          {
            "payment.trxId": rx,
          },
        ];
      }

      const [docs, total] = await Promise.all([
        orders
          .find(filter)
          .sort({
            createdAt: -1,
          })
          .skip((page - 1) * 10)
          .limit(10)
          .toArray(),

        orders.countDocuments(filter),
      ]);

      res.set("Cache-Control", "no-store");

      res.json({
        success: true,

        [kind]: docs.map(viewOrder),

        pagination: {
          page,

          limit: 10,

          total,

          totalPages: Math.ceil(total / 10),
        },
      });
    }),
  ];

  // ==========================================
  // ADMIN ORDERS LIST
  // Guest + Customer
  // Search, Filter, Pagination, Global Stats
  // ==========================================

  app.get(
    "/admin/orders",
    verifyFirebaseToken,
    verifyAdmin,
    handle(async (req, res) => {
      const page = Math.min(
        10000,
        Math.max(1, parseInt(req.query.page, 10) || 1),
      );

      const perPage = 10;

      const status = str(req.query.status, 30).toLowerCase();
      const method = str(req.query.method, 20).toLowerCase();
      const date = str(req.query.date, 20).toLowerCase();
      const search = str(req.query.search, 100);

      const allowedStatuses = [
        "all",
        "pending",
        "verified",
        "processing",
        "shipped",
        "delivered",
        "rejected",
        "cancelled",
      ];

      const allowedMethods = ["all", "bkash", "nagad", "rocket", "cod"];

      if (status && !allowedStatuses.includes(status)) {
        fail("Invalid order status");
      }

      if (method && !allowedMethods.includes(method)) {
        fail("Invalid payment method");
      }

      if (date && !["all", "today", "week", "month"].includes(date)) {
        fail("Invalid date filter");
      }

      const filter = {};

      if (status && status !== "all") {
        filter.status = status;
      }

      if (method && method !== "all") {
        filter["payment.method"] = method;
      }

      // ======================================
      // SEARCH
      // ======================================

      if (search) {
        const escaped = search.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

        const rx = new RegExp(escaped, "i");

        filter.$or = [
          { orderNumber: rx },
          { "customer.name": rx },
          { "customer.phone": rx },
          { "customer.email": rx },
          { "shipping.phone": rx },
          { "items.name": rx },
          { "items.sku": rx },
          { "payment.trxId": rx },
        ];

        if (/^[a-f0-9]{24}$/i.test(search)) {
          filter.$or.push({
            _id: new ObjectId(search),
          });
        }
      }

      // ======================================
      // DATE — DHAKA TIMEZONE
      // ======================================

      if (date && date !== "all") {
        const now = new Date();
        const offset = 6 * 60 * 60 * 1000;

        const dhaka = new Date(now.getTime() + offset);

        const year = dhaka.getUTCFullYear();
        const month = dhaka.getUTCMonth();
        const day = dhaka.getUTCDate();

        const today = new Date(Date.UTC(year, month, day) - offset);

        let start;

        if (date === "today") {
          start = today;
        } else if (date === "week") {
          start = new Date(today.getTime() - 6 * 86400000);
        } else {
          start = new Date(Date.UTC(year, month, 1) - offset);
        }

        filter.createdAt = {
          $gte: start,
          $lte: now,
        };
      }

      // ======================================
      // GLOBAL STATS
      // Not limited to current page
      // ======================================

      const [documents, filteredTotal, statusRows, custom] = await Promise.all([
        orders
          .find(filter, {
            projection: {
              checkoutId: 0,
              guestTokenHash: 0,
              paymentTrxIds: 0,
            },
          })
          .sort({
            createdAt: -1,
            _id: -1,
          })
          .skip((page - 1) * perPage)
          .limit(perPage)
          .toArray(),

        orders.countDocuments(filter),

        orders
          .aggregate([
            {
              $group: {
                _id: "$status",
                count: { $sum: 1 },
              },
            },
          ])
          .toArray(),

        orders.countDocuments({
          status: {
            $in: ["verified", "processing"],
          },
          "items.customization.mode": {
            $in: ["frame", "note"],
          },
        }),
      ]);

      const counts = {
        all: 0,
        pending: 0,
        verified: 0,
        processing: 0,
        shipped: 0,
        delivered: 0,
        rejected: 0,
        cancelled: 0,
      };

      for (const item of statusRows) {
        counts[item._id] = item.count;
        counts.all += item.count;
      }

      const stats = {
        total: counts.all,

        active:
          (counts.pending || 0) +
          (counts.verified || 0) +
          (counts.processing || 0) +
          (counts.shipped || 0),

        pending: counts.pending || 0,
        custom,
        transit: counts.shipped || 0,
      };

      // ========================================
      // LOAD CUSTOMER PROFILE PHOTOS
      // ========================================

      const customerUids = [
        ...new Set(
          documents
            .filter((order) => !order.guest && order.uid)
            .map((order) => order.uid),
        ),
      ];

      // Uses existing MongoDB users collection.
      const customerAccounts = customerUids.length
        ? await users
            .find(
              {
                uid: { $in: customerUids },
              },
              {
                projection: {
                  uid: 1,
                  photoUrl: 1,
                  photoURL: 1,
                  imageUrl: 1,
                  image_url: 1,
                },
              },
            )
            .toArray()
        : [];

      const customerPhotoMap = new Map(
        customerAccounts.map((account) => [
          account.uid,
          account.photoUrl ||
            account.photoURL ||
            account.imageUrl ||
            account.image_url ||
            "",
        ]),
      );

      res.set("Cache-Control", "no-store");

      return res.json({
        success: true,

        orders: documents.map((order) => {
          const { uid, ...orderData } = order;

          const items = Array.isArray(order.items) ? order.items : [];

          const itemCount = items.reduce(
            (total, item) => total + (Number(item.quantity) || 0),
            0,
          );

          return {
            ...orderData,

            _id: order._id.toString(),

            customerPhotoUrl: order.guest
              ? ""
              : customerPhotoMap.get(uid) || "",

            itemCount,
          };
        }),

        stats,
        counts,

        pagination: {
          page,
          limit: perPage,
          total: filteredTotal,
          totalPages: Math.max(1, Math.ceil(filteredTotal / perPage)),
          hasNextPage: page * perPage < filteredTotal,
          hasPreviousPage: page > 1,
        },
      });
    }),
  );

  // ==========================================
  // ADMIN PAYMENT LIST
  // Guest + Registered Customer
  // Search + Filters + Stats + Pagination
  // ==========================================

  app.get(
    "/admin/payments",
    verifyFirebaseToken,
    verifyAdmin,
    handle(async (req, res) => {
      const page = Math.min(
        10000,
        Math.max(1, parseInt(req.query.page, 10) || 1),
      );

      const limit = 10;

      const status = str(req.query.status, 30).toLowerCase();
      const method = str(req.query.method, 20).toLowerCase();
      const date = str(req.query.date, 20).toLowerCase();
      const search = str(req.query.search, 100);

      const statuses = [
        "",
        "all",
        "pending",
        "partially_paid",
        "verified",
        "rejected",
      ];

      const methods = ["", "all", "bkash", "nagad", "rocket"];

      const dates = ["", "all", "today", "week", "month"];

      if (!statuses.includes(status)) {
        fail("Invalid payment status");
      }

      if (!methods.includes(method)) {
        fail("Invalid payment method");
      }

      if (!dates.includes(date)) {
        fail("Invalid date filter");
      }

      // COD is managed separately.
      // Never count COD as verified online payment.
      const onlineFilter = {
        "payment.method": {
          $in: ["bkash", "nagad", "rocket"],
        },
      };

      const filter = { ...onlineFilter };

      // ======================================
      // PAYMENT STATUS
      // ======================================

      if (status === "pending") {
        filter["payment.status"] = {
          $in: ["pending", "partially_paid"],
        };
      } else if (status && status !== "all") {
        filter["payment.status"] = status;
      }

      // ======================================
      // PAYMENT METHOD
      // ======================================

      if (method && method !== "all") {
        filter["payment.method"] = method;
      }

      // ======================================
      // SEARCH
      // ======================================

      if (search) {
        const escaped = search.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

        const regex = new RegExp(escaped, "i");

        const searchConditions = [
          { orderNumber: regex },
          { "customer.name": regex },
          { "customer.phone": regex },
          { "customer.email": regex },
          { "payment.senderPhone": regex },
          { "payment.trxId": regex },
        ];

        if (/^[a-f0-9]{24}$/i.test(search)) {
          searchConditions.push({
            _id: new ObjectId(search),
          });
        }

        filter.$or = searchConditions;
      }

      // ======================================
      // DATE FILTER — ASIA/DHAKA UTC+06
      // ======================================

      if (date && date !== "all") {
        const dhakaNow = new Date(Date.now() + 6 * 60 * 60 * 1000);

        const year = dhakaNow.getUTCFullYear();
        const month = dhakaNow.getUTCMonth();
        const day = dhakaNow.getUTCDate();

        const todayStart = new Date(
          Date.UTC(year, month, day) - 6 * 60 * 60 * 1000,
        );

        let start;

        if (date === "today") {
          start = todayStart;
        } else if (date === "week") {
          start = new Date(todayStart.getTime() - 6 * 24 * 60 * 60 * 1000);
        } else {
          start = new Date(Date.UTC(year, month, 1) - 6 * 60 * 60 * 1000);
        }

        filter.createdAt = {
          $gte: start,
          $lte: new Date(),
        };
      }

      // ======================================
      // GLOBAL STATS
      // Independent of table filters
      // ======================================

      const statsPipeline = [
        { $match: onlineFilter },

        {
          $group: {
            _id: null,

            total: { $sum: 1 },

            pending: {
              $sum: {
                $cond: [
                  {
                    $in: ["$payment.status", ["pending", "partially_paid"]],
                  },
                  1,
                  0,
                ],
              },
            },

            partiallyPaid: {
              $sum: {
                $cond: [
                  {
                    $eq: ["$payment.status", "partially_paid"],
                  },
                  1,
                  0,
                ],
              },
            },

            verified: {
              $sum: {
                $cond: [
                  {
                    $eq: ["$payment.status", "verified"],
                  },
                  1,
                  0,
                ],
              },
            },

            rejected: {
              $sum: {
                $cond: [
                  {
                    $eq: ["$payment.status", "rejected"],
                  },
                  1,
                  0,
                ],
              },
            },

            verifiedCollection: {
              $sum: {
                $ifNull: ["$payment.verifiedAmount", 0],
              },
            },
          },
        },
      ];

      // ======================================
      // FETCH TABLE + TOTAL + STATS
      // ======================================

      const [documents, total, statsResult] = await Promise.all([
        orders
          .find(filter, {
            projection: {
              orderNumber: 1,
              guest: 1,
              customer: 1,
              payment: 1,
              total: 1,
              status: 1,
              createdAt: 1,
              updatedAt: 1,

              uid: 1,

              "items.name": 1,
              "items.image": 1,
              "items.quantity": 1,
              "items.variantTitle": 1,
            },
          })
          .sort({
            createdAt: -1,
            _id: -1,
          })
          .skip((page - 1) * limit)
          .limit(limit)
          .toArray(),

        orders.countDocuments(filter),

        orders.aggregate(statsPipeline).toArray(),
      ]);

      const stats = statsResult[0] || {
        total: 0,
        pending: 0,
        partiallyPaid: 0,
        verified: 0,
        rejected: 0,
        verifiedCollection: 0,
      };

      // ========================================
      // LOAD CUSTOMER PROFILE IMAGES
      // ========================================

      const customerUids = [
        ...new Set(
          documents
            .filter((order) => !order.guest && order.uid)
            .map((order) => order.uid),
        ),
      ];

      const customerAccounts = customerUids.length
        ? await users
            .find(
              {
                uid: { $in: customerUids },
              },
              {
                projection: {
                  uid: 1,
                  photoUrl: 1,
                  photoURL: 1,
                  imageUrl: 1,
                  image_url: 1,
                },
              },
            )
            .toArray()
        : [];

      const customerPhotoMap = new Map(
        customerAccounts.map((account) => [
          account.uid,

          account.photoUrl ||
            account.photoURL ||
            account.imageUrl ||
            account.image_url ||
            "",
        ]),
      );

      res.set("Cache-Control", "no-store");

      return res.json({
        success: true,

        payments: documents.map(({ uid, ...order }) => {
          const items = Array.isArray(order.items) ? order.items : [];

          const itemCount = items.reduce(
            (total, item) => total + (Number(item.quantity) || 0),
            0,
          );

          return {
            ...order,

            _id: order._id.toString(),

            // Registered Customer profile photo.
            // Guest => no photo, icon fallback.
            customerPhotoUrl: customerPhotoMap.get(uid) || "",

            // Total product quantity
            itemCount,

            // Maximum two preview images
            items: items.slice(0, 2),
          };
        }),

        stats: {
          total: stats.total,
          pending: stats.pending,
          partiallyPaid: stats.partiallyPaid,
          verified: stats.verified,
          rejected: stats.rejected,
          verifiedCollection: stats.verifiedCollection,
        },

        pagination: {
          page,
          limit,
          total,
          totalPages: Math.max(1, Math.ceil(total / limit)),
        },
      });
    }),
  );

  // =========================================
  // GET /admin/orders/:identifier
  // =========================================

  app.get(
    "/admin/orders/:identifier",
    verifyFirebaseToken,
    verifyAdmin,
    handle(async (req, res) => {
      const order = await orders.findOne(orderFilter(req.params.identifier));

      if (!order) {
        fail("Order not found", 404);
      }

      let customerPhotoUrl = "";

      if (!order.guest && order.uid) {
        const account = await users.findOne(
          { uid: order.uid },
          {
            projection: {
              photoUrl: 1,
              photoURL: 1,
              imageUrl: 1,
              image_url: 1,
            },
          },
        );

        customerPhotoUrl =
          account?.photoUrl ||
          account?.photoURL ||
          account?.imageUrl ||
          account?.image_url ||
          "";
      }

      res.set("Cache-Control", "no-store");

      return res.json({
        success: true,

        order: {
          ...viewOrder(order),

          customerPhotoUrl,

          // Only returned by admin endpoint.
          internalNotes: order.internalNotes || [],
        },
      });
    }),
  );

  // ==========================================
  // ADMIN INTERNAL NOTES
  // POST /admin/orders/:identifier/notes
  // ==========================================

  app.post(
    "/admin/orders/:identifier/notes",
    verifyFirebaseToken,
    verifyAdmin,
    handle(async (req, res) => {
      const text = str(req.body?.text, 1000);

      if (!text) {
        fail("Note cannot be empty");
      }

      const updated = await updateOrder(
        req.params.identifier,

        (order) => {
          const previous = Array.isArray(order.internalNotes)
            ? order.internalNotes
            : [];

          const newNote = {
            id: randomUUID(),

            author: req.user.name || req.user.email || "SokhBilash Admin",

            uid: req.user.uid,

            text,

            createdAt: new Date(),
          };

          return {
            set: {
              internalNotes: [...previous.slice(-99), newNote],
            },

            event: "internal_note_added",

            // Do not expose the note content
            // through public order history.
            note: "Admin-only note added",

            by: req.user.uid,
          };
        },
      );

      res.set("Cache-Control", "no-store");

      return res.status(201).json({
        success: true,
        message: "Internal note saved",

        order: {
          ...viewOrder(updated),
          internalNotes: updated.internalNotes || [],
        },
      });
    }),
  );

  // ==========================================
  // ADMIN PAYMENT VERIFY / REJECT
  // Secure cumulative reconciliation
  // ==========================================

  app.patch(
    "/admin/orders/:identifier/payment",
    verifyFirebaseToken,
    verifyAdmin,
    handle(async (req, res) => {
      const decision = str(req.body?.decision, 20).toLowerCase();

      if (!["verify", "reject"].includes(decision)) {
        fail("Invalid payment decision");
      }

      const updated = await updateOrder(
        req.params.identifier,

        (order) => {
          const payment = order.payment || {};

          if (payment.method === "cod") {
            fail("Use phone confirmation for COD", 409);
          }

          // Only a new pending proof can be
          // verified or rejected.
          // A partially reviewed proof cannot
          // be credited twice.

          if (order.status !== "pending" || payment.status !== "pending") {
            fail(
              "This payment proof is already reviewed or is not pending",
              409,
            );
          }

          const previous = currency(payment.verifiedAmount || 0);

          // ==================================
          // REJECT
          // ==================================

          if (decision === "reject") {
            const reason = str(req.body?.reason, 500);

            if (!reason) {
              fail("Rejection reason required");
            }

            return {
              set: {
                status: "rejected",

                payment: {
                  ...payment,
                  status: "rejected",
                  rejectedReason: reason,
                  verifiedBy: req.user.uid,
                  verifiedAt: new Date(),

                  // Previously verified money
                  // must not disappear.
                  verifiedAmount: previous,
                  dueAmount: currency(order.total - previous),
                },
              },

              event: "payment_rejected",
              note: reason,
              by: req.user.uid,
            };
          }

          // ==================================
          // VERIFY
          // verifiedAmount is CUMULATIVE.
          // ==================================

          const amount = parseAmount(
            req.body?.verifiedAmount,
            "verified amount",
          );

          const receivedForThisProof = currency(amount - previous);

          const claim = currency(payment.claimedAmount || 0);

          const remaining = currency(order.total - previous);

          if (receivedForThisProof <= 0) {
            fail("Verified amount must increase", 409);
          }

          if (receivedForThisProof > claim) {
            fail("Actual received amount exceeds submitted claim");
          }

          if (receivedForThisProof > remaining) {
            fail("Received amount exceeds remaining due");
          }

          const due = currency(order.total - amount);

          const fullyPaid = due <= 0;

          return {
            set: {
              status: fullyPaid ? "verified" : "pending",

              payment: {
                ...payment,

                status: fullyPaid ? "verified" : "partially_paid",

                verifiedAmount: amount,
                dueAmount: due,

                verifiedAt: new Date(),
                verifiedBy: req.user.uid,
                rejectedReason: null,

                // Audit which proof was reviewed.
                reviewedTrxId: payment.trxId,
              },
            },

            event: fullyPaid
              ? "payment_verified"
              : "payment_partially_verified",

            note:
              `Received BDT ${receivedForThisProof}; ` +
              `Cumulative BDT ${amount}; ` +
              `Due BDT ${due}`,

            by: req.user.uid,
          };
        },
      );

      res.set("Cache-Control", "no-store");

      return res.json({
        success: true,
        message: "Payment updated successfully",
        order: viewOrder(updated),
      });
    }),
  );

  // =========================================
  // COD PHONE CONFIRMATION
  // =========================================

  app.patch(
    "/admin/orders/:identifier/phone-confirmation",
    verifyFirebaseToken,
    verifyAdmin,
    handle(async (req, res) => {
      if (typeof req.body.confirmed !== "boolean") {
        fail("confirmed must be boolean");
      }

      const updated = await updateOrder(
        req.params.identifier,

        (order) => {
          if (order.payment.method !== "cod") {
            fail("Not a COD order");
          }

          if (!["pending", "verified"].includes(order.status)) {
            fail("Cannot change phone confirmation", 409);
          }

          return {
            set: {
              phoneConfirmed: req.body.confirmed,

              status: req.body.confirmed ? "verified" : "pending",
            },

            event: req.body.confirmed ? "phone_confirmed" : "phone_unconfirmed",

            note: req.body.confirmed
              ? "COD confirmed by phone"
              : "Confirmation revoked",

            by: req.user.uid,
          };
        },
      );

      res.json({
        success: true,

        order: viewOrder(updated),
      });
    }),
  );

  // =========================================
  // ADMIN ORDER STATUS
  // =========================================

  app.patch(
    "/admin/orders/:identifier/status",
    verifyFirebaseToken,
    verifyAdmin,
    handle(async (req, res) => {
      const status = str(req.body.status, 30);

      const note = str(req.body.note, 500);

      const transitions = {
        pending: ["verified", "cancelled"],

        verified: ["processing", "cancelled"],

        processing: ["shipped", "cancelled"],

        shipped: ["delivered"],

        delivered: [],
        rejected: [],
        cancelled: [],
      };

      const updated = await updateOrder(
        req.params.identifier,

        (order) => {
          if (!transitions[order.status]?.includes(status)) {
            fail("Invalid status transition", 409);
          }

          if (status === "verified" || status === "processing") {
            const allowed =
              order.payment.method === "cod"
                ? order.phoneConfirmed === true
                : order.payment.status === "verified";

            if (!allowed) {
              fail("Payment or phone verification required", 409);
            }
          }

          return {
            set: {
              status,
            },

            event: status,

            note: note || `Order marked ${status}`,

            by: req.user.uid,
          };
        },
      );

      res.json({
        success: true,

        message: "Order status updated",

        order: viewOrder(updated),
      });
    }),
  );

  // =========================================
  // ADMIN COURIER/TRACKING
  // =========================================

  app.patch(
    "/admin/orders/:identifier/tracking",
    verifyFirebaseToken,
    verifyAdmin,
    handle(async (req, res) => {
      const name = str(req.body?.name, 150);

      const trackingNumber = str(req.body?.trackingNumber, 150);

      const trackingUrl = str(req.body?.trackingUrl, 2048);

      const parcelWeight = str(req.body?.parcelWeight, 30);

      // ====================================
      // VALIDATION
      // ====================================

      if (!name && (trackingNumber || trackingUrl || parcelWeight)) {
        fail(
          "Courier name is required when tracking or parcel details are provided",
        );
      }

      if (trackingUrl && !trackingNumber) {
        fail("Tracking number required for tracking URL");
      }

      if (trackingUrl && !validHttpsUrl(trackingUrl)) {
        fail("Invalid HTTPS tracking URL");
      }

      if (
        parcelWeight &&
        !/^\d{1,4}(?:\.\d{1,2})?\s*(?:kg|g)$/i.test(parcelWeight)
      ) {
        fail("Invalid parcel weight. Example: 1.5 kg or 500 g");
      }

      // Keep compatibility with the existing
      // Order Management tracking form.
      // If date is not supplied, do not touch it.

      const dateProvided = Object.prototype.hasOwnProperty.call(
        req.body || {},
        "estimatedDelivery",
      );

      let estimatedDelivery = null;

      if (dateProvided) {
        const rawDate = req.body.estimatedDelivery;

        if (rawDate !== null && rawDate !== "") {
          if (
            typeof rawDate !== "string" ||
            Number.isNaN(Date.parse(rawDate))
          ) {
            fail("Invalid estimated delivery date");
          }

          estimatedDelivery = new Date(rawDate);
        }
      }

      // ====================================
      // ATOMIC ORDER UPDATE
      // ====================================

      const updated = await updateOrder(
        req.params.identifier,

        (order) => {
          if (["rejected", "cancelled"].includes(order.status)) {
            fail("Cannot edit an inactive order", 409);
          }

          return {
            set: {
              courier: {
                ...order.courier,

                name: name || null,

                trackingNumber: trackingNumber || null,

                trackingUrl: trackingUrl || null,

                parcelWeight: parcelWeight || null,
              },

              // Only change the date when the
              // client explicitly supplies it.
              ...(dateProvided ? { estimatedDelivery } : {}),
            },

            event: "tracking_updated",

            note:
              `Courier: ${name || "Unassigned"}; ` +
              `Tracking: ${trackingNumber || "None"}; ` +
              `Weight: ${parcelWeight || "None"}`,

            by: req.user.uid,
          };
        },
      );

      res.set("Cache-Control", "no-store");

      return res.json({
        success: true,
        message: "Courier details updated",

        order: viewOrder(updated),
      });
    }),
  );

  // ================================================
  // ADMIN DASHBOARD - FULL DYNAMIC API
  // GET /admin/dashboard
  // ================================================

  app.get(
    "/admin/dashboard",
    verifyFirebaseToken,
    verifyAdmin,
    handle(async (req, res) => {
      // ==========================================
      // DHAKA TIMEZONE
      // ==========================================

      const now = new Date();
      const DAY_MS = 24 * 60 * 60 * 1000;
      const DHAKA_OFFSET_MS = 6 * 60 * 60 * 1000;

      const dhakaNow = new Date(now.getTime() + DHAKA_OFFSET_MS);

      const year = dhakaNow.getUTCFullYear();
      const month = dhakaNow.getUTCMonth();
      const day = dhakaNow.getUTCDate();

      const todayCalendar = Date.UTC(year, month, day);

      const todayStart = new Date(todayCalendar - DHAKA_OFFSET_MS);

      const currentMonthStart = new Date(
        Date.UTC(year, month, 1) - DHAKA_OFFSET_MS,
      );

      const sixMonthStart = new Date(
        Date.UTC(year, month - 5, 1) - DHAKA_OFFSET_MS,
      );

      const current30Start = new Date(todayStart.getTime() - 29 * DAY_MS);

      const previous30Start = new Date(current30Start.getTime() - 30 * DAY_MS);

      const dayAt = (offset) => new Date(todayCalendar + offset * DAY_MS);

      const dateKey = (date) => date.toISOString().slice(0, 10);

      const roundMoney = (value) =>
        Math.round((Number(value || 0) + Number.EPSILON) * 100) / 100;

      const percentChange = (current, previous) => {
        if (!previous) return null;

        return Math.round(((current - previous) / previous) * 1000) / 10;
      };

      // ==========================================
      // BUSINESS CONFIGURATION
      // ==========================================

      const activeStatuses = ["pending", "verified", "processing", "shipped"];

      const onlineMethods = ["bkash", "nagad", "rocket"];

      const customProductCondition = {
        $gt: [
          {
            $size: {
              $filter: {
                input: {
                  $ifNull: ["$items", []],
                },
                as: "item",
                cond: {
                  $in: ["$$item.customization.mode", ["frame", "note"]],
                },
              },
            },
          },
          0,
        ],
      };

      // ==========================================
      // 1. DASHBOARD KPI AGGREGATION
      // ==========================================

      const overviewPipeline = [
        {
          $group: {
            _id: null,

            // All orders
            totalOrders: {
              $sum: 1,
            },

            // Pending orders
            pendingOrders: {
              $sum: {
                $cond: [{ $eq: ["$status", "pending"] }, 1, 0],
              },
            },

            // Only unreviewed online payment proofs
            pendingPayments: {
              $sum: {
                $cond: [
                  {
                    $and: [
                      {
                        $eq: ["$status", "pending"],
                      },
                      {
                        $eq: ["$payment.status", "pending"],
                      },
                      {
                        $in: ["$payment.method", onlineMethods],
                      },
                    ],
                  },
                  1,
                  0,
                ],
              },
            },

            // Delivered orders
            deliveredOrders: {
              $sum: {
                $cond: [{ $eq: ["$status", "delivered"] }, 1, 0],
              },
            },

            // Total fulfilled sales
            totalSales: {
              $sum: {
                $cond: [
                  { $eq: ["$status", "delivered"] },
                  {
                    $ifNull: ["$total", 0],
                  },
                  0,
                ],
              },
            },

            // Outstanding balance on active orders
            outstandingBalance: {
              $sum: {
                $cond: [
                  {
                    $in: ["$status", activeStatuses],
                  },
                  {
                    $max: [
                      0,
                      {
                        $subtract: [
                          {
                            $ifNull: ["$total", 0],
                          },
                          {
                            $ifNull: ["$payment.verifiedAmount", 0],
                          },
                        ],
                      },
                    ],
                  },
                  0,
                ],
              },
            },

            // COD phone confirmation pending
            codUnconfirmed: {
              $sum: {
                $cond: [
                  {
                    $and: [
                      {
                        $eq: ["$payment.method", "cod"],
                      },
                      {
                        $eq: ["$status", "pending"],
                      },
                      {
                        $ne: ["$phoneConfirmed", true],
                      },
                    ],
                  },
                  1,
                  0,
                ],
              },
            },

            // Custom orders in production
            customProcessing: {
              $sum: {
                $cond: [
                  {
                    $and: [
                      {
                        $in: ["$status", ["verified", "processing"]],
                      },
                      customProductCondition,
                    ],
                  },
                  1,
                  0,
                ],
              },
            },
          },
        },
      ];

      // ==========================================
      // 2. CURRENT MONTH ORDER STATUS CHART
      // ==========================================

      const monthStatusPipeline = [
        {
          $match: {
            createdAt: {
              $gte: currentMonthStart,
              $lte: now,
            },
          },
        },
        {
          $group: {
            _id: "$status",
            count: {
              $sum: 1,
            },
          },
        },
      ];

      // ==========================================
      // 3. SALES TREND
      // Delivered orders grouped by createdAt
      // ==========================================

      const salesPipeline = [
        {
          $match: {
            status: "delivered",
            createdAt: {
              $gte: sixMonthStart,
              $lte: now,
            },
          },
        },
        {
          $group: {
            _id: {
              $dateToString: {
                format: "%Y-%m-%d",
                date: "$createdAt",
                timezone: "Asia/Dhaka",
              },
            },
            sales: {
              $sum: {
                $ifNull: ["$total", 0],
              },
            },
          },
        },
        {
          $sort: {
            _id: 1,
          },
        },
      ];

      // ==========================================
      // 4. VERIFIED ONLINE PAYMENT COLLECTION
      // ==========================================

      const paymentPipeline = [
        {
          $match: {
            "payment.method": {
              $in: onlineMethods,
            },
          },
        },
        {
          $group: {
            _id: "$payment.method",
            amount: {
              $sum: {
                $ifNull: ["$payment.verifiedAmount", 0],
              },
            },
          },
        },
      ];

      // ==========================================
      // 5. FETCH DASHBOARD DATA
      // ==========================================

      const [
        overviewRows,
        monthStatusRows,
        salesRows,
        paymentRows,
        recentDocuments,
        firstCodOrder,
        firstCustomOrder,
        current30Orders,
        previous30Orders,
      ] = await Promise.all([
        orders.aggregate(overviewPipeline).toArray(),

        orders.aggregate(monthStatusPipeline).toArray(),

        orders.aggregate(salesPipeline).toArray(),

        orders.aggregate(paymentPipeline).toArray(),

        // ======================================
        // RECENT 5 ORDERS
        // Order Management-style table
        // ======================================

        orders
          .find(
            {},
            {
              projection: {
                _id: 1,
                uid: 1,
                guest: 1,
                orderNumber: 1,

                "customer.name": 1,
                "customer.phone": 1,

                "shipping.phone": 1,

                "items.name": 1,
                "items.image": 1,
                "items.quantity": 1,
                "items.variantTitle": 1,
                "items.cartId": 1,
                "items.productId": 1,

                total: 1,
                status: 1,

                "payment.method": 1,
                "payment.status": 1,
                "payment.verifiedAmount": 1,
                "payment.dueAmount": 1,

                "courier.name": 1,
                "courier.trackingNumber": 1,

                createdAt: 1,
              },
            },
          )
          .sort({
            createdAt: -1,
            _id: -1,
          })
          .limit(5)
          .toArray(),

        // First COD order requiring a call
        orders.findOne(
          {
            status: "pending",
            "payment.method": "cod",
            phoneConfirmed: {
              $ne: true,
            },
          },
          {
            sort: {
              createdAt: 1,
            },
            projection: {
              _id: 1,
            },
          },
        ),

        // First customized order in progress
        orders.findOne(
          {
            status: {
              $in: ["verified", "processing"],
            },
            "items.customization.mode": {
              $in: ["frame", "note"],
            },
          },
          {
            sort: {
              createdAt: 1,
            },
            projection: {
              _id: 1,
            },
          },
        ),

        // Orders in current 30 days
        orders.countDocuments({
          createdAt: {
            $gte: current30Start,
            $lte: now,
          },
        }),

        // Orders in previous 30 days
        orders.countDocuments({
          createdAt: {
            $gte: previous30Start,
            $lt: current30Start,
          },
        }),
      ]);

      // ==========================================
      // 6. CUSTOMER PROFILE PHOTOS
      // ==========================================

      const recentUids = [
        ...new Set(
          recentDocuments
            .filter((order) => !order.guest && order.uid)
            .map((order) => order.uid),
        ),
      ];

      const customerAccounts = recentUids.length
        ? await users
            .find(
              {
                uid: {
                  $in: recentUids,
                },
              },
              {
                projection: {
                  uid: 1,
                  photoUrl: 1,
                  photoURL: 1,
                  imageUrl: 1,
                  image_url: 1,
                },
              },
            )
            .toArray()
        : [];

      const customerPhotoMap = new Map(
        customerAccounts.map((account) => [
          account.uid,
          account.photoUrl ||
            account.photoURL ||
            account.imageUrl ||
            account.image_url ||
            "",
        ]),
      );

      // ==========================================
      // 7. KPI RESULT
      // ==========================================

      const overview = overviewRows[0] || {};

      const totalOrders = Number(overview.totalOrders) || 0;

      const deliveredOrders = Number(overview.deliveredOrders) || 0;

      const totalSales = roundMoney(overview.totalSales);

      const outstandingBalance = roundMoney(overview.outstandingBalance);

      const deliveryRate = totalOrders
        ? Math.round((deliveredOrders / totalOrders) * 1000) / 10
        : 0;

      const orderGrowthPercent = percentChange(
        current30Orders,
        previous30Orders,
      );

      // ==========================================
      // 8. DAILY SALES LOOKUP
      // ==========================================

      const dailySalesMap = new Map(
        salesRows.map((row) => [row._id, roundMoney(row.sales)]),
      );

      const saleOn = (date) => dailySalesMap.get(date) || 0;

      // ==========================================
      // 9. DAILY SALES - LAST 7 DAYS
      // ==========================================

      const weekdayFormatter = new Intl.DateTimeFormat("bn-BD", {
        weekday: "short",
        timeZone: "UTC",
      });

      const daily = Array.from({ length: 7 }, (_, index) => {
        const date = dayAt(index - 6);

        return {
          name: weekdayFormatter.format(date),
          sales: saleOn(dateKey(date)),
        };
      });

      // ==========================================
      // 10. WEEKLY SALES - LAST 4 WEEKS
      // ==========================================

      const weekLabels = ["১ম", "২য়", "৩য়", "৪র্থ"];

      const weekly = weekLabels.map((name, index) => {
        const startOffset = -27 + index * 7;

        let sales = 0;

        for (let dayIndex = 0; dayIndex < 7; dayIndex++) {
          const date = dayAt(startOffset + dayIndex);

          sales += saleOn(dateKey(date));
        }

        return {
          name,
          sales: roundMoney(sales),
        };
      });

      // ==========================================
      // 11. MONTHLY SALES - LAST 6 MONTHS
      // ==========================================

      const monthlyFormatter = new Intl.DateTimeFormat("bn-BD", {
        month: "short",
        timeZone: "UTC",
      });

      const monthly = [];

      for (let offset = 5; offset >= 0; offset--) {
        const date = new Date(Date.UTC(year, month - offset, 1));

        const monthKey = date.toISOString().slice(0, 7);

        let sales = 0;

        for (const [key, value] of dailySalesMap) {
          if (key.startsWith(monthKey)) {
            sales += value;
          }
        }

        monthly.push({
          name: monthlyFormatter.format(date),
          sales: roundMoney(sales),
        });
      }

      // ==========================================
      // 12. SALES GROWTH - LAST 30 DAYS
      // ==========================================

      const current30Key = dateKey(new Date(todayCalendar - 29 * DAY_MS));

      const previous30Key = dateKey(new Date(todayCalendar - 59 * DAY_MS));

      let current30Sales = 0;
      let previous30Sales = 0;

      for (const [key, value] of dailySalesMap) {
        if (key >= current30Key) {
          current30Sales += value;
        } else if (key >= previous30Key) {
          previous30Sales += value;
        }
      }

      const salesGrowthPercent = percentChange(
        roundMoney(current30Sales),
        roundMoney(previous30Sales),
      );

      // ==========================================
      // 13. ORDER STATUS DISTRIBUTION
      // ==========================================

      const monthlyStatusCounts = Object.fromEntries(
        monthStatusRows.map((item) => [item._id, item.count]),
      );

      const completed = monthlyStatusCounts.delivered || 0;

      const processing =
        (monthlyStatusCounts.verified || 0) +
        (monthlyStatusCounts.processing || 0) +
        (monthlyStatusCounts.shipped || 0);

      const pending = monthlyStatusCounts.pending || 0;

      const cancelled =
        (monthlyStatusCounts.cancelled || 0) +
        (monthlyStatusCounts.rejected || 0);

      const statusData = [
        {
          name: "সম্পন্ন",
          value: completed,
          color: "#8d389e",
        },
        {
          name: "প্রসেসিং",
          value: processing,
          color: "#df72ef",
        },
        {
          name: "পেন্ডিং",
          value: pending,
          color: "#ffe16d",
        },
        {
          name: "বাতিল",
          value: cancelled,
          color: "#c73e49",
        },
      ];

      const statusTotal = statusData.reduce((sum, item) => sum + item.value, 0);

      // ==========================================
      // 14. VERIFIED PAYMENT BY METHOD
      // ==========================================

      const paymentMap = new Map(
        paymentRows.map((item) => [item._id, roundMoney(item.amount)]),
      );

      const paymentData = [
        {
          name: "bKash",
          amount: paymentMap.get("bkash") || 0,
          color: "#8d389e",
        },
        {
          name: "Nagad",
          amount: paymentMap.get("nagad") || 0,
          color: "#ffd700",
        },
        {
          name: "Rocket",
          amount: paymentMap.get("rocket") || 0,
          color: "#310039",
        },
      ];

      // ==========================================
      // 15. RECENT ORDERS
      // Order Management compatible format
      // ==========================================

      const recentOrders = recentDocuments.map((order) => {
        const items = Array.isArray(order.items) ? order.items : [];

        const itemCount = items.reduce(
          (sum, item) => sum + (Number(item.quantity) || 0),
          0,
        );

        const verifiedAmount = roundMoney(order.payment?.verifiedAmount);

        const dueAmount = Math.max(
          0,
          roundMoney(
            order.payment?.dueAmount ??
              Number(order.total || 0) - verifiedAmount,
          ),
        );

        return {
          _id: order._id.toString(),

          orderNumber: order.orderNumber || "—",

          createdAt: order.createdAt || null,

          status: order.status || "pending",

          total: roundMoney(order.total),

          guest: Boolean(order.guest),

          // Customer information
          customer: {
            name: order.customer?.name || "Unknown Customer",

            phone: order.customer?.phone || "",
          },

          shipping: {
            phone: order.shipping?.phone || "",
          },

          // Registered customer avatar
          customerPhotoUrl: order.guest
            ? ""
            : customerPhotoMap.get(order.uid) || "",

          // Total quantity
          itemCount,

          // Maximum two product previews
          items: items.slice(0, 2),

          // Financial details
          payment: {
            method: order.payment?.method || null,

            status: order.payment?.status || null,

            verifiedAmount,

            dueAmount,
          },

          // Courier information
          courier: {
            name: order.courier?.name || null,

            trackingNumber: order.courier?.trackingNumber || null,
          },
        };
      });

      // ==========================================
      // 16. FINAL DASHBOARD RESPONSE
      // ==========================================

      res.set("Cache-Control", "private, no-store");

      return res.status(200).json({
        success: true,

        generatedAt: now.toISOString(),

        // ======================================
        // SIX KPI CARDS
        // ======================================

        kpis: {
          totalOrders,

          pendingOrders: Number(overview.pendingOrders) || 0,

          pendingPayments: Number(overview.pendingPayments) || 0,

          totalSales,

          deliveredOrders,

          outstandingBalance,

          deliveryRate,

          orderGrowthPercent,

          salesGrowthPercent,
        },

        // ======================================
        // NEEDS ATTENTION CARDS
        // ======================================

        attention: {
          paymentPending: Number(overview.pendingPayments) || 0,

          codUnconfirmed: Number(overview.codUnconfirmed) || 0,

          customProcessing: Number(overview.customProcessing) || 0,

          firstCodOrderId: firstCodOrder?._id?.toString() || null,

          firstCustomOrderId: firstCustomOrder?._id?.toString() || null,
        },

        // ======================================
        // SALES TREND
        // ======================================

        salesData: {
          daily,
          weekly,
          monthly,
        },

        // ======================================
        // ORDER STATUS CHART
        // ======================================

        statusData,
        statusTotal,

        // ======================================
        // PAYMENT METHOD CHART
        // ======================================

        paymentData,

        // ======================================
        // RECENT ORDERS TABLE
        // ======================================

        recentOrders,
      });
    }),
  );

  // ===================================================
  // ADMIN CUSTOMER MANAGEMENT - READ ONLY
  // GET /admin/customers
  //
  // Existing dependencies:
  // app, users, orders, verifyFirebaseToken,
  // verifyAdmin, handle, str, fail
  // ===================================================

  app.get(
    "/admin/customers",
    verifyFirebaseToken,
    verifyAdmin,
    handle(async (req, res) => {
      // ==========================================
      // PAGINATION
      // ==========================================

      const pageRaw = str(req.query.page ?? "1", 6);

      if (!/^[1-9]\d{0,5}$/.test(pageRaw)) {
        fail("Invalid page number");
      }

      const page = Math.min(Number(pageRaw), 10000);

      const perPage = 10;
      const skip = (page - 1) * perPage;

      // ==========================================
      // FILTERS
      // ==========================================

      const search = str(req.query.search, 80);

      const status = str(req.query.status || "all", 20).toLowerCase();

      const ordersFilter = str(req.query.orders || "all", 20).toLowerCase();

      const sort = str(req.query.sort || "newest", 30).toLowerCase();

      if (!["all", "active", "restricted"].includes(status)) {
        fail("Invalid customer status filter");
      }

      if (!["all", "with_orders", "no_orders"].includes(ordersFilter)) {
        fail("Invalid customer order filter");
      }

      // ==========================================
      // SORT OPTIONS
      // ==========================================

      const sorts = {
        newest: {
          createdAt: -1,
          _id: -1,
        },

        oldest: {
          createdAt: 1,
          _id: 1,
        },

        orders: {
          "summary.orderCount": -1,
          createdAt: -1,
          _id: -1,
        },

        spent: {
          "summary.totalSpent": -1,
          createdAt: -1,
          _id: -1,
        },

        last_order: {
          "summary.lastOrderAt": -1,
          createdAt: -1,
          _id: -1,
        },
      };

      if (!Object.prototype.hasOwnProperty.call(sorts, sort)) {
        fail("Invalid sort option");
      }

      // ==========================================
      // CUSTOMER BASE FILTER
      // ==========================================

      const match = {
        role: "customer",
      };

      if (status === "active") {
        match.status = "active";
      } else if (status === "restricted") {
        match.status = {
          $ne: "active",
        };
      }

      // ==========================================
      // SEARCH
      // ==========================================

      if (search) {
        const escaped = search.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

        const regex = new RegExp(escaped, "i");

        match.$or = [
          {
            displayName: regex,
          },
          {
            email: regex,
          },
          {
            phone: regex,
          },
          {
            "checkoutProfile.name": regex,
          },
          {
            "checkoutProfile.phone": regex,
          },
        ];
      }

      // ==========================================
      // CURRENT MONTH IN BANGLADESH
      // ==========================================

      const offset = 6 * 60 * 60 * 1000;

      const dhaka = new Date(Date.now() + offset);

      const monthStart = new Date(
        Date.UTC(dhaka.getUTCFullYear(), dhaka.getUTCMonth(), 1) - offset,
      );

      // ==========================================
      // CUSTOMERS + ORDERS AGGREGATION
      // ==========================================

      const customerPipeline = [
        {
          $match: match,
        },

        // Match each registered user with
        // orders belonging to their Firebase UID.
        {
          $lookup: {
            from: "orders",

            let: {
              customerUid: "$uid",
            },

            pipeline: [
              {
                $match: {
                  $expr: {
                    $and: [
                      {
                        $eq: ["$uid", "$$customerUid"],
                      },
                      {
                        $ne: ["$$customerUid", null],
                      },
                      {
                        $ne: ["$$customerUid", ""],
                      },
                    ],
                  },
                },
              },

              {
                $sort: {
                  createdAt: -1,
                  _id: -1,
                },
              },

              {
                $group: {
                  _id: null,

                  // All customer orders
                  orderCount: {
                    $sum: 1,
                  },

                  // Successfully delivered
                  deliveredOrders: {
                    $sum: {
                      $cond: [
                        {
                          $eq: ["$status", "delivered"],
                        },
                        1,
                        0,
                      ],
                    },
                  },

                  // Delivered order value
                  totalSpent: {
                    $sum: {
                      $cond: [
                        {
                          $eq: ["$status", "delivered"],
                        },
                        {
                          $ifNull: ["$total", 0],
                        },
                        0,
                      ],
                    },
                  },

                  lastOrderAt: {
                    $first: "$createdAt",
                  },

                  lastOrderId: {
                    $first: "$_id",
                  },

                  lastOrderNumber: {
                    $first: "$orderNumber",
                  },
                },
              },
            ],

            as: "orderSummary",
          },
        },

        // Convert aggregation result into
        // a single summary object.
        {
          $addFields: {
            summary: {
              $ifNull: [
                {
                  $arrayElemAt: ["$orderSummary", 0],
                },
                {},
              ],
            },
          },
        },

        // ======================================
        // ORDER ACTIVITY FILTER
        // ======================================

        ...(ordersFilter === "with_orders"
          ? [
              {
                $match: {
                  "summary.orderCount": {
                    $gt: 0,
                  },
                },
              },
            ]
          : ordersFilter === "no_orders"
            ? [
                {
                  $match: {
                    "summary.orderCount": {
                      $exists: false,
                    },
                  },
                },
              ]
            : []),

        // ======================================
        // PAGINATION + SAFE PROJECTION
        // ======================================

        {
          $facet: {
            metadata: [
              {
                $count: "total",
              },
            ],

            customers: [
              {
                $sort: sorts[sort],
              },

              {
                $skip: skip,
              },

              {
                $limit: perPage,
              },

              {
                $project: {
                  _id: 0,

                  uid: {
                    $ifNull: ["$uid", ""],
                  },

                  name: {
                    $ifNull: [
                      "$displayName",
                      {
                        $ifNull: ["$checkoutProfile.name", ""],
                      },
                    ],
                  },

                  email: {
                    $ifNull: ["$email", ""],
                  },

                  phone: {
                    $ifNull: [
                      "$phone",
                      {
                        $ifNull: ["$checkoutProfile.phone", ""],
                      },
                    ],
                  },

                  // Profile image fallback
                  photoUrl: {
                    $ifNull: [
                      "$photoUrl",
                      {
                        $ifNull: [
                          "$photoURL",
                          {
                            $ifNull: [
                              "$imageUrl",
                              {
                                $ifNull: ["$image_url", ""],
                              },
                            ],
                          },
                        ],
                      },
                    ],
                  },

                  status: {
                    $ifNull: ["$status", "unknown"],
                  },

                  division: {
                    $ifNull: [
                      "$checkoutProfile.division",
                      {
                        $ifNull: ["$division", ""],
                      },
                    ],
                  },

                  district: {
                    $ifNull: [
                      "$checkoutProfile.district",
                      {
                        $ifNull: ["$district", ""],
                      },
                    ],
                  },

                  address: {
                    $ifNull: [
                      "$checkoutProfile.address",
                      {
                        $ifNull: ["$address", ""],
                      },
                    ],
                  },

                  createdAt: 1,

                  orderCount: {
                    $ifNull: ["$summary.orderCount", 0],
                  },

                  deliveredOrders: {
                    $ifNull: ["$summary.deliveredOrders", 0],
                  },

                  totalSpent: {
                    $ifNull: ["$summary.totalSpent", 0],
                  },

                  lastOrderAt: {
                    $ifNull: ["$summary.lastOrderAt", null],
                  },

                  lastOrderNumber: {
                    $ifNull: ["$summary.lastOrderNumber", null],
                  },

                  lastOrderId: {
                    $cond: [
                      {
                        $ifNull: ["$summary.lastOrderId", false],
                      },
                      {
                        $toString: "$summary.lastOrderId",
                      },
                      null,
                    ],
                  },
                },
              },
            ],
          },
        },
      ];

      // ==========================================
      // GLOBAL CUSTOMER STATISTICS
      // Independent of search and filters
      // ==========================================

      const statsPipeline = [
        {
          $match: {
            role: "customer",
          },
        },

        {
          $group: {
            _id: null,

            total: {
              $sum: 1,
            },

            active: {
              $sum: {
                $cond: [
                  {
                    $eq: ["$status", "active"],
                  },
                  1,
                  0,
                ],
              },
            },

            restricted: {
              $sum: {
                $cond: [
                  {
                    $ne: ["$status", "active"],
                  },
                  1,
                  0,
                ],
              },
            },

            newThisMonth: {
              $sum: {
                $cond: [
                  {
                    $gte: ["$createdAt", monthStart],
                  },
                  1,
                  0,
                ],
              },
            },
          },
        },
      ];

      // ==========================================
      // FETCH DATABASE RESULTS
      // ==========================================

      const [listRows, statsRows, guestOrders] = await Promise.all([
        users.aggregate(customerPipeline).toArray(),

        users.aggregate(statsPipeline).toArray(),

        orders.countDocuments({
          guest: true,
        }),
      ]);

      // ==========================================
      // FORMAT RESULTS
      // ==========================================

      const list = listRows[0] || {};

      const total = list.metadata?.[0]?.total || 0;

      const summary = statsRows[0] || {};

      const customers = (list.customers || []).map((customer) => ({
        ...customer,

        totalSpent: Math.round((Number(customer.totalSpent) || 0) * 100) / 100,
      }));

      // ==========================================
      // FINAL RESPONSE
      // ==========================================

      res.set("Cache-Control", "private, no-store");

      return res.status(200).json({
        success: true,

        customers,

        stats: {
          total: summary.total || 0,

          active: summary.active || 0,

          restricted: summary.restricted || 0,

          newThisMonth: summary.newThisMonth || 0,

          guestOrders,
        },

        pagination: {
          page,

          limit: perPage,

          total,

          totalPages: Math.max(1, Math.ceil(total / perPage)),

          hasNextPage: page * perPage < total,

          hasPreviousPage: page > 1,
        },
      });
    }),
  );

  // =====================================================
  // ADMIN DELIVERY MANAGEMENT
  // GET /admin/deliveries
  // Firebase Auth + Active Admin
  // No automatic status updates
  // =====================================================

  app.get(
    "/admin/deliveries",
    verifyFirebaseToken,
    verifyAdmin,
    handle(async (req, res) => {
      // =====================================
      // PAGINATION & FILTER VALIDATION
      // =====================================

      const rawPage = str(req.query.page ?? "1", 6);

      if (!/^[1-9]\d{0,5}$/.test(rawPage)) {
        fail("Invalid page number");
      }

      const page = Math.min(10000, Number(rawPage));
      const limit = 10;

      const view = str(req.query.view || "all", 24).toLowerCase();

      const sort = str(req.query.sort || "newest", 30).toLowerCase();

      const search = str(req.query.search || "", 80);

      const allowedViews = [
        "all",
        "verified",
        "processing",
        "shipped",
        "delivered",
        "overdue",
        "upcoming",
        "unassigned",
      ];

      if (!allowedViews.includes(view)) {
        fail("Invalid delivery filter");
      }

      if (!["newest", "oldest", "eta_soon"].includes(sort)) {
        fail("Invalid delivery sorting");
      }

      // =====================================
      // FILTER CONDITIONS
      // =====================================

      const now = new Date();

      const nextWeek = new Date(now.getTime() + 7 * 86400000);

      const deliveryStatuses = [
        "verified",
        "processing",
        "shipped",
        "delivered",
      ];

      const missingCourier = {
        $or: [
          {
            "courier.name": {
              $in: [null, ""],
            },
          },
          {
            "courier.trackingNumber": {
              $in: [null, ""],
            },
          },
        ],
      };

      const clauses = [
        {
          status: {
            $in: deliveryStatuses,
          },
        },
      ];

      // Status filtering
      if (["verified", "processing", "shipped", "delivered"].includes(view)) {
        clauses.push({ status: view });
      }

      // Overdue shipments
      else if (view === "overdue") {
        clauses.push({
          status: "shipped",
          estimatedDelivery: {
            $type: "date",
            $lt: now,
          },
        });
      }

      // Deliveries due in next 7 days
      else if (view === "upcoming") {
        clauses.push({
          status: "shipped",
          estimatedDelivery: {
            $gte: now,
            $lte: nextWeek,
          },
        });
      }

      // Missing courier information
      else if (view === "unassigned") {
        clauses.push(
          {
            status: {
              $in: ["verified", "processing"],
            },
          },
          missingCourier,
        );
      }

      // =====================================
      // SEARCH
      // =====================================

      if (search) {
        const escaped = search.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

        const regex = new RegExp(escaped, "i");

        clauses.push({
          $or: [
            { orderNumber: regex },
            { "customer.name": regex },
            { "customer.phone": regex },
            { "shipping.phone": regex },
            { "shipping.district": regex },
            { "courier.name": regex },
            { "courier.trackingNumber": regex },
          ],
        });
      }

      const query = {
        $and: clauses,
      };

      // =====================================
      // SORT
      // =====================================

      const orderBy =
        sort === "oldest"
          ? {
              createdAt: 1,
              _id: 1,
            }
          : sort === "eta_soon"
            ? {
                estimatedDelivery: 1,
                createdAt: -1,
                _id: -1,
              }
            : {
                createdAt: -1,
                _id: -1,
              };

      // =====================================
      // FETCH ORDERS, COUNTS & STATS
      // =====================================

      const [docs, total, byStatus, overdueCount] = await Promise.all([
        // Filtered delivery orders
        orders
          .find(query, {
            projection: {
              _id: 1,
              uid: 1,
              guest: 1,
              orderNumber: 1,
              createdAt: 1,
              status: 1,
              total: 1,
              estimatedDelivery: 1,
              deliveredAt: 1,

              "customer.name": 1,
              "customer.phone": 1,

              "shipping.phone": 1,
              "shipping.address": 1,
              "shipping.district": 1,
              "shipping.division": 1,

              "courier.name": 1,
              "courier.trackingNumber": 1,
              "courier.trackingUrl": 1,
              "courier.parcelWeight": 1,

              "payment.method": 1,
              "payment.status": 1,

              "items.name": 1,
              "items.image": 1,
              "items.quantity": 1,
              "items.cartId": 1,
            },
          })
          .sort(orderBy)
          .skip((page - 1) * limit)
          .limit(limit)
          .toArray(),

        // Filtered total
        orders.countDocuments(query),

        // Global status stats
        orders
          .aggregate([
            {
              $match: {
                status: {
                  $in: deliveryStatuses,
                },
              },
            },
            {
              $group: {
                _id: "$status",
                total: {
                  $sum: 1,
                },
              },
            },
          ])
          .toArray(),

        // Global overdue count
        orders.countDocuments({
          status: "shipped",
          estimatedDelivery: {
            $type: "date",
            $lt: now,
          },
        }),
      ]);

      // =====================================
      // REGISTERED CUSTOMER PROFILE IMAGES
      // =====================================

      const customerUids = [
        ...new Set(
          docs
            .filter((order) => !order.guest && order.uid)
            .map((order) => order.uid),
        ),
      ];

      const accounts = customerUids.length
        ? await users
            .find(
              {
                uid: {
                  $in: customerUids,
                },
              },
              {
                projection: {
                  uid: 1,
                  photoUrl: 1,
                  photoURL: 1,
                  imageUrl: 1,
                  image_url: 1,
                },
              },
            )
            .toArray()
        : [];

      const photos = new Map(
        accounts.map((account) => [
          account.uid,
          account.photoUrl ||
            account.photoURL ||
            account.imageUrl ||
            account.image_url ||
            "",
        ]),
      );

      // =====================================
      // STATUS COUNTS
      // =====================================

      const counts = Object.fromEntries(
        byStatus.map((item) => [item._id, item.total]),
      );

      // =====================================
      // DELIVERY TABLE RESPONSE
      // =====================================

      const deliveries = docs.map((order) => {
        const items = Array.isArray(order.items) ? order.items : [];

        return {
          _id: order._id.toString(),

          orderNumber: order.orderNumber,

          createdAt: order.createdAt,

          status: order.status,

          total: Number(order.total || 0),

          guest: order.guest === true,

          customer: {
            name: order.customer?.name || "",
            phone: order.customer?.phone || "",
          },

          customerPhotoUrl: order.guest ? "" : photos.get(order.uid) || "",

          shipping: order.shipping || {},

          courier: {
            name: order.courier?.name || "",

            trackingNumber: order.courier?.trackingNumber || "",

            trackingUrl: order.courier?.trackingUrl || "",

            parcelWeight: order.courier?.parcelWeight || "",
          },

          payment: {
            method: order.payment?.method || "",
            status: order.payment?.status || "",
          },

          estimatedDelivery: order.estimatedDelivery || null,

          deliveredAt: order.deliveredAt || null,

          itemCount: items.reduce(
            (sum, item) => sum + (Number(item.quantity) || 0),
            0,
          ),

          items: items.slice(0, 2).map((item) => ({
            name: item.name || "",
            image: item.image || "",
            quantity: Number(item.quantity || 1),
            cartId: item.cartId || "",
          })),
        };
      });

      // =====================================
      // FINAL RESPONSE
      // =====================================

      res.set("Cache-Control", "private, no-store");

      return res.json({
        success: true,

        stats: {
          verified: counts.verified || 0,
          processing: counts.processing || 0,
          shipped: counts.shipped || 0,
          delivered: counts.delivered || 0,
          overdue: overdueCount,
        },

        deliveries,

        pagination: {
          page,
          limit,
          total,

          totalPages: Math.max(1, Math.ceil(total / limit)),

          hasNextPage: page * limit < total,

          hasPreviousPage: page > 1,
        },
      });
    }),
  );

  console.log("SokhBilash Cart, Checkout and Order APIs ready");
};
