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

  app.get("/admin/orders", ...listAdmin("orders"));

  app.get("/admin/payments", ...listAdmin("payments"));

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

      res.set("Cache-Control", "no-store");

      res.json({
        success: true,

        order: viewOrder(order),
      });
    }),
  );

  // =========================================
  // ADMIN PAYMENT VERIFICATION
  // =========================================

  app.patch(
    "/admin/orders/:identifier/payment",
    verifyFirebaseToken,
    verifyAdmin,
    handle(async (req, res) => {
      const decision = str(req.body.decision, 20);

      if (!["verify", "reject"].includes(decision)) {
        fail("Invalid decision");
      }

      const updated = await updateOrder(
        req.params.identifier,

        (order) => {
          if (order.payment.method === "cod") {
            fail("Use phone confirmation for COD", 409);
          }

          if (
            order.status !== "pending" ||
            !["pending", "partially_paid"].includes(order.payment.status)
          ) {
            fail("Payment is not pending verification", 409);
          }

          // REJECT

          if (decision === "reject") {
            const reason = str(req.body.reason, 500);

            if (!reason) {
              fail("Rejection reason required");
            }

            return {
              set: {
                status: "rejected",

                payment: {
                  ...order.payment,

                  status: "rejected",

                  rejectedReason: reason,

                  verifiedBy: req.user.uid,

                  verifiedAt: new Date(),
                },
              },

              event: "payment_rejected",

              note: reason,

              by: req.user.uid,
            };
          }

          // VERIFY
          // verifiedAmount is cumulative.

          const amount = parseAmount(
            req.body.verifiedAmount,
            "verified amount",
          );

          const previouslyVerified = currency(
            order.payment.verifiedAmount || 0,
          );

          if (amount < previouslyVerified) {
            fail("Verified amount cannot decrease", 409);
          }

          if (amount > order.total) {
            fail("Amount exceeds order total");
          }

          if (
            amount >
            currency(previouslyVerified + (order.payment.claimedAmount || 0))
          ) {
            fail("Amount exceeds customer-submitted payment claim");
          }

          const fullyPaid = amount >= currency(order.total);

          return {
            set: {
              status: fullyPaid ? "verified" : "pending",

              payment: {
                ...order.payment,

                status: fullyPaid ? "verified" : "partially_paid",

                verifiedAmount: amount,

                dueAmount: currency(order.total - amount),

                verifiedAt: new Date(),

                verifiedBy: req.user.uid,

                rejectedReason: null,
              },
            },

            event: fullyPaid
              ? "payment_verified"
              : "payment_partially_verified",

            note: `Verified BDT ${amount}`,

            by: req.user.uid,
          };
        },
      );

      res.json({
        success: true,

        message: "Payment updated",

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
      const name = str(req.body.name, 150);

      const trackingNumber = str(req.body.trackingNumber, 150);

      const trackingUrl = str(req.body.trackingUrl, 2048);

      if (trackingUrl && !validHttpsUrl(trackingUrl)) {
        fail("Invalid tracking URL");
      }

      const date = req.body.estimatedDelivery || null;

      if (date && Number.isNaN(Date.parse(date))) {
        fail("Invalid estimated delivery date");
      }

      const updated = await updateOrder(
        req.params.identifier,

        (order) => {
          if (["rejected", "cancelled"].includes(order.status)) {
            fail("Inactive order", 409);
          }

          return {
            set: {
              courier: {
                name: name || null,

                trackingNumber: trackingNumber || null,

                trackingUrl: trackingUrl || null,
              },

              estimatedDelivery: date ? new Date(date) : null,
            },

            event: "tracking_updated",

            note: trackingNumber
              ? `Tracking: ${trackingNumber}`
              : "Courier updated",

            by: req.user.uid,
          };
        },
      );

      res.json({
        success: true,

        message: "Tracking updated",

        order: viewOrder(updated),
      });
    }),
  );

  console.log("SokhBilash Cart, Checkout and Order APIs ready");
};
