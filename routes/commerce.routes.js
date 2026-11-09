// Part 1

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

const DISTRICTS = require("../utils/bangladeshRegions");

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
    orders.createIndex({ uid: 1, createdAt: -1 }),
    orders.createIndex({ status: 1, createdAt: -1 }),
    orders.createIndex({ "payment.status": 1, createdAt: -1 }),
  ]);

  const limit = (max, message) =>
    rateLimit({
      windowMs: 15 * 60 * 1000,
      limit: max,
      standardHeaders: "draft-7",
      legacyHeaders: false,
      message: { success: false, message },
    });

  const quoteLimit = limit(40, "Too many quote requests");
  const orderLimit = limit(8, "Too many order attempts");
  const trackingLimit = limit(5, "Too many tracking attempts");
  const proofLimit = limit(5, "Too many payment submissions");
  const lookupLimit = limit(10, "Too many order lookups");

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
    if (typeof value !== "string") fail("Invalid text value");
    const clean = value.trim();
    if (clean.length > max) fail(`Text exceeds ${max} characters`);
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

  // Total received can include both online payment and delivery cash.
  const onlineReceived = (payment) =>
    Math.max(
      0,
      currency(
        payment?.onlineVerifiedAmount ??
          (payment?.verifiedAmount || 0) - (payment?.cashCollected || 0),
      ),
    );

  const refundableBalance = (payment) =>
    Math.max(
      0,
      currency((payment?.verifiedAmount || 0) - (payment?.refundedAmount || 0)),
    );

  const mongoOnlineReceived = {
    $max: [
      0,
      {
        $ifNull: [
          "$payment.onlineVerifiedAmount",
          {
            $subtract: [
              { $ifNull: ["$payment.verifiedAmount", 0] },
              { $ifNull: ["$payment.cashCollected", 0] },
            ],
          },
        ],
      },
    ],
  };

  const newCancellationRefund = (payment, reason, now) => {
    const remaining = refundableBalance(payment);

    return {
      status: remaining > 0 ? "pending" : "not_required",
      totalAmount: remaining,
      remainingAmount: remaining,
      reason: reason || "Order cancelled",
      createdAt: now,
      completedAt: remaining === 0 ? now : null,
    };
  };

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
    if (!validHttpsUrl(value)) return false;
    return allowedImageHosts.has(new URL(value).hostname.toLowerCase());
  };

  const orderFilter = (identifier) => {
    const value = str(identifier, 100);
    if (!value) fail("Order identifier required");

    if (validObjectId(value)) {
      return {
        $or: [{ _id: new ObjectId(value) }, { orderNumber: value }],
      };
    }

    return { orderNumber: value.toUpperCase() };
  };

  // Admin-only response.
  const viewAdminOrder = (doc) => {
    if (!doc) return null;

    const { checkoutId, guestTokenHash, paymentTrxIds, ...rest } = doc;

    return {
      ...rest,
      _id: rest._id.toString(),
    };
  };

  // Customer and guest responses must exclude private admin data.
  const viewOrder = (doc) => {
    const original = viewAdminOrder(doc);
    if (!original) return null;

    const { payment: rawPayment, history, phoneConfirmation } = original;

    const p = rawPayment || {};
    const r = p.excessResolution;
    const c = p.cancellationRefund;

    return {
      _id: original._id,
      orderNumber: original.orderNumber,
      guest: original.guest === true,
      customer: original.customer,
      shipping: original.shipping,
      items: original.items,
      subtotal: original.subtotal,
      deliveryCharge: original.deliveryCharge,
      giftWrapCharge: original.giftWrapCharge || 0,
      giftOptions: original.giftOptions || { message: "" },
      discount: original.discount || 0,
      total: original.total,
      status: original.status,
      phoneConfirmed: original.phoneConfirmed === true,
      courier: original.courier || null,
      estimatedDelivery: original.estimatedDelivery || null,
      deliveredAt: original.deliveredAt || null,
      createdAt: original.createdAt,
      updatedAt: original.updatedAt,

      payment: {
        method: p.method || null,
        status: p.status || null,
        senderPhone: p.senderPhone || null,
        trxId: p.trxId || null,
        claimedAmount: currency(p.claimedAmount || 0),
        note: p.note || "",
        claimDifference: p.claimDifference || null,
        verifiedAmount: currency(p.verifiedAmount || 0),
        onlineVerifiedAmount: currency(
          p.onlineVerifiedAmount ??
            Math.max(0, (p.verifiedAmount || 0) - (p.cashCollected || 0)),
        ),
        cashCollected: currency(p.cashCollected || 0),
        dueAmount: currency(p.dueAmount || 0),
        excessAmount: currency(p.excessAmount || 0),
        refundedAmount: currency(p.refundedAmount || 0),
        rejectedReason: p.rejectedReason || null,
        verifiedAt: p.verifiedAt || null,

        excessResolution: r
          ? {
              type: r.type,
              amount: r.amount,
              status: r.status,
              completedAt: r.completedAt || null,
            }
          : null,

        cancellationRefund: c
          ? {
              status: c.status,
              totalAmount: c.totalAmount,
              remainingAmount: c.remainingAmount,
              completedAt: c.completedAt || null,
            }
          : null,
      },

      phoneConfirmation: phoneConfirmation
        ? {
            confirmed: phoneConfirmation.confirmed === true,
            confirmedAt: phoneConfirmation.confirmedAt || null,
          }
        : null,

      history: (Array.isArray(history) ? history : [])
        .filter((entry) => entry.status !== "internal_note_added")
        .map((entry) => ({
          status: entry.status,
          date: entry.date,
        })),
    };
  };

  const region = (customer) => {
    const division = str(customer?.division, 80);
    const district = str(customer?.district, 80);

    if (!DISTRICTS[division]?.includes(district)) {
      fail("Invalid division or district");
    }

    return { division, district };
  };

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

  // Part 2 — Cart APIs

  const customerOrGuest = async (req, res, next) => {
    if (!req.user) return next();

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

  // ==========================================
  // PRODUCT + CART LINE
  // ==========================================

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

    const product = await products.findOne({
      _id: new ObjectId(productId),
      status: "published",
    });

    if (!product) fail("Product not found", 404);
    if (product.available !== true) fail("Product unavailable", 409);

    let variant = null;
    let variantKey = "";

    if (product.variantsEnabled === true) {
      variantKey = str(raw.variantKey, 220);
      variant = (product.variants || []).find((v) => v.key === variantKey);

      if (!variant || variant.available === false) {
        fail("Variant unavailable", 409);
      }
    }

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

    if (unitPrice <= 0) fail("Invalid unit price", 409);

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

    const signature = digest(
      JSON.stringify({
        productId,
        variantKey,
        packaging,
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
      selectedOptions: variant ? { ...variant.options } : {},
      packaging,
      premiumBoxPrice: extra,
      customization,
      price: unitPrice,
      unitPrice,
      addedAt: new Date().toISOString(),
    };
  };

  // ==========================================
  // CART MERGING AND ATOMIC UPDATE
  // ==========================================

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

    return [...lines, { ...incoming, cartId }];
  };

  const mutateCart = async (uid, cb) => {
    for (let attempt = 0; attempt < 10; attempt++) {
      const current = await carts.findOne({ uid });

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

      if (change === null) return base;

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

          return { ...data, version: 1 };
        } catch (error) {
          if (error.code === 11000) continue;
          throw error;
        }
      }

      const result = await carts.updateOne(
        { uid, version: current.version },
        {
          $set: data,
          $inc: { version: 1 },
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
    const doc = await carts.findOne({ uid });

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
          .filter((line) => !line.unavailable)
          .reduce((sum, line) => sum + line.unitPrice * line.quantity, 0),
      ),
    };
  };

  // ==========================================
  // CART ROUTES
  // ==========================================

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

        if (index < 0) fail("Cart item not found", 404);

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

        if (!item) fail("Cart item not found", 404);

        cart.items = cart.items.map((line) =>
          line.cartId === item.cartId ? { ...line, quantity } : line,
        );

        return cart;
      });

      res.json({
        success: true,
        cart: await viewCart(req.user.uid),
      });
    }),
  );

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

  app.post(
    "/cart/merge",
    verifyFirebaseToken,
    activeAccount,
    handle(async (req, res) => {
      const mergeId = requireId(req.body?.mergeId);
      const guestItems = req.body?.items;

      if (!Array.isArray(guestItems) || guestItems.length > LIMIT_ITEMS) {
        fail("Invalid guest cart", 400);
      }

      const validated = await Promise.all(guestItems.map(buildCartLine));

      let alreadyMerged = false;

      await mutateCart(req.user.uid, (cart) => {
        if (cart.mergeIds.includes(mergeId)) {
          alreadyMerged = true;
          return null;
        }

        alreadyMerged = false;

        for (const line of validated) {
          const present = cart.items.some(
            (item) =>
              item.cartId === line.cartId && item.signature === line.signature,
          );

          if (!present) {
            cart.items = combineLine(cart.items, line);
          }
        }

        cart.mergeIds = [...cart.mergeIds, mergeId].slice(-50);

        return cart;
      });

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

  // Part 3 — Checkout, Profile ও Payment Validation

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

    return { name, phone, email, address, division, district, note };
  };

  const cleanProfileString = (value) =>
    typeof value === "string" ? value.trim() : "";

  const checkoutProfileView = async (account) => {
    const saved = account.checkoutProfile || {};

    const lastOrder = await orders.findOne(
      { uid: account.uid },
      {
        sort: { createdAt: -1 },
        projection: { _id: 0, customer: 1 },
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

  app.get(
    "/checkout/profile",
    verifyFirebaseToken,
    activeAccount,
    handle(async (req, res) => {
      const account = await users.findOne(
        { uid: req.user.uid, status: "active" },
        {
          projection: {
            uid: 1,
            displayName: 1,
            phone: 1,
            checkoutProfile: 1,
          },
        },
      );

      if (!account) fail("Account unavailable", 403);

      const profile = await checkoutProfileView(account);
      res.set("Cache-Control", "no-store");

      return res.json({ success: true, profile });
    }),
  );

  const checkoutProfileMergeLimit = limit(12, "Too many profile sync requests");

  app.post(
    "/checkout/profile/merge-guest",
    checkoutProfileMergeLimit,
    verifyFirebaseToken,
    activeAccount,
    handle(async (req, res) => {
      const guest = req.body?.profile;

      const validated = validateCustomer({
        name: guest?.name,
        phone: guest?.phone,
        address: guest?.address,
        division: guest?.division,
        district: guest?.district,
        note: "",
      });

      const account = await users.findOne(
        { uid: req.user.uid, status: "active" },
        {
          projection: {
            uid: 1,
            displayName: 1,
            phone: 1,
            checkoutProfile: 1,
          },
        },
      );

      if (!account) fail("Account unavailable", 403);

      const dbProfile = await checkoutProfileView(account);

      const candidate = {
        name: dbProfile.name || validated.name,
        phone: dbProfile.phone || validated.phone,
        division: dbProfile.division || validated.division,
        district: dbProfile.district || validated.district,
        address: dbProfile.address || validated.address,
      };

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

      const compatibleRegion = {
        $and: [
          {
            $in: [
              { $ifNull: ["$checkoutProfile.division", ""] },
              ["", candidate.division],
            ],
          },
          {
            $in: [
              { $ifNull: ["$checkoutProfile.district", ""] },
              ["", candidate.district],
            ],
          },
        ],
      };

      await users.updateOne({ uid: req.user.uid, status: "active" }, [
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
      ]);

      const fresh = await users.findOne(
        { uid: req.user.uid, status: "active" },
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

    if (couponCode) fail("Coupons are not enabled");

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
      fail("Invalid gift options");
    }

    const giftWrapCharge = 0;
    const message = str(options.message, 250);
    const total = currency(subtotal + deliveryCharge);

    return {
      items: lines,
      subtotal,
      deliveryCharge,
      giftWrapCharge,
      giftOptions: { message },
      discount: 0,
      total,
    };
  };

  const validatePayment = (input, total) => {
    const payment = input || {};
    const method = str(payment.method, 20).toLowerCase();

    if (!["bkash", "nagad", "rocket", "cod"].includes(method)) {
      fail("Invalid payment method");
    }

    const base = {
      method,
      verifiedAmount: 0,
      onlineVerifiedAmount: 0,
      dueAmount: currency(total),
      excessAmount: 0,
      cashCollected: 0,
      deliveryCollections: [],
      refundedAmount: 0,
      refunds: [],
      cancellationRefund: null,
      excessResolution: null,
      verifiedAt: null,
      verifiedBy: null,
      rejectedReason: null,
      reviews: [],
    };

    if (method === "cod") {
      return {
        ...base,
        status: "cod_pending",
        senderPhone: null,
        trxId: null,
        claimedAmount: 0,
        note: "",
        claimDifference: {
          type: "cod",
          amount: currency(total),
        },
      };
    }

    const senderPhone = str(payment.senderPhone, 30).replace(/\s/g, "");

    const trxId = str(payment.trxId, 60).toUpperCase();

    if (!/^01[3-9]\d{8}$/.test(senderPhone)) {
      fail("Invalid sender phone");
    }

    if (!/^[A-Z0-9_-]{5,60}$/.test(trxId)) {
      fail("Invalid Transaction ID");
    }

    const claimedAmount = parseAmount(payment.amount, "payment amount");

    const difference = currency(claimedAmount - total);

    return {
      ...base,
      status: "pending",
      senderPhone,
      trxId,
      claimedAmount,
      note: str(payment.note, 200),
      claimDifference: {
        type:
          difference < 0 ? "underpaid" : difference > 0 ? "overpaid" : "exact",
        amount: Math.abs(difference),
      },
    };
  };

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

  // Part 4 — Order Creation, History, Tracking ও Payment Proof

  app.post(
    "/orders",
    orderLimit,
    optionalAuth,
    customerOrGuest,
    handle(async (req, res) => {
      const checkoutId = checkoutIdOf(req.body.checkoutId);
      const previous = await orders.findOne({ checkoutId });

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

        if (!account) fail("Active account required", 403);
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
          ? { paymentTrxIds: [`${payment.method}:${payment.trxId}`] }
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
          const first = await orders.findOne({ checkoutId });

          if (first) {
            return answerExisting(req, res, first, checkoutId);
          }

          fail("Duplicate order or TrxID", 409);
        }

        throw error;
      }

      if (account) {
        try {
          await users.updateOne(
            { uid: account.uid, status: "active" },
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
          console.error(
            "Checkout profile update failed:",
            profileError.message,
          );
        }
      }

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

              return remaining > 0 ? [{ ...line, quantity: remaining }] : [];
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

  app.get(
    "/orders/my",
    verifyFirebaseToken,
    handle(async (req, res) => {
      const uid = req.user?.uid;

      if (!uid) {
        return res.status(401).json({
          success: false,
          message: "Authentication required",
        });
      }

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
        "cod_collected",
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

      if (search && !/^[A-Z0-9-]{1,60}$/.test(search)) {
        fail("Invalid order number search", 400);
      }

      const query = { uid };

      if (status && status !== "all") {
        query.status = status;
      }

      if (paymentStatus && paymentStatus !== "all") {
        query["payment.status"] = paymentStatus;
      }

      if (search) {
        query.orderNumber = new RegExp(`^${search}`);
      }

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

      const [orderDocuments, filteredTotal, statusCounts] = await Promise.all([
        orders
          .find(query, { projection })
          .sort({ createdAt: -1, _id: -1 })
          .skip(skip)
          .limit(perPage)
          .toArray(),

        orders.countDocuments(query),

        orders
          .aggregate([
            { $match: { uid } },
            {
              $group: {
                _id: "$status",
                count: { $sum: 1 },
              },
            },
          ])
          .toArray(),
      ]);

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

      if (!order) return deny();

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

  const updateOrder = async (identifier, buildChange) => {
    for (let i = 0; i < 8; i++) {
      const previous = await orders.findOne(orderFilter(identifier));

      if (!previous) fail("Order not found", 404);

      const change = await buildChange(previous);

      if (change?.noop === true) return previous;
      if (!change?.set) fail("No changes supplied");

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

  app.post(
    "/orders/:identifier/payment-proof",
    proofLimit,
    optionalAuth,
    handle(async (req, res) => {
      const updated = await updateOrder(req.params.identifier, (order) => {
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

        const trxKey = `${payment.method}:${payment.trxId}`;

        if ((order.paymentTrxIds || []).includes(trxKey)) {
          fail("Previously submitted TrxID", 409);
        }

        return {
          set: {
            payment: {
              ...payment,
              verifiedAmount: verified,

              onlineVerifiedAmount: onlineReceived(order.payment),

              dueAmount: Math.max(0, currency(order.total - verified)),

              excessAmount: Math.max(0, currency(verified - order.total)),

              cashCollected: currency(order.payment.cashCollected || 0),

              deliveryCollections: order.payment.deliveryCollections || [],

              refundedAmount: currency(order.payment.refundedAmount || 0),

              refunds: order.payment.refunds || [],

              cancellationRefund: order.payment.cancellationRefund || null,

              reviews: order.payment.reviews || [],
              excessResolution: null,
              status: "pending",
            },

            paymentTrxIds: [...(order.paymentTrxIds || []), trxKey],

            phoneConfirmed: false,
            status: "pending",
          },

          event: "payment_resubmitted",
          note: "Customer resubmitted payment proof",
          by: order.uid || "guest",
        };
      });

      res.set("Cache-Control", "no-store");

      res.json({
        success: true,
        order: viewOrder(updated),
      });
    }),
  );

  // Part 5 — Admin Orders, Payments ও Private Notes

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

      const [documents, filteredTotal, statusRows, custom] = await Promise.all([
        orders
          .find(filter, {
            projection: {
              checkoutId: 0,
              guestTokenHash: 0,
              paymentTrxIds: 0,
            },
          })
          .sort({ createdAt: -1, _id: -1 })
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
              { uid: { $in: customerUids } },
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

      const onlineFilter = {
        "payment.method": {
          $in: ["bkash", "nagad", "rocket"],
        },
      };

      const filter = { ...onlineFilter };

      if (status === "pending") {
        filter["payment.status"] = {
          $in: ["pending", "partially_paid"],
        };
      } else if (status && status !== "all") {
        filter["payment.status"] = status;
      }

      if (method && method !== "all") {
        filter["payment.method"] = method;
      }

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

      const statsPipeline = [
        {
          $match: onlineFilter,
        },
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
              $sum: mongoOnlineReceived,
            },

            cashCollection: {
              $sum: {
                $ifNull: ["$payment.cashCollected", 0],
              },
            },

            grossCollection: {
              $sum: {
                $ifNull: ["$payment.verifiedAmount", 0],
              },
            },

            refundedCollection: {
              $sum: {
                $ifNull: ["$payment.refundedAmount", 0],
              },
            },
          },
        },
      ];

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
          .sort({ createdAt: -1, _id: -1 })
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
        cashCollection: 0,
        grossCollection: 0,
        refundedCollection: 0,
      };

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
              { uid: { $in: customerUids } },
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
            customerPhotoUrl: customerPhotoMap.get(uid) || "",
            itemCount,
            items: items.slice(0, 2),
          };
        }),

        stats: {
          total: stats.total,
          pending: stats.pending,
          partiallyPaid: stats.partiallyPaid,
          verified: stats.verified,
          rejected: stats.rejected,

          verifiedCollection: currency(stats.verifiedCollection || 0),

          cashCollection: currency(stats.cashCollection || 0),

          grossCollection: currency(stats.grossCollection || 0),

          refundedCollection: currency(stats.refundedCollection || 0),

          netCollection: currency(
            (stats.grossCollection || 0) - (stats.refundedCollection || 0),
          ),
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

  app.get(
    "/admin/orders/:identifier",
    verifyFirebaseToken,
    verifyAdmin,
    handle(async (req, res) => {
      const order = await orders.findOne(orderFilter(req.params.identifier));

      if (!order) fail("Order not found", 404);

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
          ...viewAdminOrder(order),
          customerPhotoUrl,
          internalNotes: order.internalNotes || [],
        },
      });
    }),
  );

  app.post(
    "/admin/orders/:identifier/notes",
    verifyFirebaseToken,
    verifyAdmin,
    handle(async (req, res) => {
      const text = str(req.body?.text, 1000);

      if (!text) fail("Note cannot be empty");

      const updated = await updateOrder(req.params.identifier, (order) => {
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
          note: "Admin-only note added",
          by: req.user.uid,
        };
      });

      res.set("Cache-Control", "no-store");

      return res.status(201).json({
        success: true,
        message: "Internal note saved",
        order: {
          ...viewAdminOrder(updated),
          internalNotes: updated.internalNotes || [],
        },
      });
    }),
  );

  // Part 6 — Payment Verification, Phone Confirmation ও COD Collection

  app.patch(
    "/admin/orders/:identifier/payment",
    verifyFirebaseToken,
    verifyAdmin,
    handle(async (req, res) => {
      const decision = str(req.body?.decision, 20).toLowerCase();

      if (!["verify", "reject"].includes(decision)) {
        fail("Invalid payment decision");
      }

      const updated = await updateOrder(req.params.identifier, (order) => {
        const payment = order.payment || {};

        if (payment.method === "cod") {
          fail("Use phone confirmation for COD", 409);
        }

        if (order.status !== "pending" || payment.status !== "pending") {
          fail("This payment proof is not pending review", 409);
        }

        const previous = currency(payment.verifiedAmount || 0);

        const priorReviews = Array.isArray(payment.reviews)
          ? payment.reviews
          : [];

        const now = new Date();

        if (decision === "reject") {
          const reason = str(req.body?.reason, 500);

          if (!reason) {
            fail("Rejection reason required");
          }

          return {
            set: {
              status: "rejected",
              phoneConfirmed: false,

              payment: {
                ...payment,
                status: "rejected",
                rejectedReason: reason,
                verifiedAmount: previous,

                onlineVerifiedAmount: onlineReceived(payment),

                cancellationRefund:
                  previous > 0
                    ? newCancellationRefund(payment, reason, now)
                    : null,

                dueAmount: Math.max(0, currency(order.total - previous)),

                excessAmount: Math.max(0, currency(previous - order.total)),

                verifiedBy: req.user.uid,
                verifiedAt: now,

                reviews: [
                  ...priorReviews,
                  {
                    decision: "reject",
                    trxId: payment.trxId,
                    claimedAmount: payment.claimedAmount,
                    reason,
                    by: req.user.uid,
                    at: now,
                  },
                ],
              },
            },

            event: "payment_rejected",
            note: reason,
            by: req.user.uid,
          };
        }

        const verifiedAmount = parseAmount(
          req.body?.verifiedAmount,
          "verified amount",
        );

        const receivedNow = currency(verifiedAmount - previous);

        const cashAlready = currency(payment.cashCollected || 0);

        const newOnline = currency(verifiedAmount - cashAlready);

        if (newOnline < onlineReceived(payment)) {
          fail("Mobile receipts cannot decrease", 409);
        }

        if (receivedNow <= 0) {
          fail(
            "Verified amount must exceed the previously recorded amount",
            409,
          );
        }

        const dueAmount = Math.max(0, currency(order.total - verifiedAmount));

        const excessAmount = Math.max(
          0,
          currency(verifiedAmount - order.total),
        );

        const status = dueAmount > 0 ? "partially_paid" : "verified";

        const previousResolution = payment.excessResolution;

        const resolution =
          excessAmount > 0 && previousResolution?.amount === excessAmount
            ? previousResolution
            : null;

        const ready =
          order.phoneConfirmed === true &&
          (excessAmount === 0 || Boolean(resolution?.type));

        return {
          set: {
            status: ready ? "verified" : "pending",

            payment: {
              ...payment,
              status,
              verifiedAmount,
              onlineVerifiedAmount: newOnline,
              dueAmount,
              excessAmount,
              excessResolution: resolution,
              verifiedAt: now,
              verifiedBy: req.user.uid,
              reviewedTrxId: payment.trxId,
              rejectedReason: null,

              reviews: [
                ...priorReviews,
                {
                  decision: "verify",
                  trxId: payment.trxId,
                  claimedAmount: payment.claimedAmount,
                  receivedForProof: receivedNow,
                  cumulativeReceived: verifiedAmount,
                  by: req.user.uid,
                  at: now,
                },
              ],
            },
          },

          event:
            excessAmount > 0
              ? "payment_overpaid_verified"
              : dueAmount > 0
                ? "payment_partially_verified"
                : "payment_fully_verified",

          note:
            `Received BDT ${receivedNow}; ` +
            `cumulative ${verifiedAmount}; ` +
            `due ${dueAmount}; excess ${excessAmount}`,

          by: req.user.uid,
        };
      });

      res.set("Cache-Control", "no-store");

      return res.json({
        success: true,
        message: "Payment reviewed successfully",
        order: viewAdminOrder(updated),
      });
    }),
  );

  app.patch(
    "/admin/orders/:identifier/phone-confirmation",
    verifyFirebaseToken,
    verifyAdmin,
    handle(async (req, res) => {
      if (typeof req.body?.confirmed !== "boolean") {
        fail("confirmed must be boolean");
      }

      const confirmed = req.body.confirmed;
      const note = str(req.body?.note, 500);

      const resolutionType = str(req.body?.excessResolution, 30).toLowerCase();

      if (
        resolutionType &&
        !["refund", "extra_product"].includes(resolutionType)
      ) {
        fail("Invalid excess resolution");
      }

      const updated = await updateOrder(req.params.identifier, (order) => {
        if (!["pending", "verified"].includes(order.status)) {
          fail("Phone confirmation cannot be changed at this order stage", 409);
        }

        const payment = order.payment || {};

        const verified = currency(payment.verifiedAmount || 0);

        const excessAmount = Math.max(0, currency(verified - order.total));

        let excessResolution = payment.excessResolution || null;

        if (confirmed && excessAmount > 0) {
          if (!resolutionType && !excessResolution?.type) {
            fail("Customer must agree to refund or extra_product", 409);
          }

          if (resolutionType) {
            if (!note) {
              fail("Customer agreement note required");
            }

            if (
              excessResolution?.status === "completed" &&
              excessResolution.type !== resolutionType
            ) {
              fail("Completed resolution cannot be changed", 409);
            }

            const same =
              excessResolution?.type === resolutionType &&
              excessResolution?.amount === excessAmount;

            excessResolution = same
              ? excessResolution
              : {
                  type: resolutionType,
                  amount: excessAmount,
                  status: "pending",
                  note,
                  agreedAt: new Date(),
                  agreedBy: req.user.uid,
                  completedAt: null,
                };
          }
        }

        const paymentReviewed =
          payment.method === "cod" ||
          ["verified", "partially_paid", "cod_collected"].includes(
            payment.status,
          );

        const resolutionReady =
          excessAmount === 0 || Boolean(excessResolution?.type);

        const approve = confirmed && paymentReviewed && resolutionReady;

        return {
          set: {
            phoneConfirmed: confirmed,

            phoneConfirmation: {
              confirmed,
              note,
              confirmedAt: confirmed ? new Date() : null,
              confirmedBy: confirmed ? req.user.uid : null,
            },

            payment: {
              ...payment,
              excessResolution,
            },

            status: approve ? "verified" : "pending",
          },

          event: confirmed ? "phone_confirmed" : "phone_unconfirmed",

          note:
            note ||
            (confirmed
              ? "Customer confirmed by phone"
              : "Confirmation revoked"),

          by: req.user.uid,
        };
      });

      res.set("Cache-Control", "no-store");

      return res.json({
        success: true,
        order: viewAdminOrder(updated),
      });
    }),
  );

  app.patch(
    "/admin/orders/:identifier/collect-balance",
    verifyFirebaseToken,
    verifyAdmin,
    handle(async (req, res) => {
      const collectionId = checkoutIdOf(req.body?.collectionId);

      const collectedAmount = parseAmount(req.body?.amount, "collected amount");

      const note = str(req.body?.note, 500);

      if (!note) {
        fail("Collection note is required");
      }

      const updated = await updateOrder(req.params.identifier, (order) => {
        const payment = order.payment || {};

        const existing = Array.isArray(payment.deliveryCollections)
          ? payment.deliveryCollections
          : [];

        const sameId = existing.find(
          (entry) => entry.collectionId === collectionId,
        );

        if (sameId) {
          if (currency(sameId.amount) !== currency(collectedAmount)) {
            fail("Collection ID has already been used for another amount", 409);
          }

          return { noop: true };
        }

        if (
          !["verified", "processing", "shipped", "delivered"].includes(
            order.status,
          )
        ) {
          fail("Order is not ready for balance collection", 409);
        }

        if (order.phoneConfirmed !== true) {
          fail("Phone confirmation required", 409);
        }

        const previousReceived = currency(payment.verifiedAmount || 0);

        const currentDue = Math.max(
          0,
          currency(order.total - previousReceived),
        );

        if (currentDue <= 0) {
          fail("No outstanding balance", 409);
        }

        if (currency(collectedAmount) > currentDue) {
          fail("Collection amount exceeds outstanding balance", 409);
        }

        const newReceived = currency(previousReceived + collectedAmount);

        const newDue = Math.max(0, currency(order.total - newReceived));

        const cashCollected = currency(
          (payment.cashCollected || 0) + collectedAmount,
        );

        const paymentStatus =
          payment.method === "cod"
            ? newDue === 0
              ? "cod_collected"
              : "cod_pending"
            : newDue === 0
              ? "verified"
              : "partially_paid";

        return {
          set: {
            payment: {
              ...payment,
              status: paymentStatus,
              verifiedAmount: newReceived,

              onlineVerifiedAmount: onlineReceived(payment),

              dueAmount: newDue,

              excessAmount: Math.max(0, currency(newReceived - order.total)),

              cashCollected,

              deliveryCollections: [
                ...existing,
                {
                  collectionId,
                  amount: collectedAmount,
                  method: "cash_on_delivery",
                  note,
                  collectedAt: new Date(),
                  collectedBy: req.user.uid,
                },
              ],
            },
          },

          event: "delivery_balance_collected",

          note:
            `Cash BDT ${collectedAmount}; ` +
            `remaining BDT ${newDue}. ${note}`,

          by: req.user.uid,
        };
      });

      res.set("Cache-Control", "no-store");

      return res.json({
        success: true,
        message: "Delivery collection recorded",
        order: viewAdminOrder(updated),
      });
    }),
  );

  // Part 7 — Excess Refund, Cancelled Order Refund ও Tracking

  app.patch(
    "/admin/orders/:identifier/excess-resolution",
    verifyFirebaseToken,
    verifyAdmin,
    handle(async (req, res) => {
      if (req.body?.completed !== true) {
        fail("Set completed: true after actual fulfillment");
      }

      const note = str(req.body?.note, 500);
      if (!note) fail("Completion note required");

      const reference = str(req.body?.reference, 150);

      const updated = await updateOrder(req.params.identifier, (order) => {
        if (["cancelled", "rejected"].includes(order.status)) {
          fail("Cannot settle a cancelled or rejected order", 409);
        }

        if (order.phoneConfirmed !== true) {
          fail("Phone confirmation required", 409);
        }

        const payment = order.payment || {};
        const resolution = payment.excessResolution;

        if (
          !resolution ||
          !["refund", "extra_product"].includes(resolution.type)
        ) {
          fail("No agreed excess resolution", 409);
        }

        if (resolution.status === "completed") {
          return { noop: true };
        }

        const excess = Math.max(
          0,
          currency((payment.verifiedAmount || 0) - order.total),
        );

        if (excess <= 0 || currency(resolution.amount) !== excess) {
          fail("Excess amount has changed; review again", 409);
        }

        let extraProducts = [];

        if (resolution.type === "refund") {
          if (!reference) {
            fail("Refund transaction/receipt reference is required");
          }
        } else {
          if (
            !Array.isArray(req.body?.extraProducts) ||
            !req.body.extraProducts.length ||
            req.body.extraProducts.length > 20
          ) {
            fail("List the delivered extra products (maximum 20)");
          }

          extraProducts = req.body.extraProducts.map((item) => {
            const name = str(item?.name, 200);
            const sku = str(item?.sku, 100);
            const quantity = Number(item?.quantity);

            const unitPrice = parseAmount(
              item?.unitPrice,
              "extra product unit price",
            );

            if (
              !name ||
              !Number.isInteger(quantity) ||
              quantity < 1 ||
              quantity > 100
            ) {
              fail("Invalid extra product name or quantity");
            }

            return {
              name,
              sku,
              quantity,
              unitPrice,
            };
          });

          const equivalent = currency(
            extraProducts.reduce(
              (sum, item) => sum + item.quantity * item.unitPrice,
              0,
            ),
          );

          if (equivalent !== excess) {
            fail(
              `Extra product value BDT ${equivalent} does not equal excess BDT ${excess}`,
            );
          }
        }

        return {
          set: {
            payment: {
              ...payment,

              refundedAmount:
                resolution.type === "refund"
                  ? currency((payment.refundedAmount || 0) + excess)
                  : currency(payment.refundedAmount || 0),

              refunds:
                resolution.type === "refund"
                  ? [
                      ...(payment.refunds || []),
                      {
                        refundId: randomUUID(),
                        type: "overpayment",
                        amount: excess,
                        reference,
                        method: payment.method,
                        note,
                        refundedAt: new Date(),
                        by: req.user.uid,
                      },
                    ]
                  : payment.refunds || [],

              excessResolution: {
                ...resolution,
                status: "completed",
                completedAt: new Date(),
                completedBy: req.user.uid,
                completionNote: note,
                reference: reference || null,
                extraProducts,
              },
            },
          },

          event:
            resolution.type === "refund"
              ? "excess_refund_completed"
              : "extra_product_completed",

          note: `Excess BDT ${excess}; ` + `${resolution.type}; ${note}`,

          by: req.user.uid,
        };
      });

      res.set("Cache-Control", "no-store");

      return res.json({
        success: true,
        message: "Excess resolution recorded",
        order: viewAdminOrder(updated),
      });
    }),
  );

  // Cancelled/rejected order funds must be returned.
  // Any previously completed refund is deducted.

  app.patch(
    "/admin/orders/:identifier/refund",
    verifyFirebaseToken,
    verifyAdmin,
    handle(async (req, res) => {
      if (req.body?.completed !== true) {
        fail("completed: true required after funds are actually returned");
      }

      const refundId = checkoutIdOf(req.body?.refundId);

      const amount = parseAmount(req.body?.amount, "refund amount");

      const reference = str(req.body?.reference, 150);

      const note = str(req.body?.note, 500);

      const method = str(req.body?.method, 20).toLowerCase();

      if (!reference || !note) {
        fail("Refund reference and note required");
      }

      if (
        !["bkash", "nagad", "rocket", "bank", "cash", "other"].includes(method)
      ) {
        fail("Invalid refund method");
      }

      const updated = await updateOrder(req.params.identifier, (order) => {
        if (!["cancelled", "rejected"].includes(order.status)) {
          fail("This endpoint is only for cancelled/rejected orders", 409);
        }

        const p = order.payment || {};

        const prior = Array.isArray(p.refunds) ? p.refunds : [];

        const existing = prior.find((entry) => entry.refundId === refundId);

        if (existing) {
          if (
            currency(existing.amount) !== amount ||
            existing.reference !== reference
          ) {
            fail("Refund ID reused with different details", 409);
          }

          return { noop: true };
        }

        const pending = refundableBalance(p);

        if (pending <= 0) {
          fail("No remaining money to refund", 409);
        }

        if (amount > pending) {
          fail(`Refund exceeds outstanding BDT ${pending}`, 409);
        }

        const refundedAmount = currency((p.refundedAmount || 0) + amount);

        const remainingAmount = Math.max(0, currency(pending - amount));

        const previousCase =
          p.cancellationRefund ||
          newCancellationRefund(p, "Rejected order", new Date());

        const now = new Date();

        return {
          set: {
            payment: {
              ...p,
              refundedAmount,

              refunds: [
                ...prior,
                {
                  refundId,
                  type: "cancellation",
                  amount,
                  method,
                  reference,
                  note,
                  refundedAt: now,
                  by: req.user.uid,
                },
              ],

              cancellationRefund: {
                ...previousCase,

                status:
                  remainingAmount === 0 ? "completed" : "partially_refunded",

                remainingAmount,

                completedAt: remainingAmount === 0 ? now : null,
              },
            },
          },

          event:
            remainingAmount === 0
              ? "cancellation_refund_completed"
              : "cancellation_refund_partial",

          note:
            `Refund BDT ${amount} via ${method}; ` +
            `remaining ${remainingAmount}; ${note}`,

          by: req.user.uid,
        };
      });

      res.set("Cache-Control", "no-store");

      res.json({
        success: true,
        message: "Refund recorded",
        order: viewAdminOrder(updated),
      });
    }),
  );

  app.patch(
    "/admin/orders/:identifier/status",
    verifyFirebaseToken,
    verifyAdmin,
    handle(async (req, res) => {
      const status = str(req.body?.status, 30);

      const note = str(req.body?.note, 500);

      const transitions = {
        pending: ["verified", "cancelled"],
        verified: ["processing", "cancelled"],
        processing: ["shipped", "cancelled"],
        shipped: ["delivered"],
        delivered: [],
        rejected: [],
        cancelled: [],
      };

      const updated = await updateOrder(req.params.identifier, (order) => {
        if (!transitions[order.status]?.includes(status)) {
          fail("Invalid order status transition", 409);
        }

        const payment = order.payment || {};

        const verifiedAmount = currency(payment.verifiedAmount || 0);

        const due = Math.max(0, currency(order.total - verifiedAmount));

        const excess = Math.max(0, currency(verifiedAmount - order.total));

        if (
          ["verified", "processing", "shipped", "delivered"].includes(status)
        ) {
          if (order.phoneConfirmed !== true) {
            fail("Phone confirmation required", 409);
          }

          if (
            payment.method !== "cod" &&
            !["verified", "partially_paid"].includes(payment.status)
          ) {
            fail("Admin payment verification required", 409);
          }

          if (excess > 0 && !payment.excessResolution?.type) {
            fail("Customer overpayment agreement required", 409);
          }
        }

        if (status === "delivered") {
          if (due > 0) {
            fail(
              `Outstanding BDT ${due}; collect balance before delivery`,
              409,
            );
          }

          if (excess > 0 && payment.excessResolution?.status !== "completed") {
            fail("Refund/extra product must be completed before delivery", 409);
          }
        }

        const set = { status };

        if (status === "cancelled") {
          const oldResolution = payment.excessResolution;

          if (
            oldResolution?.type === "extra_product" &&
            oldResolution.status === "completed"
          ) {
            fail(
              "Extra product already fulfilled; resolve its return before cancellation",
              409,
            );
          }

          const cancellationRefund = newCancellationRefund(
            payment,
            note || "Order cancelled",
            new Date(),
          );

          set.payment = {
            ...payment,
            cancellationRefund,

            excessResolution:
              oldResolution && oldResolution.status !== "completed"
                ? {
                    ...oldResolution,
                    status: "superseded_by_cancellation",
                  }
                : oldResolution || null,
          };
        }

        return {
          set,
          event: status,
          note: note || `Order marked ${status}`,
          by: req.user.uid,
        };
      });

      res.set("Cache-Control", "no-store");

      return res.json({
        success: true,
        message: "Order status updated",
        order: viewAdminOrder(updated),
      });
    }),
  );

  app.patch(
    "/admin/orders/:identifier/tracking",
    verifyFirebaseToken,
    verifyAdmin,
    handle(async (req, res) => {
      const name = str(req.body?.name, 150);

      const trackingNumber = str(req.body?.trackingNumber, 150);

      const trackingUrl = str(req.body?.trackingUrl, 2048);

      const parcelWeight = str(req.body?.parcelWeight, 30);

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

      const updated = await updateOrder(req.params.identifier, (order) => {
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

            ...(dateProvided ? { estimatedDelivery } : {}),
          },

          event: "tracking_updated",

          note:
            `Courier: ${name || "Unassigned"}; ` +
            `Tracking: ${trackingNumber || "None"}; ` +
            `Weight: ${parcelWeight || "None"}`,

          by: req.user.uid,
        };
      });

      res.set("Cache-Control", "no-store");

      return res.json({
        success: true,
        message: "Courier details updated",
        order: viewAdminOrder(updated),
      });
    }),
  );

  // Part 8 — Admin Dashboard

  app.get(
    "/admin/dashboard",
    verifyFirebaseToken,
    verifyAdmin,
    handle(async (req, res) => {
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

      const overviewPipeline = [
        {
          $group: {
            _id: null,
            totalOrders: { $sum: 1 },

            pendingOrders: {
              $sum: {
                $cond: [
                  {
                    $eq: ["$status", "pending"],
                  },
                  1,
                  0,
                ],
              },
            },

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

            totalSales: {
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

            onlineCollection: {
              $sum: mongoOnlineReceived,
            },

            cashCollection: {
              $sum: {
                $ifNull: ["$payment.cashCollected", 0],
              },
            },

            grossCollection: {
              $sum: {
                $ifNull: ["$payment.verifiedAmount", 0],
              },
            },

            refundedCollection: {
              $sum: {
                $ifNull: ["$payment.refundedAmount", 0],
              },
            },

            refundsPending: {
              $sum: {
                $cond: [
                  {
                    $in: ["$status", ["cancelled", "rejected"]],
                  },
                  {
                    $max: [
                      0,
                      {
                        $subtract: [
                          {
                            $ifNull: ["$payment.verifiedAmount", 0],
                          },
                          {
                            $ifNull: ["$payment.refundedAmount", 0],
                          },
                        ],
                      },
                    ],
                  },
                  0,
                ],
              },
            },

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
            count: { $sum: 1 },
          },
        },
      ];

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
          $sort: { _id: 1 },
        },
      ];

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
              $sum: mongoOnlineReceived,
            },
          },
        },
      ];

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

        orders.countDocuments({
          createdAt: {
            $gte: current30Start,
            $lte: now,
          },
        }),

        orders.countDocuments({
          createdAt: {
            $gte: previous30Start,
            $lt: current30Start,
          },
        }),
      ]);

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

      const dailySalesMap = new Map(
        salesRows.map((row) => [row._id, roundMoney(row.sales)]),
      );

      const saleOn = (date) => dailySalesMap.get(date) || 0;

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

          customer: {
            name: order.customer?.name || "Unknown Customer",
            phone: order.customer?.phone || "",
          },

          shipping: {
            phone: order.shipping?.phone || "",
          },

          customerPhotoUrl: order.guest
            ? ""
            : customerPhotoMap.get(order.uid) || "",

          itemCount,
          items: items.slice(0, 2),

          payment: {
            method: order.payment?.method || null,
            status: order.payment?.status || null,
            verifiedAmount,
            dueAmount,
          },

          courier: {
            name: order.courier?.name || null,
            trackingNumber: order.courier?.trackingNumber || null,
          },
        };
      });

      res.set("Cache-Control", "private, no-store");

      return res.status(200).json({
        success: true,
        generatedAt: now.toISOString(),

        kpis: {
          totalOrders,

          pendingOrders: Number(overview.pendingOrders) || 0,

          pendingPayments: Number(overview.pendingPayments) || 0,

          totalSales,
          deliveredOrders,
          outstandingBalance,

          onlineCollection: roundMoney(overview.onlineCollection),

          cashCollection: roundMoney(overview.cashCollection),

          grossCollection: roundMoney(overview.grossCollection),

          refundedCollection: roundMoney(overview.refundedCollection),

          netCollection: roundMoney(
            (overview.grossCollection || 0) -
              (overview.refundedCollection || 0),
          ),

          refundsPending: roundMoney(overview.refundsPending),

          deliveryRate,
          orderGrowthPercent,
          salesGrowthPercent,
        },

        attention: {
          paymentPending: Number(overview.pendingPayments) || 0,

          codUnconfirmed: Number(overview.codUnconfirmed) || 0,

          customProcessing: Number(overview.customProcessing) || 0,

          firstCodOrderId: firstCodOrder?._id?.toString() || null,

          firstCustomOrderId: firstCustomOrder?._id?.toString() || null,
        },

        salesData: {
          daily,
          weekly,
          monthly,
        },

        statusData,
        statusTotal,
        paymentData,
        recentOrders,
      });
    }),
  );

  // Part 9 — Admin Customer Management

  app.get(
    "/admin/customers",
    verifyFirebaseToken,
    verifyAdmin,
    handle(async (req, res) => {
      const pageRaw = str(req.query.page ?? "1", 6);

      if (!/^[1-9]\d{0,5}$/.test(pageRaw)) {
        fail("Invalid page number");
      }

      const page = Math.min(Number(pageRaw), 10000);

      const perPage = 10;
      const skip = (page - 1) * perPage;
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

      if (search) {
        const escaped = search.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

        const regex = new RegExp(escaped, "i");

        match.$or = [
          { displayName: regex },
          { email: regex },
          { phone: regex },
          {
            "checkoutProfile.name": regex,
          },
          {
            "checkoutProfile.phone": regex,
          },
        ];
      }

      const offset = 6 * 60 * 60 * 1000;

      const dhaka = new Date(Date.now() + offset);

      const monthStart = new Date(
        Date.UTC(dhaka.getUTCFullYear(), dhaka.getUTCMonth(), 1) - offset,
      );

      const customerPipeline = [
        {
          $match: match,
        },
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

                  orderCount: {
                    $sum: 1,
                  },

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

      const [listRows, statsRows, guestOrders] = await Promise.all([
        users.aggregate(customerPipeline).toArray(),

        users.aggregate(statsPipeline).toArray(),

        orders.countDocuments({
          guest: true,
        }),
      ]);

      const list = listRows[0] || {};
      const total = list.metadata?.[0]?.total || 0;

      const summary = statsRows[0] || {};

      const customers = (list.customers || []).map((customer) => ({
        ...customer,

        totalSpent: Math.round((Number(customer.totalSpent) || 0) * 100) / 100,
      }));

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

  // Part 10 — Admin Delivery Management

  app.get(
    "/admin/deliveries",
    verifyFirebaseToken,
    verifyAdmin,
    handle(async (req, res) => {
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

      if (["verified", "processing", "shipped", "delivered"].includes(view)) {
        clauses.push({ status: view });
      } else if (view === "overdue") {
        clauses.push({
          status: "shipped",
          estimatedDelivery: {
            $type: "date",
            $lt: now,
          },
        });
      } else if (view === "upcoming") {
        clauses.push({
          status: "shipped",
          estimatedDelivery: {
            $gte: now,
            $lte: nextWeek,
          },
        });
      } else if (view === "unassigned") {
        clauses.push(
          {
            status: {
              $in: ["verified", "processing"],
            },
          },
          missingCourier,
        );
      }

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

      const [docs, total, byStatus, overdueCount] = await Promise.all([
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

        orders.countDocuments(query),

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

        orders.countDocuments({
          status: "shipped",
          estimatedDelivery: {
            $type: "date",
            $lt: now,
          },
        }),
      ]);

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

      const counts = Object.fromEntries(
        byStatus.map((item) => [item._id, item.total]),
      );

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
