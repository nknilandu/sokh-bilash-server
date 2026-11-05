"use strict";

const { ObjectId } = require("mongodb");

const MAX_ITEMS = 100;
const VALID_ID = /^[a-f0-9]{24}$/i;

module.exports = async function registerWishlistRoutes({
  app,
  DB,
  users,
  products,
  verifyFirebaseToken,
}) {
  const wishlists = DB.collection("wishlists");

  await wishlists.createIndex({ uid: 1 }, { unique: true });

  // ========================================
  // ONLY ACTIVE CUSTOMERS
  // ========================================

  const onlyCustomer = async (req, res, next) => {
    try {
      const account = await users.findOne(
        {
          uid: req.user.uid,
          role: "customer",
          status: "active",
        },
        { projection: { _id: 1 } },
      );

      if (!account) {
        return res.status(403).json({
          success: false,
          message: "Only active customers can use account wishlists",
        });
      }

      next();
    } catch (error) {
      next(error);
    }
  };

  // ========================================
  // ERROR HANDLER
  // ========================================

  const wrap = (fn) => async (req, res) => {
    try {
      await fn(req, res);
    } catch (error) {
      console.error("Wishlist API:", error);

      return res.status(error.status || 500).json({
        success: false,
        message: error.status ? error.message : "Wishlist request failed",
      });
    }
  };

  // ========================================
  // VALIDATE PRODUCT ID
  // ========================================

  const cleanId = (value) => {
    if (typeof value !== "string" || !VALID_ID.test(value.trim())) {
      const error = new Error("Invalid product ID");
      error.status = 400;
      throw error;
    }

    return value.trim().toLowerCase();
  };

  // ========================================
  // PUBLIC PRODUCT FIELDS
  // Same fields needed by ProductCard
  // ========================================

  const publicFields = {
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
    variants: 1,
    options: 1,
  };

  // ========================================
  // ATOMIC UNIQUE MERGE
  // Keeps existing IDs and appends new IDs.
  // Maximum 100 saved products.
  // ========================================

  const appendUnique = (newIds) => ({
    $slice: [
      {
        $reduce: {
          input: {
            $concatArrays: [
              {
                $ifNull: ["$productIds", []],
              },
              {
                $literal: newIds,
              },
            ],
          },

          initialValue: [],

          in: {
            $cond: [
              {
                $in: ["$$this", "$$value"],
              },
              "$$value",
              {
                $concatArrays: ["$$value", ["$$this"]],
              },
            ],
          },
        },
      },
      -MAX_ITEMS,
    ],
  });

  // ========================================
  // ADD IDs TO CUSTOMER WISHLIST
  // ========================================

  const addIds = async (uid, ids) => {
    if (!ids.length) return;

    await wishlists.updateOne(
      { uid },
      [
        {
          $set: {
            uid: { $literal: uid },

            productIds: appendUnique(ids),

            createdAt: {
              $ifNull: ["$createdAt", "$$NOW"],
            },

            updatedAt: "$$NOW",
          },
        },
      ],
      { upsert: true },
    );
  };

  // ========================================
  // GET CUSTOMER WISHLIST WITH PRODUCTS
  // ========================================

  const getWishlist = async (uid) => {
    const document = await wishlists.findOne({
      uid,
    });

    const productIds = Array.isArray(document?.productIds)
      ? document.productIds.slice(-MAX_ITEMS)
      : [];

    if (!productIds.length) {
      return {
        productIds: [],
        products: [],
        missingIds: [],
      };
    }

    const found = await products
      .find(
        {
          _id: {
            $in: productIds.map((id) => new ObjectId(id)),
          },

          status: "published",
        },
        {
          projection: publicFields,
        },
      )
      .toArray();

    const lookup = new Map(
      found.map((product) => [product._id.toString(), product]),
    );

    return {
      productIds,

      products: productIds
        .map((id) => lookup.get(id))
        .filter(Boolean)
        .map((product) => ({
          ...product,
          _id: product._id.toString(),
        })),

      missingIds: productIds.filter((id) => !lookup.has(id)),
    };
  };

  // ========================================
  // GET /wishlist
  // ========================================

  app.get(
    "/wishlist",
    verifyFirebaseToken,
    onlyCustomer,
    wrap(async (req, res) => {
      res.set("Cache-Control", "no-store");

      res.json({
        success: true,
        ...(await getWishlist(req.user.uid)),
      });
    }),
  );

  // ========================================
  // POST /wishlist/merge
  // MERGE GUEST IDS INTO CUSTOMER ACCOUNT
  // ========================================

  app.post(
    "/wishlist/merge",
    verifyFirebaseToken,
    onlyCustomer,
    wrap(async (req, res) => {
      if (
        !Array.isArray(req.body?.productIds) ||
        req.body.productIds.length > MAX_ITEMS
      ) {
        return res.status(400).json({
          success: false,
          message: "Invalid guest wishlist",
        });
      }

      const ids = [...new Set(req.body.productIds.map(cleanId))];

      // Merge only published products.
      const validProducts = await products
        .find(
          {
            _id: {
              $in: ids.map((id) => new ObjectId(id)),
            },

            status: "published",
          },
          {
            projection: { _id: 1 },
          },
        )
        .toArray();

      await addIds(
        req.user.uid,
        validProducts.map((item) => item._id.toString()),
      );

      res.set("Cache-Control", "no-store");

      res.json({
        success: true,
        ...(await getWishlist(req.user.uid)),
      });
    }),
  );

  // ========================================
  // PUT /wishlist/items/:productId
  // ========================================

  app.put(
    "/wishlist/items/:productId",
    verifyFirebaseToken,
    onlyCustomer,
    wrap(async (req, res) => {
      const id = cleanId(req.params.productId);

      const exists = await products.findOne(
        {
          _id: new ObjectId(id),
          status: "published",
        },
        {
          projection: { _id: 1 },
        },
      );

      if (!exists) {
        return res.status(404).json({
          success: false,
          message: "Product not found",
        });
      }

      await addIds(req.user.uid, [id]);

      res.json({
        success: true,
        ...(await getWishlist(req.user.uid)),
      });
    }),
  );

  // ========================================
  // DELETE /wishlist/items/:productId
  // ========================================

  app.delete(
    "/wishlist/items/:productId",
    verifyFirebaseToken,
    onlyCustomer,
    wrap(async (req, res) => {
      const id = cleanId(req.params.productId);

      await wishlists.updateOne(
        { uid: req.user.uid },
        {
          $pull: { productIds: id },

          $set: {
            updatedAt: new Date(),
          },
        },
      );

      res.json({
        success: true,
        ...(await getWishlist(req.user.uid)),
      });
    }),
  );

  // ========================================
  // DELETE /wishlist
  // CLEAR ALL
  // ========================================

  app.delete(
    "/wishlist",
    verifyFirebaseToken,
    onlyCustomer,
    wrap(async (req, res) => {
      await wishlists.updateOne(
        { uid: req.user.uid },
        {
          $set: {
            productIds: [],
            updatedAt: new Date(),
          },
        },
      );

      res.json({
        success: true,
        productIds: [],
        products: [],
        missingIds: [],
      });
    }),
  );
};
