const { ObjectId } = require("mongodb");
const { rateLimit } = require("express-rate-limit");

// ========================================
// BANGLADESH REGIONS
// ========================================

const DISTRICTS = require("../utils/bangladeshRegions");

// ========================================
// HELPERS
// ========================================

const fail = (message, status = 400) => {
  const error = new Error(message);
  error.status = status;
  throw error;
};

const handle = (callback) => async (req, res) => {
  try {
    await callback(req, res);
  } catch (error) {
    console.error("Profile API Error:", error);

    const status = error.status || 500;

    return res.status(status).json({
      success: false,
      message: error.status ? error.message : "Internal server error",
    });
  }
};

const cleanText = (value, name, max) => {
  if (typeof value !== "string") {
    fail(`${name} must be a string`);
  }

  const result = value.trim();

  if (result.length > max) {
    fail(`${name} exceeds ${max} characters`);
  }

  return result;
};

const validImageUrl = (value) => {
  if (!value) return true;

  try {
    const url = new URL(value);

    return (
      url.protocol === "https:" &&
      Boolean(url.hostname) &&
      !url.username &&
      !url.password
    );
  } catch {
    return false;
  }
};

const profileView = (account) => {
  const saved = account.checkoutProfile || {};

  const validRegion =
    DISTRICTS[saved.division]?.includes(saved.district) === true;

  return {
    _id: account._id.toString(),
    uid: account.uid,

    displayName: account.displayName || saved.name || "",

    email: account.email || "",

    phone: account.phone || saved.phone || "",

    photoUrl: account.photoUrl || "",

    division: validRegion ? saved.division : "",
    district: validRegion ? saved.district : "",
    address: validRegion ? saved.address || "" : "",

    role: account.role || "customer",
    status: account.status || "active",

    createdAt: account.createdAt || null,
    updatedAt: account.updatedAt || null,
  };
};

const validateProfile = (body) => {
  if (!body || typeof body !== "object" || Array.isArray(body)) {
    fail("Invalid profile information");
  }

  const allowed = new Set([
    "displayName",
    "phone",
    "photoUrl",
    "division",
    "district",
    "address",
  ]);

  // Never allow email, UID, role or status updates.
  for (const key of Object.keys(body)) {
    if (!allowed.has(key)) {
      fail(`Field '${key}' cannot be updated`);
    }
  }

  const displayName = cleanText(body.displayName, "Name", 100);

  const phone = cleanText(body.phone, "Phone", 20);

  const photoUrl = cleanText(body.photoUrl, "Photo URL", 2048);

  const division = cleanText(body.division, "Division", 80);

  const district = cleanText(body.district, "District", 80);

  const address = cleanText(body.address, "Address", 500);

  if (displayName.length < 2) {
    fail("Name must contain at least 2 characters");
  }

  if (!/^01[3-9]\d{8}$/.test(phone)) {
    fail("Enter a valid Bangladeshi phone number");
  }

  if (!validImageUrl(photoUrl)) {
    fail("Profile image must use a valid HTTPS URL");
  }

  const hasAddressData = Boolean(division || district || address);

  // Empty address is permitted until configured.
  // Once entered, require a complete address.
  if (hasAddressData) {
    if (!DISTRICTS[division]?.includes(district)) {
      fail("Select a valid division and district");
    }

    if (address.length < 5) {
      fail("Enter a complete delivery address");
    }
  }

  return {
    displayName,
    phone,
    photoUrl,
    division,
    district,
    address,
  };
};

// ========================================
// PROFILE ROUTES
// ========================================

module.exports = function registerProfileRoutes({
  app,
  users,
  verifyFirebaseToken,
  verifyAdmin,
}) {
  const updateLimit = rateLimit({
    windowMs: 15 * 60 * 1000,
    limit: 30,
    standardHeaders: "draft-7",
    legacyHeaders: false,
    message: {
      success: false,
      message: "Too many profile update attempts",
    },
  });

  // ======================================
  // GET MY PROFILE
  // GET /users/me
  // ======================================

  app.get(
    "/users/me",
    verifyFirebaseToken,
    handle(async (req, res) => {
      const account = await users.findOne({
        uid: req.user.uid,
      });

      if (!account) {
        fail("Profile not found", 404);
      }

      if (account.status !== "active") {
        fail("Account is not active", 403);
      }

      res.set("Cache-Control", "no-store");

      return res.json({
        success: true,
        profile: profileView(account),
      });
    }),
  );

  // ======================================
  // UPDATE MY PROFILE
  // PATCH /users/me
  // ======================================

  app.patch(
    "/users/me",
    updateLimit,
    verifyFirebaseToken,
    handle(async (req, res) => {
      const profile = validateProfile(req.body);

      const now = new Date();

      // UID comes exclusively from the
      // verified Firebase token.
      const result = await users.updateOne(
        {
          uid: req.user.uid,
          status: "active",
        },
        {
          $set: {
            displayName: profile.displayName,
            phone: profile.phone,
            photoUrl: profile.photoUrl || null,

            // Reuse existing checkout storage.
            "checkoutProfile.name": profile.displayName,
            "checkoutProfile.phone": profile.phone,
            "checkoutProfile.division": profile.division,
            "checkoutProfile.district": profile.district,
            "checkoutProfile.address": profile.address,
            "checkoutProfile.updatedAt": now,

            updatedAt: now,
          },
        },
      );

      if (!result.matchedCount) {
        fail("Active account not found", 403);
      }

      const updated = await users.findOne({
        uid: req.user.uid,
      });

      res.set("Cache-Control", "no-store");

      return res.json({
        success: true,
        message: "Profile updated successfully",
        profile: profileView(updated),
      });
    }),
  );

  // ======================================
  // ADMIN READ USER PROFILE
  // GET /admin/users/:id/profile
  //
  // :id = MongoDB _id OR Firebase UID
  // ======================================

  app.get(
    "/admin/users/:id/profile",
    verifyFirebaseToken,
    verifyAdmin,
    handle(async (req, res) => {
      const identifier = String(req.params.id || "").trim();

      if (
        !identifier ||
        identifier.length > 128 ||
        !/^[a-zA-Z0-9_-]+$/.test(identifier)
      ) {
        fail("Invalid user identifier", 400);
      }

      const filter = /^[a-f0-9]{24}$/i.test(identifier)
        ? {
            $or: [{ _id: new ObjectId(identifier) }, { uid: identifier }],
          }
        : { uid: identifier };

      const account = await users.findOne(filter);

      if (!account) {
        fail("User profile not found", 404);
      }

      res.set("Cache-Control", "no-store");

      return res.json({
        success: true,
        readOnly: true,
        profile: profileView(account),
      });
    }),
  );
};
