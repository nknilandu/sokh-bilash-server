
"use strict";

// =============================================
// SEARCH SYNONYMS
// Bangla + English + Banglish
// =============================================

const SEARCH_GROUPS = [
  ["ফটো", "ছবি", "photo", "foto", "picture", "pic"],
  ["ফ্রেম", "frame", "frem", "phrem"],
  ["গিফট", "উপহার", "gift", "gifts", "upohar", "upahar"],
  ["ফুল", "ফুলের", "flower", "flowers", "ful", "phul", "fuler"],
  ["বুকেট", "bouquet", "buke", "buket"],
  ["গোলাপ", "গোলাপের", "rose", "golap", "golaper"],
  ["চকলেট", "chocolate", "chocolates", "choklet"],
  ["বক্স", "box", "boks"],
  ["জন্মদিন", "birthday", "jonmodin", "jonmo"],
  ["বিবাহবার্ষিকী", "anniversary", "bibahobarshiki", "barsiki"],
  ["বিয়ে", "বিবাহ", "wedding", "biye", "biya"],
  ["নিকাহ", "নিকাহনামা", "nikah", "nikahnama"],
  ["ভালোবাসা", "প্রেম", "love", "valobasha", "bhalobasha", "prem"],
  ["রোমান্টিক", "romantic", "romance"],
  ["ইসলামিক", "ইসলামী", "islamic", "islami"],
  ["সারপ্রাইজ", "surprise", "surprize", "sarprise"],
  ["কাস্টম", "কাস্টমাইজড", "custom", "customized", "customisable", "customizable"],
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

// =============================================
// NORMALIZATION
// =============================================

const normalize = (value) =>
  String(value ?? "")
    .normalize("NFKC")
    .toLowerCase()
    .trim();

const tokenize = (value) =>
  (
    normalize(value).match(
      /[\p{L}\p{M}\p{N}]+/gu
    ) || []
  ).map((word) => word.slice(0, 64));

const escapeRegex = (value) =>
  value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

// =============================================
// BANGLA PHONETIC MAPPING
// =============================================

const consonants = {
  ক: "k", খ: "kh", গ: "g", ঘ: "gh", ঙ: "ng",
  চ: "ch", ছ: "chh", জ: "j", ঝ: "jh", ঞ: "n",
  ট: "t", ঠ: "th", ড: "d", ঢ: "dh", ণ: "n",
  ত: "t", থ: "th", দ: "d", ধ: "dh", ন: "n",
  প: "p", ফ: "ph", ব: "b", ভ: "bh", ম: "m",
  য: "j", র: "r", ল: "l", শ: "sh", ষ: "sh",
  স: "s", হ: "h", ড়: "r", ঢ়: "rh", য়: "y",
};

const vowelSigns = {
  "া": "a", "ি": "i", "ী": "i",
  "ু": "u", "ূ": "u", "ৃ": "ri",
  "ে": "e", "ৈ": "oi", "ো": "o", "ৌ": "ou",
};

const vowels = {
  অ: "o", আ: "a",
  ই: "i", ঈ: "i",
  উ: "u", ঊ: "u",
  ঋ: "ri",
  এ: "e", ঐ: "oi",
  ও: "o", ঔ: "ou",
};

// =============================================
// BANGLA TO APPROXIMATE BANGLISH
// =============================================

function makeSearchLatin(value) {
  const chars = Array.from(
    String(value || "").normalize("NFC")
  );

  let output = "";

  for (let i = 0; i < chars.length; i++) {
    const char = chars[i];
    const next = chars[i + 1];

    if (vowels[char]) {
      output += vowels[char];
      continue;
    }

    if (consonants[char]) {
      output += consonants[char];

      if (next === "্") {
        i++;
        continue;
      }

      if (vowelSigns[next]) {
        output += vowelSigns[next];
        i++;
        continue;
      }

      if (next && consonants[next]) {
        output += "o";
      }

      continue;
    }

    if (char === "ং") {
      output += "ng";
      continue;
    }

    if (["ঁ", "ঃ", "়"].includes(char)) {
      continue;
    }

    if (vowelSigns[char]) {
      output += vowelSigns[char];
      continue;
    }

    output += char;
  }

  return normalize(output).slice(0, 4000);
}

// =============================================
// BUILD SEARCHABLE TERMS
// Run during Product POST / PATCH
// =============================================

function buildProductSearchTerms(
  product,
  {
    categoryName = "",
    occasionNames = [],
  } = {}
) {
  const variantTerms = Array.isArray(
    product.variants
  )
    ? product.variants.flatMap((variant) => [
        variant.sku,
        variant.title,
        ...Object.values(
          variant.options || {}
        ),
      ])
    : [];

  const labels = [
    product.name,

    String(product.description || "")
      .slice(0, 750),

    product.sku,
    product.slug,

    product.categoryId,

    ...(product.occasionIds || []),

    categoryName,
    ...occasionNames,

    ...variantTerms,

    ...(Array.isArray(product.searchKeywords)
      ? product.searchKeywords
      : []),

    product.customizable
      ? "কাস্টমাইজড customizable custom"
      : "",

    product.surpriseBox
      ? "সারপ্রাইজ বক্স surprise box"
      : "",
  ];

  const initialWords = tokenize(
    labels.filter(Boolean).join(" ")
  ).slice(0, 160);

  const terms = new Set(initialWords);

  for (const word of initialWords) {
    // Convert Bangla tokens to Latin.
    if (/[\u0980-\u09FF]/u.test(word)) {
      const latinWords = tokenize(
        makeSearchLatin(word)
      );

      for (const latin of latinWords) {
        terms.add(latin);
      }
    }

    // Recognize joined words:
    // ফটোফ্রেম -> ফটো + ফ্রেম
    // giftbox -> gift + box

    if (word.length >= 5) {
      for (const group of SEARCH_GROUPS) {
        for (const alias of group) {
          const term = normalize(alias);

          if (
            term.length >= 3 &&
            word.includes(term)
          ) {
            terms.add(term);
          }
        }
      }
    }
  }

  // Limit stored tokens per document.
  return [...terms].slice(0, 350);
}

// =============================================
// INDEXED SEARCH CONDITIONS
// Used by GET /products
// =============================================

function buildPublicSearchConditions(search) {
  const words = tokenize(
    String(search || "").slice(0, 120)
  ).slice(0, 8);

  return words.map((word) => {
    const group =
      SEARCH_GROUPS.find((items) =>
        items.some(
          (item) => normalize(item) === word
        )
      ) || [];

    const aliases = [
      ...new Set([
        word,
        ...group.map(normalize),
      ]),
    ];

    return {
      $or: [
        // Exact words and synonyms
        {
          searchTerms: {
            $in: aliases,
          },
        },

        // Prefix matching for typing:
        // "phot" can match "photo".
        {
          searchTerms: {
            $regex: `^${escapeRegex(word)}`,
          },
        },
      ],
    };
  });
}

// =============================================
// LEGACY REGEX SEARCH
// Keeps existing admin search compatible.
// =============================================

function makeSearchRegex(word) {
  const value = normalize(word);

  const group = SEARCH_GROUPS.find(
    (items) =>
      items.some(
        (item) => normalize(item) === value
      )
  );

  return new RegExp(
    (group || [value])
      .map(escapeRegex)
      .join("|"),
    "i"
  );
}

// =============================================
// EXPORTS
// =============================================

module.exports = {
  makeSearchLatin,
  buildProductSearchTerms,
  buildPublicSearchConditions,
  makeSearchRegex,
};
