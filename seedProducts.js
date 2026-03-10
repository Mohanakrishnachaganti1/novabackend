import mongoose from "mongoose";
import dotenv from "dotenv";
dotenv.config();

const ProductSchema = new mongoose.Schema({
  name: { type: String, required: true },
  price: Number,
  category: { type: String, required: true },
  subcategory: String,
  colors: [String],
  slug: { type: String, unique: true },
  sizes: [String],
  minQty: Number,
  images: [String],
  description: String,
  variants: [{
    color: String,
    size: String,
    image: String,
    price: Number,
    sku: String,
    stock: { type: Number, default: 0 },
    active: { type: Boolean, default: true }
  }]
}, { timestamps: true });

const Product = mongoose.model("Product", ProductSchema);

const products =
[
   {
    "name": "White Dress",
    "price": 99.99,
    "category": "Fashion",
    "subcategory": "women",
    "slug": "white-dress",
    "images": [
      "https://res.cloudinary.com/djgz1kays/image/upload/v1765383124/whiteDress-S-NovaInternationalDesigns_mh8qvs.jpg"
    ],
    "description": "Classic women's dress available in multiple sizes and colors.",
    "minQty": 1,
    "variants": [
      {
        "color": "White",
        "size": "S",
        "image": "https://res.cloudinary.com/djgz1kays/image/upload/v1765383124/whiteDress-S-NovaInternationalDesigns_mh8qvs.jpg"
      },
      {
        "color": "White",
        "size": "M",
        "image": "https://res.cloudinary.com/djgz1kays/image/upload/v1765383124/whiteDress-M-NovaInternationalDesigns_zxoh15.jpg"
      },
      {
        "color": "White",
        "size": "L",
        "image": "https://res.cloudinary.com/djgz1kays/image/upload/v1765383123/whiteDress-L-NovaInternationalDesigns_vhiciz.jpg"
      }
    ]
  },
  {
    "name": "Brown Dress",
    "price": 99.99,
    "category": "Fashion",
    "subcategory": "women",
    "slug": "brown-dress",
    "images": [
      "https://res.cloudinary.com/djgz1kays/image/upload/v1765383123/BrownDress-S-NovaInternationalDesigns_mdwwwb.jpg"
    ],
    "description": "Classic women's dress available in multiple sizes and colors.",
    "minQty": 1,
    "variants": [
      {
        "color": "Brown",
        "size": "S",
        "image": "https://res.cloudinary.com/djgz1kays/image/upload/v1765383123/BrownDress-S-NovaInternationalDesigns_mdwwwb.jpg"
      },
      {
        "color": "Brown",
        "size": "M",
        "image": "https://res.cloudinary.com/djgz1kays/image/upload/v1765383124/BrownDress-M-NovaInternationalDesigns_cfvsgc.jpg"
      },
      {
        "color": "Brown",
        "size": "L",
        "image": "https://res.cloudinary.com/djgz1kays/image/upload/v1765383122/BrownDress-L-NovaInternationalDesigns_rxv0bs.jpg"
      }
    ]
  },
  {
    "name": "Blue Dress",
    "price": 99.99,
    "category": "Fashion",
    "subcategory": "women",
    "slug": "blue-dress",
    "images": [
      "https://res.cloudinary.com/djgz1kays/image/upload/v1765383122/BlueDress-S-NovaInternationalDesigns_o3dgls.jpg"
    ],
    "description": "Classic women's dress available in multiple sizes and colors.",
    "minQty": 1,
    "variants": [
      {
        "color": "Blue",
        "size": "S",
        "image": "https://res.cloudinary.com/djgz1kays/image/upload/v1765383122/BlueDress-S-NovaInternationalDesigns_o3dgls.jpg"
      },
      {
        "color": "Blue",
        "size": "M",
        "image": "https://res.cloudinary.com/djgz1kays/image/upload/v1765383122/BlueDress-M-NovaInternationalDesigns_wde5n8.jpg"
      },
      {
        "color": "Blue",
        "size": "L",
        "image": "https://res.cloudinary.com/djgz1kays/image/upload/v1765383122/BlueDress-L-NovaInternationalDesigns_s9x5q7.jpg"
      }
    ]
  },

 {
    "name": "Clutch - Magenta",
    "price": 199.99,
    "slug": "clutch-magenta",
    "category": "Accessories",
    "subcategory": "clutch",
    "minQty": 1,
    "description": "Elegant evening clutch available in multiple colors.",
    "images": [
      "https://res.cloudinary.com/djgz1kays/image/upload/v1764974490/magenta-clutch-by-Nova-International-designs-corporation_felron.png"
    ],
    "variants": [
      { "color": "Magenta", "image": "https://res.cloudinary.com/djgz1kays/image/upload/v1764974490/magenta-clutch-by-Nova-International-designs-corporation_felron.png" },
      { "color": "Silver", "image": "https://res.cloudinary.com/djgz1kays/image/upload/v1764974491/silver-clutch-by-Nova-International-designs-corporation_fjuitv.png" },
      { "color": "Red", "image": "https://res.cloudinary.com/djgz1kays/image/upload/v1764974490/red-clutch-by-Nova-International-designs-corporation_dsmva3.png" },
      { "color": "Golden", "image": "https://res.cloudinary.com/djgz1kays/image/upload/v1764974490/golden-clutch-by-Nova-International-designs-corporation_lqmo2l.png" },
      { "color": "Glittery Gold", "image": "https://res.cloudinary.com/djgz1kays/image/upload/v1764974490/gittery-gold-clutch-by-Nova-International-designs-corporation_j34sbb.png" },
      { "color": "Black", "image": "https://res.cloudinary.com/djgz1kays/image/upload/v1765384958/black-clutch-by-Nova-International-designs-corporation_b64mbs.png" }
    ]
  },
  {
    "name": "Clutch - Silver",
    "price": 199.99,
    "slug": "clutch-silver",
    "category": "Accessories",
    "subcategory": "clutch",
    "minQty": 1,
    "description": "Elegant evening clutch available in multiple colors.",
    "images": [
      "https://res.cloudinary.com/djgz1kays/image/upload/v1764974491/silver-clutch-by-Nova-International-designs-corporation_fjuitv.png"
    ],
      "variants": [
      { "color": "Magenta", "image": "https://res.cloudinary.com/djgz1kays/image/upload/v1764974490/magenta-clutch-by-Nova-International-designs-corporation_felron.png" },
      { "color": "Silver", "image": "https://res.cloudinary.com/djgz1kays/image/upload/v1764974491/silver-clutch-by-Nova-International-designs-corporation_fjuitv.png" },
      { "color": "Red", "image": "https://res.cloudinary.com/djgz1kays/image/upload/v1764974490/red-clutch-by-Nova-International-designs-corporation_dsmva3.png" },
      { "color": "Golden", "image": "https://res.cloudinary.com/djgz1kays/image/upload/v1764974490/golden-clutch-by-Nova-International-designs-corporation_lqmo2l.png" },
      { "color": "Glittery Gold", "image": "https://res.cloudinary.com/djgz1kays/image/upload/v1764974490/gittery-gold-clutch-by-Nova-International-designs-corporation_j34sbb.png" },
      { "color": "Black", "image": "https://res.cloudinary.com/djgz1kays/image/upload/v1765384958/black-clutch-by-Nova-International-designs-corporation_b64mbs.png" }
    ]
  },
  {
    "name": "Clutch - Red",
    "price": 199.99,
    "slug": "clutch-red",
    "category": "Accessories",
    "subcategory": "clutch",
    "minQty": 1,
    "description": "Elegant evening clutch available in multiple colors.",
    "images": [
      "https://res.cloudinary.com/djgz1kays/image/upload/v1764974490/red-clutch-by-Nova-International-designs-corporation_dsmva3.png"
    ],
   "variants": [
      { "color": "Magenta", "image": "https://res.cloudinary.com/djgz1kays/image/upload/v1764974490/magenta-clutch-by-Nova-International-designs-corporation_felron.png" },
      { "color": "Silver", "image": "https://res.cloudinary.com/djgz1kays/image/upload/v1764974491/silver-clutch-by-Nova-International-designs-corporation_fjuitv.png" },
      { "color": "Red", "image": "https://res.cloudinary.com/djgz1kays/image/upload/v1764974490/red-clutch-by-Nova-International-designs-corporation_dsmva3.png" },
      { "color": "Golden", "image": "https://res.cloudinary.com/djgz1kays/image/upload/v1764974490/golden-clutch-by-Nova-International-designs-corporation_lqmo2l.png" },
      { "color": "Glittery Gold", "image": "https://res.cloudinary.com/djgz1kays/image/upload/v1764974490/gittery-gold-clutch-by-Nova-International-designs-corporation_j34sbb.png" },
      { "color": "Black", "image": "https://res.cloudinary.com/djgz1kays/image/upload/v1765384958/black-clutch-by-Nova-International-designs-corporation_b64mbs.png" }
    ]
  },
  {
    "name": "Clutch - Golden",
    "price": 199.99,
    "slug": "clutch-golden",
    "category": "Accessories",
    "subcategory": "clutch",
    "minQty": 1,
    "description": "Elegant evening clutch available in multiple colors.",
    "images": [
      "https://res.cloudinary.com/djgz1kays/image/upload/v1764974490/golden-clutch-by-Nova-International-designs-corporation_lqmo2l.png"
    ],
   "variants": [
      { "color": "Magenta", "image": "https://res.cloudinary.com/djgz1kays/image/upload/v1764974490/magenta-clutch-by-Nova-International-designs-corporation_felron.png" },
      { "color": "Silver", "image": "https://res.cloudinary.com/djgz1kays/image/upload/v1764974491/silver-clutch-by-Nova-International-designs-corporation_fjuitv.png" },
      { "color": "Red", "image": "https://res.cloudinary.com/djgz1kays/image/upload/v1764974490/red-clutch-by-Nova-International-designs-corporation_dsmva3.png" },
      { "color": "Golden", "image": "https://res.cloudinary.com/djgz1kays/image/upload/v1764974490/golden-clutch-by-Nova-International-designs-corporation_lqmo2l.png" },
      { "color": "Glittery Gold", "image": "https://res.cloudinary.com/djgz1kays/image/upload/v1764974490/gittery-gold-clutch-by-Nova-International-designs-corporation_j34sbb.png" },
      { "color": "Black", "image": "https://res.cloudinary.com/djgz1kays/image/upload/v1765384958/black-clutch-by-Nova-International-designs-corporation_b64mbs.png" }
    ]
  },
  {
    "name": "Clutch - Glittery Gold",
    "price": 199.99,
    "slug": "clutch-glittery-gold",
    "category": "Accessories",
    "subcategory": "clutch",
    "minQty": 1,
    "description": "Elegant evening clutch available in multiple colors.",
    "images": [
      "https://res.cloudinary.com/djgz1kays/image/upload/v1764974490/gittery-gold-clutch-by-Nova-International-designs-corporation_j34sbb.png"
    ],
   "variants": [
      { "color": "Magenta", "image": "https://res.cloudinary.com/djgz1kays/image/upload/v1764974490/magenta-clutch-by-Nova-International-designs-corporation_felron.png" },
      { "color": "Silver", "image": "https://res.cloudinary.com/djgz1kays/image/upload/v1764974491/silver-clutch-by-Nova-International-designs-corporation_fjuitv.png" },
      { "color": "Red", "image": "https://res.cloudinary.com/djgz1kays/image/upload/v1764974490/red-clutch-by-Nova-International-designs-corporation_dsmva3.png" },
      { "color": "Golden", "image": "https://res.cloudinary.com/djgz1kays/image/upload/v1764974490/golden-clutch-by-Nova-International-designs-corporation_lqmo2l.png" },
      { "color": "Glittery Gold", "image": "https://res.cloudinary.com/djgz1kays/image/upload/v1764974490/gittery-gold-clutch-by-Nova-International-designs-corporation_j34sbb.png" },
      { "color": "Black", "image": "https://res.cloudinary.com/djgz1kays/image/upload/v1765384958/black-clutch-by-Nova-International-designs-corporation_b64mbs.png" }
    ]
  },
  {
    "name": "Clutch - Black",
    "price": 199.99,
    "slug": "clutch-black",
    "category": "Accessories",
    "subcategory": "clutch",
    "minQty": 1,
    "description": "Elegant evening clutch available in multiple colors.",
    "images": [
      "https://res.cloudinary.com/djgz1kays/image/upload/v1765384958/black-clutch-by-Nova-International-designs-corporation_b64mbs.png"
    ],
  "variants": [
      { "color": "Magenta", "image": "https://res.cloudinary.com/djgz1kays/image/upload/v1764974490/magenta-clutch-by-Nova-International-designs-corporation_felron.png" },
      { "color": "Silver", "image": "https://res.cloudinary.com/djgz1kays/image/upload/v1764974491/silver-clutch-by-Nova-International-designs-corporation_fjuitv.png" },
      { "color": "Red", "image": "https://res.cloudinary.com/djgz1kays/image/upload/v1764974490/red-clutch-by-Nova-International-designs-corporation_dsmva3.png" },
      { "color": "Golden", "image": "https://res.cloudinary.com/djgz1kays/image/upload/v1764974490/golden-clutch-by-Nova-International-designs-corporation_lqmo2l.png" },
      { "color": "Glittery Gold", "image": "https://res.cloudinary.com/djgz1kays/image/upload/v1764974490/gittery-gold-clutch-by-Nova-International-designs-corporation_j34sbb.png" },
      { "color": "Black", "image": "https://res.cloudinary.com/djgz1kays/image/upload/v1765384958/black-clutch-by-Nova-International-designs-corporation_b64mbs.png" }
    ]
  },

  {
    "name": "Jute Bag",
    "price": 199.99,
    "category": "Accessories",
    "subcategory": "jute-bag",
    "slug": "jute-bag",
    "sizes": ["S", "M", "L"],
    "minQty": 1,
    "description": "Jute bag available in multiple sizes.",
    "images": [
      "https://res.cloudinary.com/djgz1kays/image/upload/v1765384313/jute_Bag-NovaInternationalDesigns_tgz0yh.png"
    ]
  },

 {
    "name": "T2 Robot - NOVAT2-101",
    "productId": "NOVAT2-101",
    "price": 745.00,
    "description":"Educational Robot for kids with customized apps for educational learning for kids\nHelpful with Stem Education and Voice Commands and has parental control for kids \nAvailable for Shipping anywhere in USA",
    "category": "Electronics",
    "slug": "t2",
    "minQty": 1,
    "images": [
      "https://res.cloudinary.com/djgz1kays/image/upload/v1764974490/T2-by-Nova-International-designs-corporation_nlwiko.png"
    ]
  },
  {
    "name": "Kids Robot - NOVAT2-101",
    "productId": "NOVAT2-101",
    "price": 745.00,
    "description": "Educational Robot for kids with customized apps for educational learning for kids\nHelpful with Stem Education and Voice Commands and has parental control for kids \nAvailable for Shipping anywhere in USA",
    "category": "Electronics",
    "slug": "kids-robot",
    "minQty": 1,
    "images": [
      "https://res.cloudinary.com/djgz1kays/image/upload/v1764974490/T2-2-by-Nova-International-designs-corporation_rdi86f.png"    ]
  },
  {
    "name": "Technologically Advanced Robots - NOVAT2-101",
    "productId": "NOVAT2-101",
    "price": 745.00,
    "description": "Educational Robot for kids with customized apps for educational learning for kids\nHelpful with Stem Education and Voice Commands and has parental control for kids \nAvailable for Shipping anywhere in USA",
    "category": "Electronics",
    "slug": "technologically-advanced-robots",
    "minQty": 1,
    "images": [
      "https://res.cloudinary.com/djgz1kays/image/upload/v1764974490/T2-2-by-Nova-International-designs-corporation_rdi86f.png"    ]
  },
  {
    "name": "Vacuum Sealing Machine - NOVAVS-102",
    "productId": "NOVAVS-102",
    "price": 125.00,
    "description": "Vacuum sealing mechanism for plastic bags and has very Efficient and high quality sealing mechanism \nKeep any kind of food healthy, nutritious and safer to eat for you and  your family",
    "category": "Electronics",
    "subcategory": "vacuum-sealing-machine",
    "slug": "vacuum-sealing-machine",
    "minQty": 1,
    "images": [
      "https://res.cloudinary.com/djgz1kays/image/upload/v1764974490/vaccum-sealing-machine-by-Nova-International-Designs-Corporation_cqc6rj.png"
    ]
  },
  {
    "name": "Zip Lock Vacuum Sealers - NOVAVS-102",
    "productId": "NOVAVS-102",
    "price": 125.00,
    "description": "Vacuum sealing mechanism for plastic bags and has very Efficient and high quality sealing mechanism \nKeep any kind of food healthy, nutritious and safer to eat for you and  your family",
    "category": "Electronics",
    "subcategory": "vacuum-sealing-machine",
    "slug": "zip-lock-vacuum-sealers",
    "minQty": 1,
    "images": [
      "https://res.cloudinary.com/djgz1kays/image/upload/v1764974490/vaccum-sealing-machine-by-Nova-International-Designs-Corporation_cqc6rj.png"
    ]
  },
  {
    "name": "Kitchenware Vacuum Sealers - NOVAVS-102",
    "productId": "NOVAVS-102",
    "price": 125.00,
    "description": "Vacuum sealing mechanism for plastic bags and has very Efficient and high quality sealing mechanism \nKeep any kind of food healthy, nutritious and safer to eat for you and  your family",
    "category": "Electronics",
    "subcategory": "vacuum-sealing-machine",
    "slug": "kitchenware-vacuum-sealers",
    "minQty": 1,
    "images": [
      "https://res.cloudinary.com/djgz1kays/image/upload/v1764974490/vaccum-sealing-machine-by-Nova-International-Designs-Corporation_cqc6rj.png"
    ]
  },
  {
    "name": "Technologically Advance Vacuum Sealers - NOVAVS-102",
    "productId": "NOVAVS-102",
    "price": 125.00,
    "description": "Vacuum sealing mechanism for plastic bags and has very Efficient and high quality sealing mechanism \nKeep any kind of food healthy, nutritious and safer to eat for you and  your family",
    "category": "Electronics",
    "subcategory": "vacuum-sealing-machine",
    "slug": "technologically-advance-vacuum-sealers",
    "minQty": 1,
    "images": [
      "https://res.cloudinary.com/djgz1kays/image/upload/v1764974490/vaccum-sealing-machine-by-Nova-International-Designs-Corporation_cqc6rj.png"
    ]
  },
  {
    "name": "Digital Photo Frame - NOVADPF-105 ",
    "productId": "NOVADPF-105",
    "price":  225.00,
    "description":"Interactive Digital photo frame where you can upload \nYour good times and moments with loved ones",
    "category": "Electronics",
    "subcategory": "digital-photo-frame",
    "slug": "digital-photo-frame-2",
    "minQty": 1,
    "images": [
      "https://res.cloudinary.com/djgz1kays/image/upload/v1764974490/digital-photoframe-2-by-Nova-International-designs-corporation_xj1d1g.png"
    ]
  },
  {
    "name": "Digital Photo Frame - NOVADPF-105",
    "productId": "NOVADPF-105",
    "price": 225.00,
    "description":"Interactive Digital photo frame where you can upload \nYour good times and moments with loved ones",
    "category": "Electronics",
    "subcategory": "digital-photo-frame",
    "slug": "digital-photo-frame",
    "minQty": 1,
    "images": [
      "https://res.cloudinary.com/djgz1kays/image/upload/v1764974490/digital-photoframe-by-Nova-International-designs-corporation_ct2zvn.png"
    ]
  },
  {
    "name": "Campfire Light - NOVACF-104",
    "productId": "NOVACF-104",
    "price": 150.00,
    "description":" High quality lights and sound effect and Good connecting ability \nCreatively Designed and Best option for outdoor camping with family and loved ones ",
    "category": "Electronics",
    "subcategory": "campfire-light",
    "slug": "campfire-light",
    "minQty": 1,
    "images": [
      "https://res.cloudinary.com/djgz1kays/image/upload/v1764974490/campfire-light-by-Nova-International-designs-corporation_pewbmr.png"
    ]
  },
   {
    "name": "Bluetooth & Wireless Speakers - NOVACF-104",
    "productId": "NOVACF-104",
    "price": 150.00,
    "description":" High quality lights and sound effect and Good connecting ability \nCreatively Designed and Best option for outdoor camping with family and loved ones ",
    "category": "Electronics",
    "subcategory": "campfire-light",
    "slug": "bluetooth-wireless-speakers",
    "minQty": 1,
    "images": [
      "https://res.cloudinary.com/djgz1kays/image/upload/v1764974490/campfire-light-by-Nova-International-designs-corporation_pewbmr.png"
    ]
  },
    {
    "name": "Campfire Bluetooth Speakers - NOVACF-104",
    "productId": "NOVACF-104",
    "price": 150.00,
    "description":" High quality lights and sound effect and Good connecting ability \nCreatively Designed and Best option for outdoor camping with family and loved ones ",
    "category": "Electronics",
    "subcategory": "campfire-light",
    "slug": "campfire-bluetooth-speakers",
    "minQty": 1,
    "images": [
      "https://res.cloudinary.com/djgz1kays/image/upload/v1764974490/campfire-light-by-Nova-International-designs-corporation_pewbmr.png"
    ]
  },
   {
    "name": "Technologically Advanced Bluetooth Speakers - NOVACF-104",
    "productId": "NOVACF-104",
    "price": 150.00,
    "description":" High quality lights and sound effect and Good connecting ability \nCreatively Designed and Best option for outdoor camping with family and loved ones ",
    "category": "Electronics",
    "subcategory": "campfire-light",
    "slug": " technologically-advanced-bluetooth-speakers",
    "minQty": 1,
    "images": [
      "https://res.cloudinary.com/djgz1kays/image/upload/v1764974490/campfire-light-by-Nova-International-designs-corporation_pewbmr.png"
    ]
  },
   {
    "name": "Bladeless Fan - NOVAFN-106",
    "productId": "NOVAFN-106",
    "price": 1500.00,
    "description":"Modern designs with light and Musical effects\nNo Blades",
    "category": "Electronics",
    "subcategory": "bladeless-fan",
    "slug": "bladeless-fan",
    "minQty": 1,
    "images": [
      "https://res.cloudinary.com/djgz1kays/image/upload/v1765994752/bladeless-fan-by-Nova-International-designs-corporation_y9pozl.png"
    ]
  },
  {
    "name": "Technologically Advanced Fans - NOVAFN-106",
    "productId": "NOVAFN-106",
    "price": 1500.00,
    "description":"Modern designs with light and Musical effects\nNo Blades",
    "category": "Electronics",
    "subcategory": "bladeless-fan",
    "slug": "technologically-advanced-fans",
    "minQty": 1,
    "images": [
      "https://res.cloudinary.com/djgz1kays/image/upload/v1765994752/bladeless-fan-by-Nova-International-designs-corporation_y9pozl.png"
    ]
  },
{
    "name": "Musical Fans - NOVAFN-106",
    "productId": "NOVAFN-106",
    "price": 1500.00,
    "description":"Modern designs with light and Musical effects\nNo Blades",
    "category": "Electronics",
    "subcategory": "bladeless-fan",
    "slug": "musical-fans",
    "minQty": 1,
    "images": [
      "https://res.cloudinary.com/djgz1kays/image/upload/v1765994752/bladeless-fan-by-Nova-International-designs-corporation_y9pozl.png"
    ]
  },

  {
    "name": "Baby Monitor - NOVABM-103",
    "productId": "NOVABM-103",
    "price": 145.00,
    "description":"Highly Safe and secure for your little ones for monitoring your little ones at any moment to ensure their Safety \nEvery Cry and Needs of your baby  will not go unnoticed \nGood Connectivity and Creatively Designed for your loved ones and their precious moments",
    "category": "Electronics",
    "subcategory": "baby-monitor",
    "slug": "baby-monitor",
    "minQty": 1,
    "images": [
      "https://res.cloudinary.com/djgz1kays/image/upload/v1770925714/Baby-monitor-pink_kvkpev.jpg"
    ]
  }

];
const seedDatabase = async () => {
  try {
    console.log("Connecting to MongoDB...");
    await mongoose.connect(process.env.MONGO_URI);
    console.log("Connected!");

    console.log("Clearing existing products...");
    await Product.deleteMany({});

    console.log("Inserting products...");
    const inserted = await Product.insertMany(products);
    console.log(`✅ Added ${inserted.length} products!`);

    inserted.forEach((p, i) => {
      console.log(`${i + 1}. ${p.name} — $${p.price}`);
    });

  } catch (error) {
    console.error("❌ Failed:", error.message);
  } finally {
    await mongoose.disconnect();
    console.log("Done!");
  }
};

seedDatabase();