const multer = require("multer");
const { CloudinaryStorage } = require("multer-storage-cloudinary");
const cloudinary = require("./cloudinary");

const storage = new CloudinaryStorage({
  cloudinary,
  params: {
    folder: "products",   // Cloudinary folder
    resource_type: "auto" // allows images AND videos
  },
});

const upload = multer({ storage });

module.exports = upload;

