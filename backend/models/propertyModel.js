const mongoose = require("mongoose");
const AutoIncrement = require("mongoose-sequence")(mongoose);

const PropertySchema = new mongoose.Schema(
  {
    propertyId: {
      type: Number,
      unique: true,
    },
    project: {
      type: String,
      required: true,
      trim: true,
    },
    imgSrc: {
      type: String,
      required: true,
      trim: true,
    },
    alt: {
      type: String,
      required: true,
      trim: true,
    },
    address: {
      type: String,
      required: true,
      trim: true,
    },
    title: {
      type: String,
      required: true,
      trim: true,
    },
    description: {
      type: String,
      required: true,
      trim: true,
    },
    yearBuilt: {
      type: Number,
      required: true,
      trim: true,
    },
    features: {
      type: [[String]],
      required: true,
      trim: true,
    },
    city: {
      type: String,
      required: true,
      trim: true,
    },
    country: {
      type: String,
      required: true,
      trim: true,
    },
    mapSrc: {
      type: mongoose.Schema.Types.Mixed,
      required: true,
      trim: true,
    },
    beds: {
      type: Number,
      required: true,
      trim: true,
    },
    rooms: {
      type: Number,
      required: true,
      trim: true,
    },
    baths: {
      type: Number,
      required: true,
      trim: true,
    },
    sqm: {
      type: Number,
      required: true,
      trim: true,
    },
    tags: {
      type: [String],
      required: true,
      trim: true,
    },
    avatar: {
      type: String,
      required: true,
      trim: true,
    },
    agent: {
      type: String,
      required: true,
      trim: true,
    },
    lat: {
      type: Number,
      required: true,
      trim: true,
    },
    long: {
      type: Number,
      required: true,
      trim: true,
    },
    filterOptions: {
      type: [String],
      required: true,
      trim: true,
    },
    type: {
      type: [String],
      required: true,
      trim: true,
    },
    floor: {
      type: String,
      required: true,
      trim: true,
    },
    block: {
      type: String,
      required: true,
      trim: true,
    },
    price: {
      type: Number,
      required: true,
      trim: true,
    },
    gallery: {
      type: [{ href: String, className: String, src: String }],
      required: true,
      trim: true,
    },
    status: {
      type: String,
      enum: ["available", "rented", "sold out", "under construction"],
      default: "available",
      required: true,
      trim: true,
    },
  },
  { timestamps: true }
);

PropertySchema.plugin(AutoIncrement, { inc_field: "propertyId" });

module.exports = mongoose.model("Property", PropertySchema);
