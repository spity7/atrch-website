const Property = require("../models/propertyModel.js");
const { Parser } = require("json2csv");
const logger = require("../config/logger.js");

exports.getAllProperties = async (req, res) => {
  try {
    const { search, project, types = [], page = 1, limit = 6 } = req.query;
    const query = {};

    if (project) {
      query.project = project;
    }

    if (search) {
      const searchRegex = new RegExp(search, "i"); // Case-insensitive regex
      query.$or = [{ title: { $regex: searchRegex } }];
    }

    if (types.length > 0) {
      // ensure types is an array of strings
      const typesArray = Array.isArray(types) ? types : types.split(",");
      query.type = { $in: typesArray };
    }

    const properties = await Property.find(query)
      .sort({ createdAt: 1 })
      .skip((page - 1) * limit)
      .limit(Number(limit));

    const total = await Property.countDocuments(query);

    res
      .status(200)
      .json({ properties, total, page: Number(page), limit: Number(limit) });
  } catch (error) {
    res.status(500).json({ error: "Server Error" });
  }
};

exports.getPropertyByPropertyId = async (req, res) => {
  try {
    const { propertyId } = req.params;
    const property = await Property.findOne({
      propertyId: Number(propertyId),
    });
    if (!property) {
      return res.status(404).json({ error: "Property not found" });
    }
    res.json(property);
  } catch (error) {
    res.status(500).json({ error: "Server Error" });
  }
};

exports.getTypes = async (req, res) => {
  try {
    const { project } = req.query;

    const query = {};
    if (project) {
      query.project = project; // Filter by project if specified
    }

    const types = await Property.distinct("type", query);
    res.status(200).json(types);
  } catch (error) {
    res.status(500).json({ error: "Server Error" });
  }
};

exports.updateProperty = async (req, res) => {
  try {
    const { propertyId } = req.params;
    const updateData = req.body;
    console.log("Received updateData:", updateData); // <-- Add this

    // Find and update the property by propertyId
    const updatedProperty = await Property.findOneAndUpdate(
      { propertyId: Number(propertyId) },
      updateData,
      { new: true, runValidators: true }
    );

    console.log("Updated property:", updatedProperty);

    if (!updatedProperty) {
      return res.status(404).json({ error: "Property not found" });
    }

    res.status(200).json(updatedProperty);
  } catch (error) {
    res
      .status(500)
      .json({ message: "Internal server error", error: error.message });
  }
};
