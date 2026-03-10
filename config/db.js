import mongoose from "mongoose";

const connectDB = async () => {
  try {
    await mongoose.connect(process.env.MONGO_URI);
    console.log("MongoDB connected successfully");

    // Drop old userId_1 index from PurchaseOrderDraft collection
    try {
      const db = mongoose.connection.db;
      const collection = db.collection('purchaseorderdrafts');

      // Use listIndexes() to get indexes
      const indexCursor = collection.listIndexes();
      const indexes = await indexCursor.toArray();

      // Find and drop userId_1 index
      const userIdIndex = indexes.find(i => i.name === 'userId_1');
      if (userIdIndex) {
        await collection.dropIndex('userId_1');
        console.log('Dropped old userId_1 index from purchaseorderdrafts collection');
      }
    } catch (indexErr) {
      if (!indexErr.message.includes('index not found') && !indexErr.message.includes('does not exist')) {
        console.warn('Warning during index cleanup:', indexErr.message);
      }
    }
  } catch (err) {
    console.error("MongoDB connection error:", err);
  }
};

export default connectDB;
