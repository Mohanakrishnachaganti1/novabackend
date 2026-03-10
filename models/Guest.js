import mongoose from "mongoose";

const GuestSchema = new mongoose.Schema(
  {
    name: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    sessionId: { type: String, unique: true, sparse: true }, // unique session token for guest
  },
  { timestamps: true }
);

export default mongoose.model("Guest", GuestSchema);
