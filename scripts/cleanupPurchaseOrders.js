import connectDB from '../config/db.js';
import PurchaseOrder from '../models/PurchaseOrder.js';

const run = async () => {
  await connectDB();
  console.log('Connected, scanning purchase orders for empty fields...');

  const cursor = PurchaseOrder.find().cursor();
  let count = 0;
  for (let doc = await cursor.next(); doc != null; doc = await cursor.next()) {
    const unset = {};
    const set = {};

    // top-level string fields to remove if empty
    const topFields = ['bankName','accountNo','routingNo','customerName','email','attn','address','tel','fax','notes'];
    topFields.forEach((f) => {
      if (doc[f] === '') unset[f] = "";
    });

    // shippingInfo nested
    if (doc.shippingInfo && typeof doc.shippingInfo === 'object') {
      Object.keys(doc.shippingInfo).forEach((k) => {
        if (doc.shippingInfo[k] === '') unset[`shippingInfo.${k}`] = "";
      });
    }

    // form nested: remove empty-string fields inside form
    if (doc.form && typeof doc.form === 'object') {
      Object.keys(doc.form).forEach((k) => {
        if (typeof doc.form[k] === 'string' && doc.form[k].trim() === '') unset[`form.${k}`] = "";
      });
    }

    // if there are unsets, perform update
    if (Object.keys(unset).length > 0) {
      try {
        await PurchaseOrder.updateOne({ _id: doc._id }, { $unset: unset });
        count++;
        console.log(`Cleaned order ${doc._id}`);
      } catch (e) {
        console.error(`Failed to clean ${doc._id}:`, e.message);
      }
    }
  }

  console.log(`Done. Cleaned ${count} orders.`);
  process.exit(0);
};

run().catch((e) => {
  console.error('Migration error:', e);
  process.exit(1);
});
