/* One-time Stripe setup: creates the 4 products + prices for Tech Sales Accelerator.
   Run: STRIPE_SECRET_KEY=sk_test_... node stripe-setup.js
   Prints env-ready PRICE_* lines. Safe to re-run: looks up existing products by metadata key first. */
const Stripe = require("stripe");

const key = process.env.STRIPE_SECRET_KEY;
if (!key) { console.error("Set STRIPE_SECRET_KEY"); process.exit(1); }
const stripe = new Stripe(key);

const CATALOG = [
  { key: "mobility",   name: "Tech Sales Accelerator \u2014 Mobility Track",     amount: 39700 },
  { key: "cities",     name: "Tech Sales Accelerator \u2014 Smart Cities Track", amount: 39700 },
  { key: "energy",     name: "Tech Sales Accelerator \u2014 Smart Energy Track", amount: 39700 },
  { key: "bundle",     name: "Tech Sales Accelerator \u2014 Three-Track Bundle", amount: 79700 },
  { key: "membership", name: "Tech Sales Accelerator \u2014 Career Membership",  amount: 2900, recurring: { interval: "month" } },
];

async function findProductByKey(k) {
  const res = await stripe.products.search({ query: `metadata['tsa_key']:'${k}'` });
  return res.data[0] || null;
}

(async () => {
  const envLines = [];
  for (const item of CATALOG) {
    let product = await findProductByKey(item.key);
    if (!product) {
      product = await stripe.products.create({
        name: item.name,
        metadata: { tsa_key: item.key },
      });
      console.log(`created product ${item.key}: ${product.id}`);
    } else {
      console.log(`found product ${item.key}: ${product.id}`);
    }

    // Find an active USD price at the right amount and shape (one-time vs recurring), else create one.
    const prices = await stripe.prices.list({ product: product.id, active: true, limit: 10 });
    let price = prices.data.find(p =>
      p.unit_amount === item.amount && p.currency === "usd" &&
      (item.recurring ? p.recurring?.interval === item.recurring.interval : !p.recurring));
    if (!price) {
      price = await stripe.prices.create({
        product: product.id,
        unit_amount: item.amount,
        currency: "usd",
        ...(item.recurring ? { recurring: item.recurring } : {}),
      });
      console.log(`  created price: ${price.id} ($${item.amount / 100})`);
    } else {
      console.log(`  found price: ${price.id} ($${item.amount / 100})`);
    }
    envLines.push(`PRICE_${item.key.toUpperCase()}=${price.id}`);
  }

  console.log("\n--- add to your environment ---");
  envLines.forEach(l => console.log(l));
  console.log("\nOptional founding-member coupon (25% off, run once):");
  console.log("  await stripe.coupons.create({ id: 'FOUNDING100', percent_off: 25, duration: 'once', max_redemptions: 100 })");
})().catch(e => { console.error(e.message); process.exit(1); });
