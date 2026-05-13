require('dotenv').config({ path: require('path').join(__dirname, '../../.env') });
const dns = require('dns');
dns.setServers(['8.8.8.8', '8.8.4.4']);
const mongoose      = require('mongoose');
const fs            = require('fs');
const path          = require('path');
const Review        = require('../models/Review');
const ReviewSection = require('../models/ReviewSection');

const SECTION_KEYS = ['iam', 'networking', 'storage', 'compute', 'securityCenter',
                      'keyVault', 'monitor', 'resourceGroups', 'policy'];

async function migrate() {
  await mongoose.connect(process.env.MONGODB_URI, { family: 4 });
  console.log('Connected to MongoDB');

  const reviews = await Review.find({}).lean();
  console.log(`Found ${reviews.length} reviews to check`);

  let migrated = 0;
  let skipped  = 0;
  let failed   = 0;

  for (const review of reviews) {
    const existing = await ReviewSection.countDocuments({ reviewId: review.reviewId });
    if (existing > 0) {
      console.log(`  [skip]    ${review.reviewId} — ${review.name} (already in DB)`);
      skipped++;
      continue;
    }

    const sections = {};
    for (const key of SECTION_KEYS) {
      const filePath = path.join(review.scanDir, `${key}.json`);
      try {
        sections[key] = fs.existsSync(filePath)
          ? JSON.parse(fs.readFileSync(filePath, 'utf8'))
          : [];
      } catch {
        sections[key] = [];
      }
    }

    const toSave = Object.entries(sections).filter(([, data]) => data.length > 0);
    if (toSave.length === 0) {
      console.log(`  [empty]   ${review.reviewId} — ${review.name} (no file data found)`);
      failed++;
      continue;
    }

    await ReviewSection.bulkWrite(
      toSave.map(([key, data]) => ({
        updateOne: {
          filter: { reviewId: review.reviewId, key },
          update: { $set: { data } },
          upsert: true,
        },
      }))
    );

    console.log(`  [migrated] ${review.reviewId} — ${review.name} (${toSave.length} sections)`);
    migrated++;
  }

  console.log(`\nDone: ${migrated} migrated, ${skipped} already in DB, ${failed} empty/failed`);
  await mongoose.disconnect();
}

migrate().catch(err => {
  console.error('Migration failed:', err);
  process.exit(1);
});
