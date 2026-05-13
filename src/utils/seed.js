const bcrypt = require('bcryptjs');
const User   = require('../models/User');

const SEED_USER = {
  name:     'Demo User',
  email:    'demo@azurereview.com',
  password: 'Demo1234!',
};

async function seedDemoUser() {
  const exists = await User.findOne({ email: SEED_USER.email });
  if (exists) return;

  const passwordHash = await bcrypt.hash(SEED_USER.password, 12);
  await User.create({ name: SEED_USER.name, email: SEED_USER.email, passwordHash });

  console.log('─────────────────────────────────────────');
  console.log('  Demo account created');
  console.log(`  Email   : ${SEED_USER.email}`);
  console.log(`  Password: ${SEED_USER.password}`);
  console.log('─────────────────────────────────────────');
}

module.exports = seedDemoUser;
