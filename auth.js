
const bcrypt = require("bcryptjs");


// Function to hash a password
async function hashPassword(password) {
  const saltRounds = 10; 
  const hash = await bcrypt.hash(password, saltRounds);
  return hash;
}

// Function to verify a password
async function verifyPassword(password, hashedPassword) {
  const match = await bcrypt.compare(password, hashedPassword);
  return match; 
}

// Example usage
(async () => {
  const plainPassword = "mySecret123";

  // Hashing
  const hashed = await hashPassword(plainPassword);
  console.log("Hashed password:", hashed);

  // Verifying (simulate login)
  const isMatch = await verifyPassword("mySecret123", hashed);
  console.log("Password matches:", isMatch); // true
})();
