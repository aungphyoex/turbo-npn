import argon2 from 'argon2';

/**
 * Hashes a plain text password using Argon2id algorithm.
 *
 * @param {string} password - The plain text password to hash.
 * @returns {Promise<string>} The hashed password as a string.
 */
const hashString = async (password: string): Promise<string> => {
  return await argon2.hash(password, {
    type: argon2.argon2id,
    memoryCost: 2 ** 8,
    timeCost: 5,
    parallelism: 1,
  });
};

/**
 * Compares a plain text password with a hashed password.
 *
 * @param {string} plainPassword - The plain text password to verify.
 * @param {string} hashedPassword - The hashed password to compare against.
 * @returns {Promise<boolean>} True if the passwords match, false otherwise.
 */
const validateString = async (
  plainPassword: string,
  hashedPassword: string,
): Promise<boolean> => {
  try {
    return await argon2.verify(hashedPassword, plainPassword);
  } catch {
    return false;
  }
};

export { hashString, validateString };
