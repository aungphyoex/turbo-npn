import crypto from 'crypto';

/**
 * Generates a numeric One-Time Password (OTP) of specified length.
 *
 * @param {number} [length=6] - The length of the OTP to generate.
 * @returns {Promise<string>} A promise that resolves to the generated OTP as a zero-padded string.
 */
export const generateOTP = async (length = 6): Promise<string> => {
  return crypto
    .randomInt(0, 10 ** length)
    .toString()
    .padStart(length, '0');
};
