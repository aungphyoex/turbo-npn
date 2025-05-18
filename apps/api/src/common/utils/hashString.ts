import argon2 from 'argon2';

/**
 * @description Plain text transform to hex
 * @param password
 * @return Promise<string>
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
 * @description Compare plain password with hashed password
 * @param plainPassword
 * @param hashedPassword
 * @return Promise<boolean>
 */
const validateString = async (
  plainPassword: string,
  hashedPassword: string,
): Promise<boolean> => {
  try {
    return await argon2.verify(hashedPassword, plainPassword);
  } catch (e) {
    return false;
  }
};

export { hashString, validateString };
