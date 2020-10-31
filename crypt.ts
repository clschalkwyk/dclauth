import {randomBytes, scrypt, createCipheriv, createDecipheriv} from "crypto";
import {promisify} from "util";
import {v4 as uuidv4} from 'uuid';

const scryptAsync = promisify(scrypt);

export async function toHash(password: string): Promise<string> {
  const salt = randomBytes(16).toString('hex');
  let buff;

  try {
    buff = (await scryptAsync(password, salt, 64)) as Buffer;
  } catch (error) {
    throw error;
  }
  return Promise.resolve(`${buff.toString('hex')}.${salt}`);
}

export async function toHashWithSalt(password: string, salt: string): Promise<string> {
  let buff;

  try {
    buff = (await scryptAsync(password, salt, 64)) as Buffer;
  } catch (error) {
    throw error;
  }
  return Promise.resolve(`${buff.toString('hex')}`);
}

const cryptAlgo = 'aes-256-ctr';

export function encrypt(input: string) {
  const cipher = createCipheriv(cryptAlgo, process.env.CRYPT_SECRET, process.env.ENCRYPT_IV);
  return Buffer.concat([cipher.update(input), cipher.final()]);
}

export function decrypt(input: string) {
  const decipher = createDecipheriv(cryptAlgo, process.env.CRYPT_SECRET, process.env.ENCRYPT_IV);
  const decrypted = Buffer.concat([decipher.update(Buffer.from(input, 'hex')), decipher.final()]);

  return decrypted.toString();
}


export async function compare(savedPassword: string, inputPassword: string): Promise<boolean> {

  // split the known password to get salt and hashed password
  const [hashedPassword, salt] = savedPassword.split('.');

  // encrypt incoming password with saved salt
  const buff = (await scryptAsync(inputPassword, salt, 64)) as Buffer;

  // return comparison between stored and computed password hashes
  return Promise.resolve(hashedPassword === buff.toString('hex'));
}

export async function getToken(): Promise<string> {
  const uuid = uuidv4();
  const salt = randomBytes(16).toString('hex');
  return Promise.resolve(`${uuid}.${salt}`);

}
