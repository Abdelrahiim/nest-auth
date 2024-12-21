import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import * as argon2 from 'argon2';
import { createCipheriv, createDecipheriv, randomBytes } from 'crypto';
import { EncryptedToken } from '../interface/encrypted-token.interface';

@Injectable()
export class CryptoService {
  constructor(private readonly configService: ConfigService) {}

  /**
   * Encrypts a token with AES-256-GCM.
   * @param token the token to encrypt.
   * @returns the encrypted token.
   */
  public encrypt(token: string): EncryptedToken {
    const iv = randomBytes(
      parseInt(this.configService.getOrThrow('IV_LENGTH')),
    );
    const cipher = createCipheriv(
      'aes-256-gcm',
      this.configService.getOrThrow('ENCRYPTION_KEY'),
      iv,
    );

    let encrypted = cipher.update(token, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    const authTag = cipher.getAuthTag();
    return {
      iv: iv.toString('hex'),
      encrypted: encrypted,
      authTag: authTag.toString('hex'),
    };
  }

  /**
   * Decrypts a token which was previously encrypted with the encrypt method.
   * @param encryptedToken the encrypted token to decrypt.
   * @returns the decrypted token.
   */
  public decrypt(encryptedToken: EncryptedToken): string {
    const { iv, authTag, encrypted } = encryptedToken;
    const decipher = createDecipheriv(
      'aes-256-gcm',
      this.configService.getOrThrow('ENCRYPTION_KEY'),
      Buffer.from(iv, 'hex'),
    );
    decipher.setAuthTag(Buffer.from(authTag, 'hex'));
    let decrypted = decipher.update(encrypted, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
  }

  /**
   * Hashes a password with Argon2id.
   * @param password the password to hash.
   * @returns the hashed password.
   */
  public async hash(password: string) {
    return argon2.hash(password);
  }

  /**
   * Compares a plain text password with a hashed password using Argon2id.
   * @param password The plain text password to verify.
   * @param hashedPassword The hashed password to compare against.
   * @returns A promise that resolves to true if the password matches the hash, otherwise false.
   */
  public async compare(password: string, hashedPassword: string) {
    return await argon2.verify(hashedPassword, password);
  }
}
