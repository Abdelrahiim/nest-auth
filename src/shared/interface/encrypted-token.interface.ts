export interface EncryptedToken {
  iv: string;
  encrypted: string;
  authTag: string;
}
