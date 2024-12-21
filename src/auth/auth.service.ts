import { Injectable, Logger, UnauthorizedException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';
import { User } from '../users/schema/user.schema';
import { UsersService } from '../users/users.service';
import { TokenPayload } from './interfaces/token-payload.interface';
import { Response } from 'express';
import { CryptoService } from '../shared/utils/crypto.service';
import { RedisService } from '../shared/utils/redis.service';

@Injectable()
export class AuthService {
  private readonly logger = new Logger('AuthService');
  constructor(
    private readonly usersService: UsersService,
    private readonly configService: ConfigService,
    private readonly jwtService: JwtService,
    private readonly cryptoService: CryptoService,
    private readonly redisService: RedisService,
  ) {}

  public async login(user: User, res: Response) {
    const {
      accessToken,
      refreshToken,
      expiresAccessToken,
      expiresRefreshToken,
    } = this.generateTokens(user);
    const refreshTokenHash = await this.cryptoService.hash(refreshToken);
    this.redisService.set(
      `refreshToken:${user._id.toString()}`,
      refreshTokenHash,
    );

    res.cookie('Authentication', accessToken, {
      httpOnly: true,
      secure: this.configService.get('NODE_ENV') === 'production',
      path: '/',
      expires: expiresAccessToken,
    });

    res.cookie('Refresh', refreshToken, {
      httpOnly: true,
      secure: this.configService.get('NODE_ENV') === 'production',
      path: '/',
      expires: expiresRefreshToken,
    });
    
    return  {data: user };
  }

  public async verifyUser(email: string, password: string) {
    try {
      const user = await this.usersService.getUser({ email });

      const authenticated = await this.cryptoService.compare(
        password,
        user.password,
      );

      if (!authenticated) {
        throw new UnauthorizedException('Invalid credentials');
      }
      delete user.password;
      return user;
    } catch (error) {
      this.logger.error(error);
      throw new UnauthorizedException('Invalid credentials');
    }
  }

  /**
   * Generates a new access token for the given user and sets it as a cookie
   * on the response.
   * @param user - The user to generate the new access token for.
   * @param res - The response object to set the cookie on.
   */
  public refreshAccessToken(user: User, res: Response) {
    const tokenPayload = { sub: user._id.toString() } as TokenPayload;
    const { accessToken, expiresAccessToken } =
      this.generateAccessToken(tokenPayload);

    res.cookie('Authentication', accessToken, {
      httpOnly: true,
      secure: this.configService.get('NODE_ENV') === 'production',
      path: '/',
      expires: expiresAccessToken,
    });
  }

  /**
   * Verifies a refresh token. If the token is invalid, it throws an UnauthorizedException.
   * @param refreshToken The refresh token to verify.
   * @param userId The user ID that the refresh token belongs to.
   * @returns The user object if the token is valid.
   */
  public async verifyRefreshToken(refreshToken: string, userId: string) {
    try {
      const user = await this.usersService.getUser({ _id: userId });
      if (!user) {
        throw new UnauthorizedException('Invalid refresh token');
      }
      const hashedRefreshToken = await this.redisService.get(
        `refreshToken:${userId}`,
      );
      if (!hashedRefreshToken) {
        throw new UnauthorizedException('Invalid refresh token');
      }
      const isValid = await this.cryptoService.compare(
        refreshToken,
        hashedRefreshToken,
      );
      if (!isValid) {
        throw new UnauthorizedException('Invalid refresh token');
      }
      delete user.password;

      return user;
    } catch (error) {
      this.logger.error(error);
      throw new UnauthorizedException('Invalid refresh token');
    }
  }

  /**
   * Generates an access token and refresh token for the given user.
   * @param user - The user to generate the tokens for.
   * @returns An object containing the generated access token, its expiration date,
   * and the refresh token.
   */
  private generateTokens(user: User) {
    const tokenPayload: TokenPayload = { sub: user._id.toString() };
    const accessTokenData = this.generateAccessToken(tokenPayload);
    const refreshTokenData = this.generateRefreshToken(tokenPayload);

    return {
      ...accessTokenData,
      ...refreshTokenData,
    };
  }

  /**
   * Generates an access token and its expiration date.
   * @param tokenPayload - The payload to include in the access token.
   * @returns An object containing the generated access token and its expiration date.
   */
  private generateAccessToken(tokenPayload: TokenPayload) {
    const expiresAccessToken = new Date(
      Date.now() +
        parseInt(this.configService.getOrThrow('JWT_ACCESS_TOKEN_EXPIRATION')),
    );
    const accessToken = this.jwtService.sign(tokenPayload, {
      secret: this.configService.getOrThrow('JWT_ACCESS_TOKEN_SECRET_KEY'),
      expiresIn: `${this.configService.getOrThrow('JWT_ACCESS_TOKEN_EXPIRATION')}ms`,
    });

    return { accessToken, expiresAccessToken };
  }

  /**
   * Generates a refresh token and its expiration date.
   * @param tokenPayload payload for the refresh token
   * @returns an object with the refresh token and its expiration date
   */
  private generateRefreshToken(tokenPayload: TokenPayload) {
    const expiresRefreshToken = new Date(
      Date.now() +
        parseInt(this.configService.getOrThrow('JWT_REFRESH_TOKEN_EXPIRATION')),
    );
    const refreshToken = this.jwtService.sign(tokenPayload, {
      secret: this.configService.getOrThrow('JWT_REFRESH_TOKEN_SECRET_KEY'),
      expiresIn: `${this.configService.getOrThrow('JWT_REFRESH_TOKEN_EXPIRATION')}ms`,
    });

    return { refreshToken, expiresRefreshToken };
  }
}
