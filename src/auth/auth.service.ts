import { Injectable, UnauthorizedException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';
import { verify } from 'argon2';
import { User } from '../users/schema/user.schema';
import { UsersService } from '../users/users.service';
import { TokenPayload } from './interfaces/token-payload.interface';
import { FastifyReply } from 'fastify';

@Injectable()
export class AuthService {
  constructor(
    private readonly usersService: UsersService,
    private readonly configService: ConfigService,
    private readonly jwtService: JwtService,
  ) {}

  async login(user: User, res: FastifyReply) {
    const expiresAccessToken = new Date();
    expiresAccessToken.setMilliseconds(
      expiresAccessToken.getMilliseconds() +
        parseInt(this.configService.get('JWT_ACCESS_TOKEN_EXPIRATION')),
    );
    const tokenPayload = { sub: user._id.toString() } as TokenPayload;
    const accessToken = this.jwtService.sign(tokenPayload, {
      secret: this.configService.getOrThrow('JWT_ACCESS_TOKEN_SECRET_KEY'),
      expiresIn: `${this.configService.getOrThrow(
        'JWT_ACCESS_TOKEN_EXPIRATION',
      )}ms`,
    });

    res.setCookie('Authentication', accessToken, {
      httpOnly: true,
      secure: this.configService.get('NODE_ENV') === 'production',
      path:"/",
      expires: expiresAccessToken,
    });
    return res.send({ data: user });
  }
  async verifyUser(email: string, password: string) {
    try {
      const user = await this.usersService.getUser({ email });

      const authenticated = await verify(user.password, password);
      if (!authenticated) {
        throw new UnauthorizedException('Invalid credentials');
      }
      delete user.password;
      return user;
    } catch (error) {
      throw new UnauthorizedException('Invalid credentials');
    }
  }
}
