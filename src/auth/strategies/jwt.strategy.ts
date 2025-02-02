import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { PassportStrategy } from '@nestjs/passport';
import { Request } from 'express';
import { ExtractJwt, Strategy } from 'passport-jwt';
import { TokenPayload } from '../interfaces/token-payload.interface';
import { UsersService } from '../../users/users.service';

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy) {
  constructor(
    private readonly configService: ConfigService,
    private readonly usersService: UsersService,
  ) {
    super({
      jwtFromRequest: ExtractJwt.fromExtractors([
        (req: Request) => req.cookies?.Authentication,
      ]),
      secretOrKey: configService.getOrThrow('JWT_ACCESS_TOKEN_SECRET_KEY'),
    });
  }

  async validate(payload: TokenPayload) {
    const user = await this.usersService.getUser({ _id: payload.sub });
    delete user.password;
    return user;
  }
}
