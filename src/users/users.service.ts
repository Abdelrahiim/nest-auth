import { Injectable, NotFoundException } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { FilterQuery, Model } from 'mongoose';
import { User } from './schema/user.schema';
import { CreateUserDto } from './dto/create-user.dto';
import { CryptoService } from '../shared/utils/crypto.service';

@Injectable()
export class UsersService {
  constructor(
    @InjectModel('User') private readonly userModel: Model<User>,
    private readonly cryptoService: CryptoService,
  ) {}

  public async createUser(createUserDto: CreateUserDto, oAuthClient?: string) {
    const hashedPassword = await this.cryptoService.hash(
      createUserDto.password,
    );

    const user = new this.userModel({
      ...createUserDto,
      password: hashedPassword,
      oAuthClient,
    });
    const newUser = (await user.save()).toObject();

    delete newUser.password;
    return newUser;
  }

  public async getOrCreateUser(data: CreateUserDto) {
    const user = await this.userModel.findOne({ email: data.email });
    if (user) {
      delete user.password;
      return user;
    }
    return this.createUser(data, 'google');
  }

  public async getUser(query: FilterQuery<User>) {
    const user = await this.userModel.findOne(query);
    if (!user) {
      throw new NotFoundException('User not found');
    }
    return user.toObject();
  }
}
