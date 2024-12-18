import { Injectable, NotFoundException } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { FilterQuery, Model } from 'mongoose';
import { User } from './schema/user.schema';
import { CreateUserDto } from './dto/create-user.dto';
import { hash, argon2id, verify } from 'argon2';
@Injectable()
export class UsersService {
  constructor(@InjectModel('User') private readonly userModel: Model<User>) {}

  public async createUser(createUserDto: CreateUserDto) {
    const hashedPassword = await this.hashPassword(createUserDto.password);

    const user = new this.userModel({
      ...createUserDto,
      password: hashedPassword,
    });
    const newUser = (await user.save()).toObject();

    delete newUser.password;
    return newUser;
  }

  public async getUser(query: FilterQuery<User>) {
    const user = (await this.userModel.findOne(query)).toObject();
    if (!user) {
      throw new NotFoundException('User not found');
    }
    return user;
  }

  private async hashPassword(password: string) {
    return hash(password, { type: argon2id });
  }
}
