import { IsEmail, IsNotEmpty, Matches, MaxLength, MinLength } from 'class-validator';

export class CreateUserDto {
  @IsEmail()
  email: string;

  @IsNotEmpty()
  // @Matches(
  //   /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/,
  //   {
  //     message:
  //       'Password must be at least 8 characters long and contain at least one uppercase letter, one lowercase letter, one number, and one special character',
  //   },
  // )
	@MinLength(8)
	@MaxLength(20)
  password: string;
}
