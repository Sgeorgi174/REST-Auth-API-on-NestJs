import { ApiProperty } from '@nestjs/swagger';
import {
  IsEmail,
  IsNotEmpty,
  IsString,
  Length,
  MaxLength,
} from 'class-validator';

export class LoginRequest {
  @ApiProperty({ description: 'email', example: 'example@example.com' })
  @IsString({ message: 'email должен  быть строкой' })
  @IsEmail({}, { message: 'должен быть валидный формат email' })
  @IsNotEmpty({ message: 'email должен быть указан обязательно' })
  @MaxLength(50, { message: 'email не должен содержать больше 50 символов' })
  email: string;

  @ApiProperty({ description: 'password', example: 'qwerty123', minLength: 6 })
  @IsString({ message: 'пароль должен быть строкой' })
  @IsNotEmpty({ message: 'пароль должен быть указан обязательно' })
  @Length(6, 20, { message: 'Пароль должен содержвать не менее 6 символов' })
  password: string;
}
