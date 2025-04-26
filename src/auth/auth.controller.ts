import {
  Body,
  Controller,
  HttpCode,
  HttpStatus,
  Post,
  Req,
  Res,
} from '@nestjs/common';
import { AuthService } from './auth.service';
import { RegisterRequest } from './dto/register.dto';
import { LoginRequest } from './dto/login.dto';
import type { Request, Response } from 'express';
import {
  ApiTags,
  ApiOperation,
  ApiBody,
  ApiCookieAuth,
  ApiBadRequestResponse,
  ApiUnauthorizedResponse,
  ApiCreatedResponse,
  ApiOkResponse,
} from '@nestjs/swagger';

@ApiTags('Auth') // Группировка всех эндпоинтов в Swagger UI
@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @ApiOperation({ summary: 'Создание аккаунта' })
  @ApiBody({ type: RegisterRequest, description: 'Данные для регистрации' })
  @ApiCreatedResponse({
    description: 'Аккаунт успешно создан',
    schema: {
      example: { success: true, message: 'User registered successfully' },
    },
  })
  @ApiBadRequestResponse({
    description: 'Невалидные данные или пользователь уже существует',
  })
  @Post('register')
  @HttpCode(HttpStatus.CREATED)
  async register(
    @Res({ passthrough: true }) res: Response,
    @Body() dto: RegisterRequest,
  ) {
    return await this.authService.register(res, dto);
  }

  @ApiOperation({ summary: 'Вход в аккаунт' })
  @ApiBody({ type: LoginRequest, description: 'Данные для входа' })
  @ApiOkResponse({
    description: 'Успешный вход',
    schema: {
      example: { accessToken: 'string', refreshToken: 'string' },
    },
  })
  @ApiUnauthorizedResponse({ description: 'Неверные учетные данные' })
  @ApiBadRequestResponse({ description: 'Невалидные данные' })
  @Post('login')
  @HttpCode(HttpStatus.OK)
  async login(
    @Res({ passthrough: true }) res: Response,
    @Body() dto: LoginRequest,
  ) {
    return await this.authService.login(res, dto);
  }

  @ApiOperation({ summary: 'Обновление токена' })
  @ApiCookieAuth('refreshToken') // Указываем, что нужен cookie с refreshToken
  @ApiOkResponse({
    description: 'Токен успешно обновлен',
    schema: {
      example: { accessToken: 'string', refreshToken: 'string' },
    },
  })
  @ApiUnauthorizedResponse({
    description: 'Невалидный или отсутствующий refresh token',
  })
  @Post('refresh')
  @HttpCode(HttpStatus.OK)
  async refresh(
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response,
  ) {
    return await this.authService.refresh(req, res);
  }

  @ApiOperation({ summary: 'Выход из аккаунта и удаление токена' })
  @ApiCookieAuth('refreshToken')
  @ApiOkResponse({
    description: 'Успешный выход',
    schema: {
      example: { success: true, message: 'Logged out successfully' },
    },
  })
  @Post('logout')
  @HttpCode(HttpStatus.OK)
  logout(@Res({ passthrough: true }) res: Response) {
    return this.authService.logout(res);
  }
}
