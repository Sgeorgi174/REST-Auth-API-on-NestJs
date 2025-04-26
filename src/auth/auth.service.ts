import {
  ConflictException,
  Injectable,
  NotFoundException,
  UnauthorizedException,
} from '@nestjs/common';
import { PrismaService } from 'src/prisma/prisma.service';
import { RegisterRequest } from './dto/register.dto';
import { hash, verify } from 'argon2';
import { ConfigService } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';
import type { JwtPayload } from './interfaces/jwt.interface';
import { LoginRequest } from './dto/login.dto';
import type { Request, Response } from 'express';
import { isDev } from 'src/utils/is-dev.utils';

@Injectable()
export class AuthService {
  private readonly JWT_ACCESS_TOKEN_TTL: string;
  private readonly JWT_REFRESH_TOKEN_TTL: string;
  private readonly COOKIE_DOMAIN: string;

  constructor(
    private readonly prismaService: PrismaService,
    private readonly configService: ConfigService,
    private readonly jwtService: JwtService,
  ) {
    this.JWT_ACCESS_TOKEN_TTL = configService.getOrThrow<string>(
      'JWT_ACCESS_TOKEN_TTL',
    );
    this.JWT_REFRESH_TOKEN_TTL = configService.getOrThrow<string>(
      'JWT_REFRESH_TOKEN_TTL',
    );
    this.COOKIE_DOMAIN = configService.getOrThrow<string>('COOKIE_DOMAIN');
  }

  private setCookie(res: Response, value: string, expires: Date) {
    res.cookie('refreshToken', value, {
      httpOnly: true,
      domain: this.COOKIE_DOMAIN,
      expires,
      secure: !isDev(this.configService),
      sameSite: isDev(this.configService) ? 'none' : 'lax',
    });
  }

  private generateTokens(id: string) {
    const payLoad: JwtPayload = { id };

    const accesToken = this.jwtService.sign(payLoad, {
      expiresIn: this.JWT_ACCESS_TOKEN_TTL,
    });

    const refreshToken = this.jwtService.sign(payLoad, {
      expiresIn: this.JWT_REFRESH_TOKEN_TTL,
    });

    return { accesToken, refreshToken };
  }

  private auth(res: Response, id: string) {
    const { refreshToken, accesToken } = this.generateTokens(id);

    this.setCookie(
      res,
      refreshToken,
      new Date(Date.now() + 1000 * 60 * 60 * 24 * 7),
    );

    return { accesToken };
  }

  async register(res: Response, dto: RegisterRequest) {
    const { name, email, password } = dto;

    const existUser = await this.prismaService.user.findUnique({
      where: {
        email,
      },
    });

    if (existUser) {
      throw new ConflictException({
        message: 'Пользователь с таким email уже существует',
      });
    }

    const user = await this.prismaService.user.create({
      data: {
        email,
        name,
        password: await hash(password),
      },
    });

    return this.auth(res, user.id);
  }

  async login(res: Response, dto: LoginRequest) {
    const { email, password } = dto;

    const user = await this.prismaService.user.findUnique({
      where: {
        email,
      },
      select: {
        id: true,
        password: true,
      },
    });

    if (!user) throw new NotFoundException('Неверный email или пароль');

    const isValidPassword = await verify(user.password, password);

    if (!isValidPassword)
      throw new NotFoundException('Неверный email или пароль');

    return this.auth(res, user.id);
  }

  async refresh(req: Request, res: Response) {
    if (!req.cookies)
      throw new UnauthorizedException('Ошибка получения cookie');

    const refreshToken: string = req.cookies['refreshToken'] as string;

    if (!refreshToken) {
      throw new UnauthorizedException('Невалидный рефреш токен');
    }

    const payLoad: JwtPayload = await this.jwtService.verifyAsync(refreshToken);

    if (!payLoad) {
      throw new UnauthorizedException('Невалидный payload');
    }

    if (payLoad) {
      const user = await this.prismaService.user.findUnique({
        where: {
          id: payLoad.id,
        },
        select: {
          id: true,
        },
      });

      if (!user) {
        throw new NotFoundException('Пользователь не найден');
      }

      return this.auth(res, user.id);
    }
  }

  logout(res: Response) {
    this.setCookie(res, 'refreshToken', new Date(0));

    return true;
  }

  async validate(id: string) {
    const user = await this.prismaService.user.findUnique({ where: { id } });

    if (!user) throw new NotFoundException('Пользователь не найден');

    return user;
  }
}
