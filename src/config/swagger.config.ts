import { DocumentBuilder } from '@nestjs/swagger';

export function getSwaggerConfig() {
  return new DocumentBuilder()
    .setTitle('Auth API')
    .setDescription('Простое API авторизации с использованием NestJs')
    .setVersion('1.0.0')
    .addBearerAuth()
    .build();
}
