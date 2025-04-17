import { Session } from '@/features/auth/entities/session.entity';
import { MailModule } from '@/features/mail/mail.module';
import { User } from '@/features/users/entities/user.entity';
import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { AuthController } from './auth.controller';
import { AuthService } from './auth.service';

@Module({
  imports: [TypeOrmModule.forFeature([User, Session]), MailModule],
  controllers: [AuthController],
  providers: [AuthService],
})
export class AuthModule {}
