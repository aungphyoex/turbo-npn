import { Session } from '@/features/auth/entities/session.entity';

export class UpdateRefreshTokenDto {
  session: Session;
  refresh_token: string;
}
