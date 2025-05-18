import { Session } from '@/features/auth/entities/session.entity';

export interface MessageResponse {
  message: string;
}

export interface SignInResponse {
  message: string;
  data: {
    id: string;
    name: string;
    username: string;
    email: string;
    isEmailVerified: boolean;
    createdAt: Date;
    updatedAt: Date;
  };
  tokens: {
    access_token: string;
    refresh_token: string;
  };
}

export interface SessionsResponse {
  data: Session[];
}

export interface SessionResponse {
  data: Session;
}

export interface RefreshTokenResponse {
  message: string;
  access_token: string;
  refresh_token: string;
  access_token_refresh_time: string;
  session_token: string;
}
