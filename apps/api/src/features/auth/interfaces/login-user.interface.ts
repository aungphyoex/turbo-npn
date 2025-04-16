import { User } from '@/features/users/entities/user.entity';

interface LoginUserInterface {
  data: User;
  tokens: {
    session_token: string;
    access_token: string;
    refresh_token: string;
  };
}

export default LoginUserInterface;
