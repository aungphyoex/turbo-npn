import { Base } from '@/common/entities';
import { Column, Entity } from 'typeorm';

enum TokenTypes {
  EMAIL_VERIFICATION = 'EMAIL_VERIFICATION',
  EMAIL_CONFIRMATION = 'EMAIL_CONFIRMATION',
  PASSWORD_RESET = 'PASSWORD_RESET',
}

@Entity()
export class Otp extends Base {
  @Column({ type: 'varchar', nullable: false })
  otp: string;

  @Column({ type: 'timestamp', nullable: false })
  expires: Date;

  @Column({ type: 'enum', enum: TokenTypes, nullable: false })
  type: string;
}
