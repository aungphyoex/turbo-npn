import { Base } from '@/common/entities';
import { hashString } from '@/common/utils';
import { BeforeInsert, Column, Entity } from 'typeorm';

@Entity()
export class User extends Base {
  @Column({
    nullable: false,
    type: 'varchar',
    unique: true,
  })
  email: string;

  @Column({
    nullable: false,
    type: 'varchar',
  })
  password: string;

  @Column({
    type: 'varchar',
    unique: true,
    nullable: false,
  })
  username: string;

  @Column({
    nullable: false,
    type: 'varchar',
  })
  name: string;

  @Column({
    nullable: true,
    type: 'varchar',
  })
  refreshToken: string | null;

  @Column({
    type: 'boolean',
    default: false,
  })
  isEmailVerified: boolean;

  @Column({
    type: 'varchar',
    nullable: true,
  })
  emailVerificationToken: string | null;

  @Column({
    type: 'timestamp',
    nullable: true,
  })
  emailVerificationTokenExpires: Date | null;

  @Column({
    type: 'varchar',
    nullable: true,
  })
  passwordResetToken: string | null;

  @Column({
    type: 'timestamp',
    nullable: true,
  })
  passwordResetTokenExpires: Date | null;

  @BeforeInsert()
  async hashPassword() {
    this.password = await hashString(this.password);
  }
}
