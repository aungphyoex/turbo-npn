import { Base } from '@/common/entities';
import { hashString } from '@/common/utils';
import { Session } from '@/features/auth/entities/session.entity';
import { Profile } from '@/features/users/entities/profile.entity';
import {
  BeforeInsert,
  Column,
  Entity,
  OneToMany,
  OneToOne,
  Relation,
} from 'typeorm';

@Entity()
export class User extends Base {
  @Column({ type: 'varchar', unique: true, nullable: false })
  email: string;

  @Column({ type: 'varchar', nullable: true })
  password: string;

  @Column({ type: 'varchar', unique: true, nullable: false })
  username: string;

  @Column({ type: 'boolean', nullable: true, default: false })
  isEmailVerified: boolean;

  @Column({ type: 'timestamp', nullable: true })
  emailVerifiedAt: Date;

  @OneToMany(() => Session, (session) => session.user, {
    cascade: true,
  })
  sessions: Relation<Session[]>;

  @OneToOne(() => Profile, (profile) => profile.user, {
    cascade: true,
  })
  profile: Relation<Profile>;

  @BeforeInsert()
  async generateUserInfo() {
    if (!this.username) {
      this.username = this.email.split('@')[0];
    }
    if (this.password) {
      this.password = await hashString(this.password);
    }
  }
}
